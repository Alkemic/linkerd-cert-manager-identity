package csr

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmversioned "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/types/known/timestamppb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
)

const (
	identityAnnotation = "linkerd.cert-manager.io/identities"
)

type service struct {
	log zerolog.Logger

	preserveCertificateRequests bool
	issuerRef                   cmmeta.ObjectReference

	client cmclient.CertificateRequestInterface
}

func New(log zerolog.Logger, issuerNamespace string, cmCli *cmversioned.Clientset, preserveCrtReq bool, issuerRef cmmeta.ObjectReference) *service {
	return &service{
		log:                         log,
		preserveCertificateRequests: preserveCrtReq,
		issuerRef:                   issuerRef,
		client:                      cmCli.CertmanagerV1().CertificateRequests(issuerNamespace),
	}
}

func (svc *service) SignCertificate(ctx context.Context, req SigningRequest) (Response, error) {
	log := svc.log.With().Str("svc", "csr").Str("identity", req.Identity).Logger()

	// Create CertificateRequest and wait for it to be successfully signed.
	cr, err := svc.client.Create(ctx, req.ToCertManagerRequest(svc.issuerRef), metav1.CreateOptions{})
	if err != nil {
		log.Error().Err(err).Msg("failed to create CertificateRequest")
		certificatesCounter.WithLabelValues("cannot-create").Inc()
		return Response{}, fmt.Errorf("failed to create CertificateRequest: %w", err)
	}

	// If we are not preserving CertificateRequests, always delete from Kubernetes on return.
	if !svc.preserveCertificateRequests {
		defer func() {
			// Use go routine to prevent blocking on Delete call.
			go func() {
				// Use the Background context so that this call is not cancelled by the
				// gRPC context closing.
				if err := svc.client.Delete(context.Background(), cr.Name, metav1.DeleteOptions{}); err != nil {
					log.Error().Err(err).Msg("failed to delete CertificateRequest")
					return
				}

				log.Info().Msg("deleted CertificateRequest")
			}()
		}()
	}

	signedCR, err := svc.waitForCertificateRequest(ctx, log, cr)
	if err != nil {
		log.Error().Str("namespace", cr.Namespace).Str("name", cr.Name).Err(err).Msg("failed to wait for CertificateRequest")
		certificatesCounter.WithLabelValues("failed-wait").Inc()
		return Response{}, fmt.Errorf("failed to wait for CertificateRequest %s/%s to be signed: %w",
			cr.Namespace, cr.Name, err)
	}

	certificate, err := svc.unpackCertificate(signedCR.Status.Certificate)
	if err != nil {
		log.Error().Err(err).Msg("failed to decode csr chain returned from issuer")
		certificatesCounter.WithLabelValues("cannot-decode").Inc()
		return Response{}, fmt.Errorf("failed to decode csr chain returned from issuer: %w", err)
	}

	certificatesCounter.WithLabelValues("success").Inc()
	return Response{
		Certificate:  certificate.Raw,
		Intermediate: [][]byte{signedCR.Status.CA},
		NotAfter:     timestamppb.New(certificate.NotAfter),
	}, nil
}

func (svc *service) unpackCertificate(certBytes []byte) (*x509.Certificate, error) {
	respBundle, err := pki.ParseSingleCertificateChainPEM(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse and verify chain returned from issuer: %w", err)
	}

	respCerts, err := pki.DecodeX509CertificateChainBytes(respBundle.ChainPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode csr chain returned from issuer: %w", err)
	}

	if len(respCerts) == 0 {
		return nil, fmt.Errorf("response contains no csr")
	}

	return respCerts[0], nil
}

func (svc *service) waitForCertificateRequest(ctx context.Context, log zerolog.Logger, cr *cmapi.CertificateRequest) (*cmapi.CertificateRequest, error) {
	watcher, err := svc.client.Watch(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(metav1.ObjectNameField, cr.Name).String(),
	})
	if err != nil {
		return cr, fmt.Errorf("failed to build watcher for CertificateRequest: %w", err)
	}
	defer watcher.Stop()

	// Get the request in-case it has already reached a terminal state.
	cr, err = svc.client.Get(ctx, cr.Name, metav1.GetOptions{})
	if err != nil {
		return cr, fmt.Errorf("failed to get CertificateRequest: %w", err)
	}

	for {
		if apiutil.CertificateRequestIsDenied(cr) {
			return cr, fmt.Errorf("created CertificateRequest has been denied: %v", cr.Status.Conditions)
		}

		CertificateRequestFailCondition := cmapi.CertificateRequestCondition{
			Type:   cmapi.CertificateRequestConditionReady,
			Status: cmmeta.ConditionFalse,
			Reason: cmapi.CertificateRequestReasonFailed,
		}
		if apiutil.CertificateRequestHasCondition(cr, CertificateRequestFailCondition) {
			return cr, fmt.Errorf("created CertificateRequest has failed: %v", cr.Status.Conditions)
		}

		if len(cr.Status.Certificate) > 0 {
			return cr, nil
		}

		log.Info().Msg("waiting for CertificateRequest to become ready")

		for {
			w, ok := <-watcher.ResultChan()
			if !ok {
				return cr, errors.New("watcher channel closed")
			}
			if w.Type == watch.Deleted {
				return cr, errors.New("created CertificateRequest has been unexpectedly deleted")
			}

			cr, ok = w.Object.(*cmapi.CertificateRequest)
			if !ok {
				log.Error().Interface("object", w.Object).Msg("got unexpected object response from watcher")
				continue
			}
			break
		}
	}
}

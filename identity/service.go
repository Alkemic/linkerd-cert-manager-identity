package identity

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmversioned "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	pb "github.com/linkerd/linkerd2-proxy-api/go/identity"
	"github.com/linkerd/linkerd2/pkg/tls"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
)

const (
	// DefaultIssuanceLifetime is the default lifetime of certificates issued by
	// the identity service.
	DefaultIssuanceLifetime = 24 * time.Hour

	// EnvTrustAnchors is the environment variable holding the trust anchors for
	// the proxy identity.
	EnvTrustAnchors         = "LINKERD2_PROXY_IDENTITY_TRUST_ANCHORS"
	eventTypeSkipped        = "IssuerUpdateSkipped"
	eventTypeUpdated        = "IssuerUpdated"
	eventTypeFailed         = "IssuerValidationFailed"
	eventTypeIssuedLeafCert = "IssuedLeafCertificate"

	identityAnnotation = "istio.cert-manager.io/identities"
)

type (
	Opts struct {
		PreserveCertificateRequests bool
		IssuerRef                   cmmeta.ObjectReference
	}

	// Service implements the gRPC service in terms of a Validator and Issuer.
	Service struct {
		pb.UnimplementedIdentityServer
		validator    Validator
		trustAnchors *x509.CertPool
		issuer       *tls.Issuer
		issuerMutex  *sync.RWMutex
		validity     *tls.Validity

		log zerolog.Logger

		opts Opts

		client cmclient.CertificateRequestInterface
		//expectedName, issuerPathCrt, issuerPathKey string
	}

	// Validator implementors accept a bearer token, validates it, and returns a
	// DNS-form identity.
	Validator interface {
		// Validate takes an opaque authentication token, attempts to validate its
		// authenticity, and produces a DNS-like identifier.
		//
		// An InvalidToken error should be returned if the provided token was not in a
		// correct form.
		//
		// A NotAuthenticated error should be returned if the authenticity of the
		// token cannot be validated.
		Validate(context.Context, []byte) (string, error)
	}

	// InvalidToken is an error type returned by Validators to indicate that the
	// provided authentication token was not valid.
	InvalidToken struct{ Reason string }

	// NotAuthenticated is an error type returned by Validators to indicate that the
	// provided authentication token could not be authenticated.
	NotAuthenticated struct{}
)

// NewService creates a new identity service.
func NewService(log zerolog.Logger, validator Validator, validity *tls.Validity, issuerNamespace string, cmCli *cmversioned.Clientset, preserveCrtReq bool, issuerRef cmmeta.ObjectReference) *Service {
	return &Service{
		UnimplementedIdentityServer: pb.UnimplementedIdentityServer{},
		validator:                   validator,
		issuerMutex:                 &sync.RWMutex{},
		validity:                    validity,
		log:                         log,
		opts: Opts{
			PreserveCertificateRequests: preserveCrtReq,
			IssuerRef:                   issuerRef,
		},
		client: cmCli.CertmanagerV1().CertificateRequests(issuerNamespace),
	}
}

// Register registers an identity service implementation in the provided gRPC server.
func Register(g *grpc.Server, s *Service) {
	pb.RegisterIdentityServer(g, s)
}

func (svc *Service) Certify(ctx context.Context, req *pb.CertifyRequest) (*pb.CertifyResponse, error) {
	reqIdentity, tok, csr, err := checkRequest(req)
	log := svc.log.With().Str("identity", reqIdentity).Logger()
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err = checkCSR(csr, reqIdentity); err != nil {
		svc.log.Debug().Err(err).Msg("requester sent invalid CSR")
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	// Authenticate the provided token against the Kubernetes API.
	tokIdentity, err := svc.validator.Validate(ctx, tok)
	if err != nil {
		var nae NotAuthenticated
		if errors.As(err, &nae) {
			log.Info().Err(nae).Msg("authentication failed")
			return nil, status.Error(codes.FailedPrecondition, nae.Error())
		}
		var ite InvalidToken
		if errors.As(err, &ite) {
			log.Debug().Err(ite).Msg("invalid token provided")
			return nil, status.Error(codes.InvalidArgument, ite.Error())
		}

		log.Error().Err(err).Msg("error validating token")
		return nil, status.Error(codes.Internal, "error validating token")
	}

	// Ensure the requested identity matches the token's identity.
	if reqIdentity != tokIdentity {
		msg := fmt.Sprintf("requested identity did not match provided token: requested=%s; found=%s",
			reqIdentity, tokIdentity)
		log.Debug().Msg(msg)
		return nil, status.Error(codes.FailedPrecondition, msg)
	}

	// Create CertificateRequest and wait for it to be successfully signed.
	cr, err := svc.client.Create(ctx, svc.toCertManagerRequest(req), metav1.CreateOptions{})
	if err != nil {
		log.Error().Err(err).Msg("failed to create CertificateRequest")
		return nil, fmt.Errorf("failed to create CertificateRequest: %w", err)
	}

	// If we are not preserving CertificateRequests, always delete from Kubernetes on return.
	if !svc.opts.PreserveCertificateRequests {
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
		return nil, fmt.Errorf("failed to wait for CertificateRequest %s/%s to be signed: %w",
			cr.Namespace, cr.Name, err)
	}

	log.Info().Msg("signed CertificateRequest")

	// todo: validate certificate against locally supplied CA (is this really needed?)

	// get certificate as a *x509.Certificate
	certificate, err := svc.unpackCertificate(signedCR.Status.Certificate)
	if err != nil {
		log.Error().Err(err).Msg("failed to decode certificate chain returned from issuer")
		return nil, fmt.Errorf("failed to decode certificate chain returned from issuer: %w", err)
	}

	return &pb.CertifyResponse{
		LeafCertificate: certificate.Raw,
		// todo: create env for testing situation with intermediate(s)
		IntermediateCertificates: [][]byte{signedCR.Status.CA},
		ValidUntil:               timestamppb.New(certificate.NotAfter),
	}, nil
}

func (svc *Service) unpackCertificate(certBytes []byte) (*x509.Certificate, error) {
	respBundle, err := pki.ParseSingleCertificateChainPEM(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse and verify chain returned from issuer: %w", err)
	}

	respCerts, err := pki.DecodeX509CertificateChainBytes(respBundle.ChainPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate chain returned from issuer: %w", err)
	}

	if len(respCerts) == 0 {
		return nil, fmt.Errorf("response contains no certificate")
	}

	return respCerts[0], nil
}

func (svc *Service) toCertManagerRequest(req *pb.CertifyRequest) *cmapi.CertificateRequest {
	return &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "linkerd-csr-",
			Annotations: map[string]string{
				identityAnnotation: req.GetIdentity(),
			},
		},
		Spec: cmapi.CertificateRequestSpec{
			Duration: &metav1.Duration{
				Duration: 36 * time.Hour,
			},
			IsCA: false,
			Request: pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE REQUEST",
				Bytes: req.GetCertificateSigningRequest(),
			}),
			Usages: []cmapi.KeyUsage{cmapi.UsageServerAuth},

			IssuerRef: svc.opts.IssuerRef,
		},
	}
}

func (svc *Service) waitForCertificateRequest(ctx context.Context, log zerolog.Logger, cr *cmapi.CertificateRequest) (*cmapi.CertificateRequest, error) {
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

		if apiutil.CertificateRequestHasCondition(cr, cmapi.CertificateRequestCondition{
			Type:   cmapi.CertificateRequestConditionReady,
			Status: cmmeta.ConditionFalse,
			Reason: cmapi.CertificateRequestReasonFailed,
		}) {
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

func checkRequest(req *pb.CertifyRequest) (string, []byte, *x509.CertificateRequest, error) {
	reqIdentity := req.GetIdentity()
	if reqIdentity == "" {
		return "", nil, nil, errors.New("missing identity")
	}

	tok := req.GetToken()
	if len(tok) == 0 {
		return "", nil, nil, errors.New("missing token")
	}

	der := req.GetCertificateSigningRequest()
	if len(der) == 0 {
		return "", nil, nil,
			errors.New("missing certificate signing request")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return "", nil, nil, err
	}

	return reqIdentity, tok, csr, nil
}

func checkCSR(csr *x509.CertificateRequest, identity string) error {
	if len(csr.DNSNames) != 1 {
		return errors.New("CSR must have exactly one DNSName")
	}
	if csr.DNSNames[0] != identity {
		return fmt.Errorf("CSR name does not match requested identity: csr=%s; req=%s", csr.DNSNames[0], identity)
	}

	switch csr.Subject.CommonName {
	case "", identity:
	default:
		return fmt.Errorf("invalid CommonName: %s", csr.Subject.CommonName)
	}

	if len(csr.EmailAddresses) > 0 {
		return errors.New("cannot validate email addresses")
	}
	if len(csr.IPAddresses) > 0 {
		return errors.New("cannot validate IP addresses")
	}
	if len(csr.URIs) > 0 {
		return errors.New("cannot validate URIs")
	}

	return nil
}

func (NotAuthenticated) Error() string {
	return "authentication token could not be authenticated"
}

func (e InvalidToken) Error() string {
	return e.Reason
}

package grpc

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	pb "github.com/linkerd/linkerd2-proxy-api/go/identity"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/Alkemic/linekrd-cert-manager-identity/csr"
)

const (
	eventTypeIssuedLeafCert       = "IssuedLeafCertificate"
	eventTypeIssuedLeafCertFailed = "IssuedLeafCertificateFailed"
)

type (
	csrService interface {
		SignCertificate(ctx context.Context, req csr.SigningRequest) (csr.Response, error)
	}

	// Service implements the gRPC service in terms of a Validator and Issuer.
	Service struct {
		pb.UnimplementedIdentityServer
		validator   Validator
		log         zerolog.Logger
		recordEvent func(parent runtime.Object, eventType, reason, message string)
		csrService  csrService
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

// New creates a new identity service.
func New(log zerolog.Logger, validator Validator, recordEvent func(parent runtime.Object, eventType, reason, message string), csrService csrService) *Service {
	return &Service{
		UnimplementedIdentityServer: pb.UnimplementedIdentityServer{},

		log:         log,
		validator:   validator,
		recordEvent: recordEvent,
		csrService:  csrService,
	}
}

// Register registers an identity service implementation in the provided gRPC server.
func Register(g *grpc.Server, s *Service) {
	pb.RegisterIdentityServer(g, s)
}

func (svc *Service) Certify(ctx context.Context, req *pb.CertifyRequest) (*pb.CertifyResponse, error) {
	reqIdentity, tok, cr, err := checkRequest(req)
	log := svc.log.With().Str("identity", reqIdentity).Logger()
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err = checkCertificateRequest(cr, reqIdentity); err != nil {
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

	resp, err := svc.csrService.SignCertificate(ctx, csr.SigningRequest{
		CSR:      req.GetCertificateSigningRequest(),
		Identity: req.GetIdentity(),
	})

	identitySegments := strings.Split(tokIdentity, ".")
	sa := v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: identitySegments[0], Namespace: identitySegments[1]},
	}

	if err != nil {
		err := fmt.Errorf("signing csr request: %w", err)
		svc.recordEvent(&sa, v1.EventTypeNormal, eventTypeIssuedLeafCertFailed, err.Error())
		log.Error().Err(err).Msg("failed to sign csr request")
		return nil, err
	}

	msg := fmt.Sprintf("issued certificate for %s until %s: %s", tokIdentity, resp.NotAfter, resp.CertificateHash())
	svc.recordEvent(&sa, v1.EventTypeNormal, eventTypeIssuedLeafCert, msg)

	return resp.ToPBCertifyResponse(), nil
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
			errors.New("missing csr signing request")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return "", nil, nil, err
	}

	return reqIdentity, tok, csr, nil
}

func checkCertificateRequest(csr *x509.CertificateRequest, identity string) error {
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

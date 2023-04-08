package csr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	pb "github.com/linkerd/linkerd2-proxy-api/go/identity"
	"google.golang.org/protobuf/types/known/timestamppb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type SigningRequest struct {
	CSR      []byte
	Identity string
}

func (r SigningRequest) ToCertManagerRequest(issuerRef cmmeta.ObjectReference) *cmapi.CertificateRequest {
	return &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "linkerd-csr-",
			Annotations: map[string]string{
				identityAnnotation: r.Identity,
			},
		},
		Spec: cmapi.CertificateRequestSpec{
			Duration: &metav1.Duration{
				Duration: 36 * time.Hour,
			},
			IsCA: false,
			Request: pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE REQUEST",
				Bytes: r.CSR,
			}),
			Usages:    []cmapi.KeyUsage{cmapi.UsageServerAuth},
			IssuerRef: issuerRef,
		},
	}
}

type Response struct {
	Certificate  []byte
	Intermediate [][]byte
	NotAfter     *timestamppb.Timestamp
}

func (r Response) ToPBCertifyResponse() *pb.CertifyResponse {
	return &pb.CertifyResponse{
		LeafCertificate:          r.Certificate,
		IntermediateCertificates: r.Intermediate,
		ValidUntil:               r.NotAfter,
	}
}

func (r Response) CertificateHash() string {
	hasher := sha256.New()
	hasher.Write(r.Certificate)
	hash := hex.EncodeToString(hasher.Sum(nil))
	return hash
}

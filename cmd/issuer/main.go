package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/linkerd/linkerd2/pkg/tls"
	log "github.com/sirupsen/logrus"
)

func main() {
	//keyBytes, _ := ecdsa.GenerateKey(rand.Reader, 1024)

	emailAddress := "test@example.com"
	subj := pkix.Name{
		CommonName:         "example.com",
		Country:            []string{"AU"},
		Province:           []string{"Some-State"},
		Locality:           []string{"MyCity"},
		Organization:       []string{"Company Ltd"},
		OrganizationalUnit: []string{"IT"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			{
				Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1},
				Value: asn1.RawValue{
					Tag:   asn1.TagIA5String,
					Bytes: []byte(emailAddress),
				},
			},
		},
	}

	template := &x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	//csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, template, keyBytes)

	creds, err := tls.ReadPEMCreds("cmd/issuer/issuer.key", "cmd/issuer/issuer.crt")
	if err != nil {
		log.Fatal("read pem certs", err)
	}

	issuer := tls.NewCA(*creds, tls.Validity{})
	template.PublicKey = creds.Crt.Certificate.PublicKey
	crt, err := issuer.IssueEndEntityCrt(template)
	if err != nil {
		log.Fatal("issue end crt", err)
	}
	log.Print(string(crt.Certificate.Raw))
}

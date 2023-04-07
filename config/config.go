package config

import (
	"flag"
	"os"

	log "github.com/sirupsen/logrus"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

type Config struct {
	Addr                       string
	AdminAddr                  string
	KubeConfigPath             string
	ControllerNS               string
	IdentityScheme             string // not used
	TrustDomain                string
	IdentityIssuanceLifeTime   string
	IdentityClockSkewAllowance string
	EnablePprof                bool
	TraceCollector             string

	// for cert-manager part
	PreserveCrtReq bool
	IssuerName     string
	IssuerKind     string

	LogLevel  string
	LogFormat string

	PrintVersion bool
}

func Parse() *Config {
	cmd := flag.NewFlagSet("identity", flag.ExitOnError)

	cfg := &Config{}

	cmd.StringVar(&cfg.Addr, "addr", ":8080", "address to serve on")
	cmd.StringVar(&cfg.AdminAddr, "admin-addr", ":9990", "address of HTTP admin server")
	cmd.StringVar(&cfg.KubeConfigPath, "kubeconfig", "", "path to kube config")
	cmd.StringVar(&cfg.ControllerNS, "controller-namespace", "", "namespace in which Linkerd is installed")
	cmd.StringVar(&cfg.IdentityScheme, "identity-scheme", "", "scheme used for the identity issuer secret format")
	cmd.StringVar(&cfg.TrustDomain, "identity-trust-domain", "", "configures the name suffix used for identities")
	cmd.StringVar(&cfg.IdentityIssuanceLifeTime, "identity-issuance-lifetime", "", "the amount of time for which the Identity issuer should certify identity")
	cmd.StringVar(&cfg.IdentityClockSkewAllowance, "identity-clock-skew-allowance", "", "the amount of time to allow for clock skew within a Linkerd cluster")
	cmd.BoolVar(&cfg.EnablePprof, "enable-pprof", false, "Enable pprof endpoints on the admin server")

	cmd.BoolVar(&cfg.PreserveCrtReq, "preserve-certificate-requests", false, "Do not remove CertificateRequests after certificate is created")
	cmd.StringVar(&cfg.IssuerName, "issuer-name", "linkerd", "name of issuer")
	cmd.StringVar(&cfg.IssuerKind, "issuer-kind", "Issuer", "issuer kind, can be Issuer or ClusterIssuer")

	cmd.StringVar(&cfg.TraceCollector, "trace-collector", "", "Enables OC Tracing with the specified endpoint as collector")

	//flags.ConfigureAndParse(cmd, os.Args[2:])

	cmd.StringVar(&cfg.LogLevel, "log-level", log.InfoLevel.String(), "log level, must be one of: panic, fatal, error, warn, info, debug")
	cmd.StringVar(&cfg.LogFormat, "log-format", "plain", "log format, must be one of: plain, json")
	cmd.BoolVar(&cfg.PrintVersion, "version", false, "print version and exit")

	cmd.Parse(os.Args[2:])

	return cfg
}

func (c Config) IssuerRef() cmmeta.ObjectReference {
	return cmmeta.ObjectReference{
		Name:  c.IssuerName,
		Kind:  c.IssuerKind,
		Group: "cert-manager.io",
	}
}

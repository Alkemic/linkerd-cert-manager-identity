package config

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/rs/zerolog"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

type Config struct {
	Addr                       string
	AdminAddr                  string
	KubeConfigPath             string
	ControllerNS               string
	identityScheme             string // not used
	TrustDomain                string
	IdentityIssuanceLifeTime   time.Duration
	identityClockSkewAllowance string // not used
	EnablePprof                bool
	TraceCollector             string

	// for cert-manager part
	PreserveCrtReq bool
	IssuerName     string
	IssuerKind     string

	LogLevel  string
	logFormat string // not used

	PrintVersion bool
}

func Parse() *Config {
	cmd := flag.NewFlagSet("identity", flag.ExitOnError)

	cfg := &Config{}

	cmd.StringVar(&cfg.Addr, "addr", ":8080", "address to serve on")
	cmd.StringVar(&cfg.AdminAddr, "admin-addr", ":9990", "address of HTTP admin server")
	cmd.StringVar(&cfg.KubeConfigPath, "kubeconfig", "", "path to kube config")
	cmd.StringVar(&cfg.ControllerNS, "controller-namespace", "", "namespace in which Linkerd is installed")
	cmd.StringVar(&cfg.identityScheme, "identity-scheme", "", "scheme used for the identity issuer secret format")
	cmd.StringVar(&cfg.TrustDomain, "identity-trust-domain", "", "configures the name suffix used for identities")
	cmd.DurationVar(&cfg.IdentityIssuanceLifeTime, "identity-issuance-lifetime", 36*time.Hour, "the amount of time for which the Identity issuer should certify identity")
	cmd.StringVar(&cfg.identityClockSkewAllowance, "identity-clock-skew-allowance", "", "the amount of time to allow for clock skew within a Linkerd cluster")
	cmd.BoolVar(&cfg.EnablePprof, "enable-pprof", false, "Enable pprof endpoints on the admin server")
	cmd.StringVar(&cfg.TraceCollector, "trace-collector", "", "Enables OC Tracing with the specified endpoint as collector")

	// todo: support this
	cmd.BoolVar(&cfg.PrintVersion, "version", false, "print version and exit")

	// new flags, to configure CM-CSR behavior
	cmd.BoolVar(&cfg.PreserveCrtReq, "preserve-csr-requests", false, "Do not remove CertificateRequests after csr is created")
	cmd.StringVar(&cfg.IssuerName, "issuer-name", "linkerd", "name of issuer")
	cmd.StringVar(&cfg.IssuerKind, "issuer-kind", "Issuer", "issuer kind, can be Issuer or ClusterIssuer")

	cmd.StringVar(&cfg.LogLevel, "log-level", zerolog.InfoLevel.String(), "log level, must be one of: panic, fatal, error, warn, info, debug")
	cmd.StringVar(&cfg.logFormat, "log-format", "plain", "log format, must be one of: plain, json")

	if err := cmd.Parse(os.Args[2:]); err != nil {
		log.Fatalln("parsing command line arguments:", err)
	}

	return cfg
}

func (c Config) ZLLogLevel() zerolog.Level {
	lvl, err := zerolog.ParseLevel(c.LogLevel)
	if err != nil {
		return zerolog.InfoLevel
	}
	return lvl
}

func (c Config) IssuerRef() cmmeta.ObjectReference {
	return cmmeta.ObjectReference{
		Name:  c.IssuerName,
		Kind:  c.IssuerKind,
		Group: "cert-manager.io",
	}
}

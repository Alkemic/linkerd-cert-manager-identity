package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/Alkemic/linekrd-identity-cert-manager/csr"

	"github.com/Alkemic/linekrd-identity-cert-manager/config"

	cmversioned "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	idctl "github.com/linkerd/linkerd2/controller/identity"
	"github.com/linkerd/linkerd2/pkg/admin"
	"github.com/linkerd/linkerd2/pkg/k8s"
	"github.com/linkerd/linkerd2/pkg/prometheus"
	"github.com/linkerd/linkerd2/pkg/trace"

	"github.com/Alkemic/linekrd-identity-cert-manager/identity"
)

const componentName = "linkerd-identity"

func main() {
	//cmd := flag.NewFlagSet("identity", flag.ExitOnError)
	//
	//addr := cmd.String("addr", ":8080", "address to serve on")
	//adminAddr := cmd.String("admin-addr", ":9990", "address of HTTP admin server")
	//kubeConfigPath := cmd.String("kubeconfig", "", "path to kube config")
	//controllerNS := cmd.String("controller-namespace", "", "namespace in which Linkerd is installed")
	//cmd.String("identity-scheme", "", "scheme used for the identity issuer secret format")
	//trustDomain := cmd.String("identity-trust-domain", "", "configures the name suffix used for identities")
	//identityIssuanceLifeTime := cmd.String("identity-issuance-lifetime", "", "the amount of time for which the Identity issuer should certify identity")
	//identityClockSkewAllowance := cmd.String("identity-clock-skew-allowance", "", "the amount of time to allow for clock skew within a Linkerd cluster")
	//enablePprof := cmd.Bool("enable-pprof", false, "Enable pprof endpoints on the admin server")
	//
	//preserveCrtReq := cmd.Bool("preserve-csr-requests", false, "Do not remove CertificateRequests after csr is created")
	//issuerName := cmd.String("issuer-name", "linkerd", "name of issuer")
	//issuerKind := cmd.String("issuer-kind", "Issuer", "issuer kind, can be Issuer or ClusterIssuer")
	//
	////issuerName := cmd.String("identity-issuer-name", "linkerd-identity", "name of cert-manager's Issuer")
	//
	//traceCollector := flags.AddTraceFlags(cmd)
	//
	//flags.ConfigureAndParse(cmd, os.Args[2:])

	cfg := config.Parse()

	ready := false
	adminServer := admin.NewServer(cfg.AdminAddr, cfg.EnablePprof, &ready)
	log.Info().Interface("cfg", cfg).Msg("mark")
	go func() {
		log.Printf("starting admin server on %s", cfg.AdminAddr)
		if err := adminServer.ListenAndServe(); err != nil {
			log.Err(err).Msg("failed to start identity admin server")
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dom, err := idctl.NewTrustDomain(cfg.ControllerNS, cfg.TrustDomain)
	if err != nil {
		//nolint:gocritic
		log.Fatal().Err(err).Msg("Invalid trust domain")
	}

	// Create k8s API
	k8sAPI, err := k8s.NewAPI(cfg.KubeConfigPath, "", "", []string{}, 0)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load kubeconfig")
	}
	k8sTokenValidator, err := idctl.NewK8sTokenValidator(ctx, k8sAPI, dom)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize identity service")
	}

	cmCli, err := cmversioned.NewForConfig(k8sAPI.Config)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to build cert-manager client")
	}

	csrSvc := csr.New(log, cfg.ControllerNS, cmCli, cfg.PreserveCrtReq, cfg.IssuerRef())
	// Create, initialize and run service
	svc := identity.New(log, k8sTokenValidator, csrSvc)

	// Bind and serve
	lis, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		//nolint:gocritic
		log.Fatal().Err(err).Str("addr", cfg.Addr).Msg("Failed to listen")
	}

	if cfg.TraceCollector != "" {
		if err := trace.InitializeTracing(componentName, cfg.TraceCollector); err != nil {
			log.Warn().Err(err).Msg("failed to initialize tracing")
		}
	}
	srv := prometheus.NewGrpcServer()
	identity.Register(srv, svc)
	go func() {
		log.Info().Err(err).Str("addr", cfg.Addr).Msg("starting gRPC server")
		if err := srv.Serve(lis); err != nil {
			log.Fatal().Err(err).Msg("failed to start identity gRPC server")
		}
	}()

	ready = true

	<-stop
	log.Info().Str("addr", cfg.Addr).Msg("shutting down gRPC server")
	srv.GracefulStop()
	adminServer.Shutdown(ctx)
}

func initLogger(cfg config.Config) zerolog.Logger {
	return zerolog.New(os.Stderr).
		With().
		Timestamp().
		Logger().
		Level(cfg.ZLLogLevel()).
		Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "2006-01-02 15:04:05"})
}

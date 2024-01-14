package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"

	cmversioned "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	idctl "github.com/linkerd/linkerd2/controller/identity"
	"github.com/linkerd/linkerd2/pkg/admin"
	"github.com/linkerd/linkerd2/pkg/k8s"
	"github.com/linkerd/linkerd2/pkg/prometheus"
	"github.com/linkerd/linkerd2/pkg/trace"
	"github.com/rs/zerolog"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"

	"github.com/Alkemic/linkerd-cert-manager-identity/config"
	"github.com/Alkemic/linkerd-cert-manager-identity/csr"
	"github.com/Alkemic/linkerd-cert-manager-identity/grpc"
)

const componentName = "linkerd-identity"

func main() {
	ready := false
	cfg := config.Parse()
	log := initLogger(cfg)
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
		log.Fatal().Err(err).Msg("Invalid trust domain")
	}

	// Create k8s API
	config, err := k8s.GetConfig(cfg.KubeConfigPath, "")
	if err != nil {
		log.Fatal().Err(err).Msg("configuring Kubernetes API client")
	}
	k8sAPI, err := k8s.NewAPIForConfig(config, "", []string{}, 0, float32(cfg.KubeApiClient.QPS), cfg.KubeApiClient.Burst)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load kubeconfig")
	}
	log.Info().Msgf("Using k8s client with QPS=%.2f Burst=%d", config.QPS, config.Burst)

	k8sTokenValidator, err := idctl.NewK8sTokenValidator(ctx, k8sAPI, dom)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize identity service")
	}

	cmCli, err := cmversioned.NewForConfig(k8sAPI.Config)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to build cert-manager client")
	}

	// Create K8s event recorder
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{
		Interface: k8sAPI.CoreV1().Events(""),
	})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: componentName})
	recordEventFunc := func(parent runtime.Object, eventType, reason, message string) {
		if parent == nil {
			parent = &corev1.ObjectReference{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Namespace:  cfg.ControllerNS,
				Name:       componentName,
			}
		}
		recorder.Event(parent, eventType, reason, message)
	}

	csrSvc := csr.New(log, cfg.ControllerNS, cmCli, cfg.PreserveCrtReq, cfg.IssuerRef(), cfg.IdentityIssuanceLifeTime)
	svc := grpc.New(log, k8sTokenValidator, recordEventFunc, csrSvc)

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
	grpc.Register(srv, svc)
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
	if err := adminServer.Shutdown(ctx); err != nil {
		log.Err(err).Msg("server shutdown")
	}
}

func initLogger(cfg *config.Config) zerolog.Logger {
	return zerolog.New(os.Stderr).
		With().
		Timestamp().
		Logger().
		Level(cfg.ZLLogLevel()).
		Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "2006-01-02 15:04:05"})
}

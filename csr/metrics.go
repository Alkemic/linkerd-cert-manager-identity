package csr

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	certificatesCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sign_certificates_count",
			Help: "No. of certificates issued with reason and identity name",
		},
		[]string{"reason", "identity"},
	)
)

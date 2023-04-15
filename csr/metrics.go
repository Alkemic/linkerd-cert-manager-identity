package csr

import "github.com/prometheus/client_golang/prometheus"

var (
	certificatesCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sign_certificates_count",
			Help: "No. of certificates issued",
		},
		[]string{"reason"},
	)
)

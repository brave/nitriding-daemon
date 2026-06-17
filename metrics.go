package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

const (
	reqPath    = "path"
	reqMethod  = "method"
	respStatus = "status"
	respErr    = "error"

	notAvailable = "n/a"
)

var (
	goodHb = prometheus.Labels{
		respErr: notAvailable,
	}
	badHb = func(err error) prometheus.Labels {
		return prometheus.Labels{
			respErr: err.Error(),
		}
	}
)

// metrics contains our Prometheus metrics.
type metrics struct {
	reqs         *prometheus.CounterVec
	proxiedReqs  *prometheus.CounterVec
	heartbeats   *prometheus.CounterVec
	reqDurations *prometheus.HistogramVec
}

// newMetrics initializes our Prometheus metrics.
func newMetrics(reg prometheus.Registerer, namespace string) *metrics {
	elog.Printf("Initializing Prometheus metrics. namespace = %q", namespace)
	m := &metrics{
		reqs: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "requests",
				Help:      "HTTP requests to nitriding",
			},
			[]string{reqPath, reqMethod, respStatus, respErr},
		),
		reqDurations: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "request_duration_seconds",
				Help:      "Duration of proxied HTTP requests",
			},
			[]string{reqPath, reqMethod, respStatus, respErr},
		),
		proxiedReqs: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "proxied_requests",
				Help:      "HTTP requests proxied to the enclave application",
			},
			[]string{reqPath, reqMethod, respStatus, respErr},
		),
		heartbeats: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "heartbeats",
				Help:      "Heartbeats sent to the leader enclave",
			},
			[]string{respErr},
		),
	}
	reg.MustRegister(m.proxiedReqs)
	reg.MustRegister(m.reqs)
	reg.MustRegister(m.heartbeats)
	reg.MustRegister(m.reqDurations)

	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{
		Namespace: namespace,
	}))
	reg.MustRegister(collectors.NewGoCollector())

	return m
}

// checkRevProxyResp captures Prometheus metrics for HTTP responses from our
// enclave application backend.
func (m *metrics) checkRevProxyResp(resp *http.Response) error {
	m.proxiedReqs.With(prometheus.Labels{
		reqPath:    resp.Request.URL.Path,
		reqMethod:  resp.Request.Method,
		respStatus: fmt.Sprint(resp.StatusCode),
		respErr:    notAvailable,
	}).Inc()

	return nil
}

// checkRevProxyErr captures Prometheus metrics for errors that occurred when
// we tried to talk to the enclave application backend.
func (m *metrics) checkRevProxyErr(w http.ResponseWriter, r *http.Request, err error) {
	m.proxiedReqs.With(prometheus.Labels{
		reqPath:    r.URL.Path,
		reqMethod:  r.Method,
		respStatus: notAvailable,
		respErr:    err.Error(),
	}).Inc()
	// Tell the client that we couldn't reach the backend.  This is going to
	// result in another increase of proxiedReqs because the middleware below
	// is going to handle this request.
	w.WriteHeader(http.StatusBadGateway)
}

// middleware implements a chi middleware that records each request as part of
// our Prometheus metrics.
func (m *metrics) middleware(h http.Handler) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		h.ServeHTTP(ww, r)
		if ww.Status() != http.StatusNotFound {
			labels := prometheus.Labels{
				reqPath:    r.URL.Path,
				reqMethod:  r.Method,
				respStatus: fmt.Sprint(ww.Status()),
				respErr:    notAvailable,
			}
			m.reqs.With(labels).Inc()
			m.reqDurations.With(labels).Observe(time.Since(startTime).Seconds())
		}
	}
	return http.HandlerFunc(f)
}

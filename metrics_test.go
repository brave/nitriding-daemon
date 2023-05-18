package nitriding

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetrics(t *testing.T) {
	err1, err2 := errors.New("backend timeout"), errors.New("backend exploded")
	expectedStatus1, expectedStatus2 := 200, 404
	expectedPath := "/foo"
	expectedMethod := http.MethodGet
	reg := prometheus.NewRegistry()
	m := newMetrics(reg)
	req, err := http.NewRequest(expectedMethod, expectedPath, nil)
	if err != nil {
		t.Fatalf("Failed to create new HTTP request: %v", err)
	}

	r := httptest.NewRecorder()
	m.checkRevProxyErr(r, req, err1)
	m.checkRevProxyErr(r, req, err1)
	m.checkRevProxyErr(r, req, err2)

	labels := m.proxiedReqs.WithLabelValues
	assertEqual(t, testutil.ToFloat64(labels(
		expectedPath,
		expectedMethod,
		notAvailable,
		err1.Error()),
	), float64(2))
	assertEqual(t, testutil.ToFloat64(labels(
		expectedPath,
		expectedMethod,
		notAvailable,
		err2.Error()),
	), float64(1))

	_ = m.checkRevProxyResp(&http.Response{
		StatusCode: expectedStatus1,
		Request:    req,
	})
	_ = m.checkRevProxyResp(&http.Response{
		StatusCode: expectedStatus2,
		Request:    req,
	})

	assertEqual(t, testutil.ToFloat64(labels(
		expectedPath,
		expectedMethod,
		fmt.Sprint(expectedStatus1),
		notAvailable),
	), float64(1))
	assertEqual(t, testutil.ToFloat64(labels(
		expectedPath,
		expectedMethod,
		fmt.Sprint(expectedStatus2),
		notAvailable),
	), float64(1))
}

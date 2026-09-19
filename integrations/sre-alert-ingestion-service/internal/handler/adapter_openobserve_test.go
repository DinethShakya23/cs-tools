// Copyright (c) 2026 WSO2 LLC. (https://www.wso2.com).
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func openObserveAlertJSON(urgency, impact string) []byte {
	body, _ := json.Marshal(openObservePayload{
		ShortDescription: "[Critical] OpenChoreo: Test-Alert",
		Description:      "Stream: default | Alert: Test-Alert | Matched: test",
		Urgency:          urgency,
		Impact:           impact,
		Service:          "client-alert-integration",
		Environment:      "production",
		Category:         "service_interruption",
		CorrelationID:    "corr-id-1",
	})
	return body
}

func TestMapOpenObservePayload_SeverityFromUrgency(t *testing.T) {
	cases := []struct {
		urgency string
		want    string
	}{
		{"1", "critical"},
		{"2", "major"},
		{"3", "minor"},
	}
	for _, tc := range cases {
		t.Run(tc.urgency, func(t *testing.T) {
			req, err := mapOpenObservePayload(openObserveAlertJSON(tc.urgency, ""))
			if err != nil {
				t.Fatalf("mapOpenObservePayload: %v", err)
			}
			if req.Severity != tc.want {
				t.Errorf("Severity = %q, want %q", req.Severity, tc.want)
			}
		})
	}
}

func TestMapOpenObservePayload_FallsBackToImpactWhenUrgencyMissing(t *testing.T) {
	req, err := mapOpenObservePayload(openObserveAlertJSON("", "2"))
	if err != nil {
		t.Fatalf("mapOpenObservePayload: %v", err)
	}
	if req.Severity != "major" {
		t.Errorf("Severity = %q, want major (from impact fallback)", req.Severity)
	}
}

func TestMapOpenObservePayload_FallsBackToImpactWhenUrgencyUnrecognized(t *testing.T) {
	req, err := mapOpenObservePayload(openObserveAlertJSON("unrecognized", "1"))
	if err != nil {
		t.Fatalf("mapOpenObservePayload: %v", err)
	}
	if req.Severity != "critical" {
		t.Errorf("Severity = %q, want critical (from impact fallback)", req.Severity)
	}
}

func TestMapOpenObservePayload_BothMissingDefaultsToOK(t *testing.T) {
	req, err := mapOpenObservePayload(openObserveAlertJSON("", ""))
	if err != nil {
		t.Fatalf("mapOpenObservePayload: %v", err)
	}
	if req.Severity != "ok" {
		t.Errorf("Severity = %q, want ok (safe default) when both urgency and impact are missing", req.Severity)
	}
}

func TestMapOpenObservePayload_UniqueIdentifierIsCorrelationID(t *testing.T) {
	req, err := mapOpenObservePayload(openObserveAlertJSON("1", ""))
	if err != nil {
		t.Fatalf("mapOpenObservePayload: %v", err)
	}
	if req.UniqueIdentifier != sanitizeUniqueIdentifier("corr-id-1") {
		t.Errorf("UniqueIdentifier = %q, want the sanitized correlation_id", req.UniqueIdentifier)
	}
}

func TestCreateAlertFromOpenObserve_Success(t *testing.T) {
	store := &mockStore{}
	h := NewAlertHandler(store, "caller-1", "")

	body := openObserveAlertJSON("1", "")
	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/openobserve", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateAlertFromOpenObserve(w, r)

	assertStatus(t, w, http.StatusAccepted)
	if len(store.enqueuedPayloads) != 1 {
		t.Fatalf("Enqueue called %d times, want 1", len(store.enqueuedPayloads))
	}
}

func TestCreateAlertFromOpenObserve_MalformedBodyReturns400(t *testing.T) {
	store := &mockStore{}
	h := NewAlertHandler(store, "caller-1", "")

	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/openobserve", bytes.NewReader([]byte(`not json`)))
	w := httptest.NewRecorder()
	h.CreateAlertFromOpenObserve(w, r)

	assertStatus(t, w, http.StatusBadRequest)
	if len(store.enqueuedPayloads) != 0 {
		t.Error("Enqueue should not be called for a malformed body")
	}
}

func TestCreateAlertFromOpenObserve_StoreFailureReturns500(t *testing.T) {
	store := &mockStore{enqueueFn: func(ctx context.Context, id string, buildPayload func(string) ([]byte, error)) (string, error) {
		return "", errors.New("connection refused")
	}}
	h := NewAlertHandler(store, "caller-1", "")

	body := openObserveAlertJSON("1", "")
	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/openobserve", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateAlertFromOpenObserve(w, r)

	assertStatus(t, w, http.StatusInternalServerError)
	assertErrorMessage(t, w, ErrMsgInternal)
}

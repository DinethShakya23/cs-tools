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
	"strings"
	"testing"
)

func elasticsearchAlertJSON(state, severity string) []byte {
	body, _ := json.Marshal(elasticsearchPayload{
		RuleName:    "Global-Error-Threshold",
		State:       state,
		AlertID:     "alert-id-1",
		Severity:    severity,
		Service:     "client-alert-integration",
		Environment: "production",
		Category:    "service_interruption",
	})
	return body
}

func TestMapElasticsearchPayload_SeverityTableWhenActive(t *testing.T) {
	cases := []struct {
		sev  string
		want string
	}{
		{"1", "critical"},
		{"2", "major"},
		{"3", "minor"},
		{"4", "warning"},
		{"5", "ok"},
		{"unrecognized", "ok"},
	}
	for _, tc := range cases {
		t.Run(tc.sev, func(t *testing.T) {
			body := elasticsearchAlertJSON("ACTIVE", tc.sev)
			req, err := mapElasticsearchPayload(body)
			if err != nil {
				t.Fatalf("mapElasticsearchPayload: %v", err)
			}
			if req.Severity != tc.want {
				t.Errorf("Severity = %q, want %q", req.Severity, tc.want)
			}
		})
	}
}

func TestMapElasticsearchPayload_CompletedForcesOK(t *testing.T) {
	body := elasticsearchAlertJSON("COMPLETED", "1")
	req, err := mapElasticsearchPayload(body)
	if err != nil {
		t.Fatalf("mapElasticsearchPayload: %v", err)
	}
	if req.Severity != "ok" {
		t.Errorf("Severity = %q, want ok for state COMPLETED", req.Severity)
	}
}

func TestMapElasticsearchPayload_ErrorForcesCritical(t *testing.T) {
	body := elasticsearchAlertJSON("ERROR", "5")
	req, err := mapElasticsearchPayload(body)
	if err != nil {
		t.Fatalf("mapElasticsearchPayload: %v", err)
	}
	if req.Severity != "critical" {
		t.Errorf("Severity = %q, want critical for state ERROR", req.Severity)
	}
}

func TestMapElasticsearchPayload_MetricNameIncludesRuleName(t *testing.T) {
	body := elasticsearchAlertJSON("ACTIVE", "1")
	req, err := mapElasticsearchPayload(body)
	if err != nil {
		t.Fatalf("mapElasticsearchPayload: %v", err)
	}
	if !strings.Contains(req.MetricName, "Global-Error-Threshold") {
		t.Errorf("MetricName = %q, want it to contain the rule name", req.MetricName)
	}
}

func TestMapElasticsearchPayload_UniqueIdentifierIsAlertID(t *testing.T) {
	body := elasticsearchAlertJSON("ACTIVE", "1")
	req, err := mapElasticsearchPayload(body)
	if err != nil {
		t.Fatalf("mapElasticsearchPayload: %v", err)
	}
	if req.UniqueIdentifier != sanitizeUniqueIdentifier("alert-id-1") {
		t.Errorf("UniqueIdentifier = %q, want the sanitized alert_id", req.UniqueIdentifier)
	}
}

func TestCreateAlertFromElasticsearch_Success(t *testing.T) {
	store := &mockStore{}
	h := NewAlertHandler(store, "caller-1", "")

	body := elasticsearchAlertJSON("ACTIVE", "1")
	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/elasticsearch", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateAlertFromElasticsearch(w, r)

	assertStatus(t, w, http.StatusAccepted)
	if len(store.enqueuedPayloads) != 1 {
		t.Fatalf("Enqueue called %d times, want 1", len(store.enqueuedPayloads))
	}
}

func TestCreateAlertFromElasticsearch_MalformedBodyReturns400(t *testing.T) {
	store := &mockStore{}
	h := NewAlertHandler(store, "caller-1", "")

	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/elasticsearch", bytes.NewReader([]byte(`not json`)))
	w := httptest.NewRecorder()
	h.CreateAlertFromElasticsearch(w, r)

	assertStatus(t, w, http.StatusBadRequest)
	if len(store.enqueuedPayloads) != 0 {
		t.Error("Enqueue should not be called for a malformed body")
	}
}

func TestCreateAlertFromElasticsearch_StoreFailureReturns500(t *testing.T) {
	store := &mockStore{enqueueFn: func(ctx context.Context, id string, buildPayload func(string) ([]byte, error)) (string, error) {
		return "", errors.New("connection refused")
	}}
	h := NewAlertHandler(store, "caller-1", "")

	body := elasticsearchAlertJSON("ACTIVE", "1")
	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/elasticsearch", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateAlertFromElasticsearch(w, r)

	assertStatus(t, w, http.StatusInternalServerError)
	assertErrorMessage(t, w, ErrMsgInternal)
}

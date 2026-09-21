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

func gcpAlertJSON(severity, state, conditionName string) []byte {
	env, _ := json.Marshal(gcpPayload{Incident: &gcpIncident{
		IncidentID:    "incident-id-1",
		ConditionName: conditionName,
		State:         state,
		Severity:      severity,
		Summary:       "CPU usage above threshold",
		URL:           "https://console.cloud.google.com/incident/1",
		PolicyUserLabels: map[string]string{
			"service":     "Managed Cloud",
			"category":    "service_interruption",
			"environment": "production",
		},
	}})
	return env
}

func TestMapGCPPayload_SeverityTable(t *testing.T) {
	cases := []struct {
		sev  string
		want string
	}{
		{"critical", "critical"},
		{"error", "major"},
		{"warning", "minor"},
		{"info", "ok"},
		{"unrecognized", "ok"},
	}
	for _, tc := range cases {
		t.Run(tc.sev, func(t *testing.T) {
			body := gcpAlertJSON(tc.sev, "open", "high-cpu")
			req, err := mapGCPPayload(body)
			if err != nil {
				t.Fatalf("mapGCPPayload: %v", err)
			}
			if req.Severity != tc.want {
				t.Errorf("Severity = %q, want %q", req.Severity, tc.want)
			}
		})
	}
}

func TestMapGCPPayload_ClosedStateForcesOK(t *testing.T) {
	body := gcpAlertJSON("critical", "closed", "high-cpu")
	req, err := mapGCPPayload(body)
	if err != nil {
		t.Fatalf("mapGCPPayload: %v", err)
	}
	if req.Severity != "ok" {
		t.Errorf("Severity = %q, want ok when state is closed", req.Severity)
	}
}

func TestMapGCPPayload_MissingIncidentErrors(t *testing.T) {
	if _, err := mapGCPPayload([]byte(`{}`)); err == nil {
		t.Fatal("mapGCPPayload({}) should error on missing incident, got nil")
	}
}

func TestMapGCPPayload_UserLabelsPopulateServiceCategoryEnvironment(t *testing.T) {
	body := gcpAlertJSON("critical", "open", "high-cpu")
	req, err := mapGCPPayload(body)
	if err != nil {
		t.Fatalf("mapGCPPayload: %v", err)
	}
	if req.Service != "Managed Cloud" || req.Category != "service_interruption" || req.Environment != "production" {
		t.Errorf("got Service=%q Category=%q Environment=%q, want labels passed through", req.Service, req.Category, req.Environment)
	}
}

func TestMapGCPPayload_NoLabelsFallsBackToDefaultService(t *testing.T) {
	env, _ := json.Marshal(gcpPayload{Incident: &gcpIncident{ConditionName: "high-cpu", State: "open", Severity: "critical"}})
	req, err := mapGCPPayload(env)
	if err != nil {
		t.Fatalf("mapGCPPayload: %v", err)
	}
	if req.Service != gcpDefaultService {
		t.Errorf("Service = %q, want fallback %q", req.Service, gcpDefaultService)
	}
}

func TestCreateAlertFromGCP_MismatchedAuthenticatedSourceReturns403(t *testing.T) {
	store := &mockStore{}
	h := NewAlertHandler(store, "caller-1", "")

	body := gcpAlertJSON("critical", "open", "high-cpu")
	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/gcp", bytes.NewReader(body))
	r = withAuthenticatedUsername(r, "site24x7")
	w := httptest.NewRecorder()
	h.CreateAlertFromGCP(w, r)

	assertStatus(t, w, http.StatusForbidden)
	if len(store.enqueuedPayloads) != 0 {
		t.Error("Enqueue should not be called when the authenticated identity does not match this adapter's fixed source")
	}
}

func TestCreateAlertFromGCP_NoAuthenticatedUsernameReturns500(t *testing.T) {
	store := &mockStore{}
	h := NewAlertHandler(store, "caller-1", "")

	body := gcpAlertJSON("critical", "open", "high-cpu")
	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/gcp", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateAlertFromGCP(w, r)

	assertStatus(t, w, http.StatusInternalServerError)
	assertErrorMessage(t, w, ErrMsgInternal)
	if len(store.enqueuedPayloads) != 0 {
		t.Error("Enqueue should not be called when there is no authenticated identity in context")
	}
}

func TestCreateAlertFromGCP_Success(t *testing.T) {
	store := &mockStore{}
	h := NewAlertHandler(store, "caller-1", "")

	body := gcpAlertJSON("critical", "open", "high-cpu")
	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/gcp", bytes.NewReader(body))
	r = withAuthenticatedUsername(r, "gcp")
	w := httptest.NewRecorder()
	h.CreateAlertFromGCP(w, r)

	assertStatus(t, w, http.StatusAccepted)
	if len(store.enqueuedPayloads) != 1 {
		t.Fatalf("Enqueue called %d times, want 1", len(store.enqueuedPayloads))
	}
}

func TestCreateAlertFromGCP_MalformedBodyReturns400(t *testing.T) {
	store := &mockStore{}
	h := NewAlertHandler(store, "caller-1", "")

	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/gcp", bytes.NewReader([]byte(`not json`)))
	r = withAuthenticatedUsername(r, "gcp")
	w := httptest.NewRecorder()
	h.CreateAlertFromGCP(w, r)

	assertStatus(t, w, http.StatusBadRequest)
	if len(store.enqueuedPayloads) != 0 {
		t.Error("Enqueue should not be called for a malformed body")
	}
}

func TestCreateAlertFromGCP_MissingIncidentReturns400(t *testing.T) {
	store := &mockStore{}
	h := NewAlertHandler(store, "caller-1", "")

	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/gcp", bytes.NewReader([]byte(`{}`)))
	r = withAuthenticatedUsername(r, "gcp")
	w := httptest.NewRecorder()
	h.CreateAlertFromGCP(w, r)

	assertStatus(t, w, http.StatusBadRequest)
}

func TestCreateAlertFromGCP_StoreFailureReturns500(t *testing.T) {
	store := &mockStore{enqueueFn: func(ctx context.Context, id string, buildPayload func(string) ([]byte, error)) (string, error) {
		return "", errors.New("connection refused")
	}}
	h := NewAlertHandler(store, "caller-1", "")

	body := gcpAlertJSON("critical", "open", "high-cpu")
	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/gcp", bytes.NewReader(body))
	r = withAuthenticatedUsername(r, "gcp")
	w := httptest.NewRecorder()
	h.CreateAlertFromGCP(w, r)

	assertStatus(t, w, http.StatusInternalServerError)
	assertErrorMessage(t, w, ErrMsgInternal)
}

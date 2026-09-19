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

func icinga2ServiceAlertJSON(notificationType, serviceState string) []byte {
	body, _ := json.Marshal(icinga2Payload{
		NotificationType: notificationType,
		HostName:         "prod-server-01",
		HostState:        "UP",
		ServiceName:      "http",
		ServiceState:     serviceState,
		ServiceOutput:    "connection timed out",
		Vars:             icinga2Vars{Environment: "production", Service: "managed_services", Category: "service_interruption"},
	})
	return body
}

func icinga2HostAlertJSON(notificationType, hostState string) []byte {
	body, _ := json.Marshal(icinga2Payload{
		NotificationType: notificationType,
		HostName:         "prod-server-01",
		HostState:        hostState,
		Vars:             icinga2Vars{Environment: "production", Service: "managed_services", Category: "service_interruption"},
	})
	return body
}

func TestMapIcinga2Payload_ServiceSeverityTable(t *testing.T) {
	cases := []struct {
		state string
		want  string
	}{
		{"CRITICAL", "critical"},
		{"WARNING", "warning"},
		{"UNKNOWN", "major"},
		{"OK", "ok"},
	}
	for _, tc := range cases {
		t.Run(tc.state, func(t *testing.T) {
			req, err := mapIcinga2Payload(icinga2ServiceAlertJSON("Problem", tc.state))
			if err != nil {
				t.Fatalf("mapIcinga2Payload: %v", err)
			}
			if req.Severity != tc.want {
				t.Errorf("Severity = %q, want %q", req.Severity, tc.want)
			}
		})
	}
}

func TestMapIcinga2Payload_HostSeverityTable(t *testing.T) {
	cases := []struct {
		state string
		want  string
	}{
		{"DOWN", "critical"},
		{"UNREACHABLE", "major"},
		{"UP", "ok"},
	}
	for _, tc := range cases {
		t.Run(tc.state, func(t *testing.T) {
			req, err := mapIcinga2Payload(icinga2HostAlertJSON("Problem", tc.state))
			if err != nil {
				t.Fatalf("mapIcinga2Payload: %v", err)
			}
			if req.Severity != tc.want {
				t.Errorf("Severity = %q, want %q", req.Severity, tc.want)
			}
		})
	}
}

func TestMapIcinga2Payload_RecoveryForcesOKRegardlessOfState(t *testing.T) {
	req, err := mapIcinga2Payload(icinga2ServiceAlertJSON("Recovery", "CRITICAL"))
	if err != nil {
		t.Fatalf("mapIcinga2Payload: %v", err)
	}
	if req.Severity != "ok" {
		t.Errorf("Severity = %q, want ok for a Recovery notification", req.Severity)
	}
}

func TestMapIcinga2Payload_ServiceIdentifierIsHostBangService(t *testing.T) {
	req, err := mapIcinga2Payload(icinga2ServiceAlertJSON("Problem", "CRITICAL"))
	if err != nil {
		t.Fatalf("mapIcinga2Payload: %v", err)
	}
	want := "prod-server-01!http"
	if req.MetricName != want {
		t.Errorf("MetricName = %q, want %q", req.MetricName, want)
	}
	if req.UniqueIdentifier != sanitizeUniqueIdentifier(want) {
		t.Errorf("UniqueIdentifier = %q, want sanitized %q", req.UniqueIdentifier, want)
	}
}

func TestMapIcinga2Payload_HostIdentifierIsBareHostName(t *testing.T) {
	req, err := mapIcinga2Payload(icinga2HostAlertJSON("Problem", "DOWN"))
	if err != nil {
		t.Fatalf("mapIcinga2Payload: %v", err)
	}
	if req.MetricName != "prod-server-01" {
		t.Errorf("MetricName = %q, want bare host name for a host check", req.MetricName)
	}
}

func TestMapIcinga2Payload_MissingHostNameErrors(t *testing.T) {
	if _, err := mapIcinga2Payload([]byte(`{}`)); err == nil {
		t.Fatal("mapIcinga2Payload({}) should error on missing host_name, got nil")
	}
}

func TestCreateAlertFromIcinga2_Success(t *testing.T) {
	store := &mockStore{}
	h := NewAlertHandler(store, "caller-1", "")

	body := icinga2ServiceAlertJSON("Problem", "CRITICAL")
	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/icinga2", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateAlertFromIcinga2(w, r)

	assertStatus(t, w, http.StatusAccepted)
	if len(store.enqueuedPayloads) != 1 {
		t.Fatalf("Enqueue called %d times, want 1", len(store.enqueuedPayloads))
	}
}

func TestCreateAlertFromIcinga2_MalformedBodyReturns400(t *testing.T) {
	store := &mockStore{}
	h := NewAlertHandler(store, "caller-1", "")

	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/icinga2", bytes.NewReader([]byte(`not json`)))
	w := httptest.NewRecorder()
	h.CreateAlertFromIcinga2(w, r)

	assertStatus(t, w, http.StatusBadRequest)
	if len(store.enqueuedPayloads) != 0 {
		t.Error("Enqueue should not be called for a malformed body")
	}
}

func TestCreateAlertFromIcinga2_MissingHostNameReturns400(t *testing.T) {
	store := &mockStore{}
	h := NewAlertHandler(store, "caller-1", "")

	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/icinga2", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()
	h.CreateAlertFromIcinga2(w, r)

	assertStatus(t, w, http.StatusBadRequest)
}

func TestCreateAlertFromIcinga2_StoreFailureReturns500(t *testing.T) {
	store := &mockStore{enqueueFn: func(ctx context.Context, id string, buildPayload func(string) ([]byte, error)) (string, error) {
		return "", errors.New("connection refused")
	}}
	h := NewAlertHandler(store, "caller-1", "")

	body := icinga2ServiceAlertJSON("Problem", "CRITICAL")
	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/icinga2", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateAlertFromIcinga2(w, r)

	assertStatus(t, w, http.StatusInternalServerError)
	assertErrorMessage(t, w, ErrMsgInternal)
}

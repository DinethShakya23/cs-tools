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

func datadogAlertJSON(transition, tags string) []byte {
	body, _ := json.Marshal(datadogPayload{
		EventName:   "High CPU Alert",
		TriggerName: "avg(last_5m):avg:system.cpu.user{*} > 90",
		Transition:  transition,
		AlertID:     "12345678",
		Service:     "client-alert-integration",
		Category:    "service_interruption",
		Tags:        tags,
	})
	return body
}

func TestParseDatadogTags(t *testing.T) {
	got := parseDatadogTags("env:production,severity:1,bareTag,team:sre")
	if got["env"] != "production" || got["severity"] != "1" || got["team"] != "sre" {
		t.Errorf("parseDatadogTags = %v, want env/severity/team parsed", got)
	}
	if _, ok := got["bareTag"]; ok {
		t.Error("a bare tag with no colon should not produce a map entry")
	}
}

func TestMapDatadogPayload_SeverityTable(t *testing.T) {
	cases := []struct {
		sev  string
		want string
	}{
		{"1", "critical"},
		{"2", "major"},
		{"3", "minor"},
		{"4", "warning"},
		{"5", "ok"},
	}
	for _, tc := range cases {
		t.Run(tc.sev, func(t *testing.T) {
			body := datadogAlertJSON("Triggered", "env:production,severity:"+tc.sev)
			req, err := mapDatadogPayload(body)
			if err != nil {
				t.Fatalf("mapDatadogPayload: %v", err)
			}
			if req.Severity != tc.want {
				t.Errorf("Severity = %q, want %q", req.Severity, tc.want)
			}
		})
	}
}

func TestMapDatadogPayload_RecoveredForcesOKRegardlessOfSeverityTag(t *testing.T) {
	body := datadogAlertJSON("Recovered", "env:production,severity:1")
	req, err := mapDatadogPayload(body)
	if err != nil {
		t.Fatalf("mapDatadogPayload: %v", err)
	}
	if req.Severity != "ok" {
		t.Errorf("Severity = %q, want ok when transition is Recovered", req.Severity)
	}
}

func TestMapDatadogPayload_EnvironmentFromTags(t *testing.T) {
	body := datadogAlertJSON("Triggered", "env:staging,severity:2")
	req, err := mapDatadogPayload(body)
	if err != nil {
		t.Fatalf("mapDatadogPayload: %v", err)
	}
	if req.Environment != "staging" {
		t.Errorf("Environment = %q, want staging (from tags)", req.Environment)
	}
}

func TestMapDatadogPayload_UniqueIdentifierIsAlertID(t *testing.T) {
	body := datadogAlertJSON("Triggered", "env:production,severity:1")
	req, err := mapDatadogPayload(body)
	if err != nil {
		t.Fatalf("mapDatadogPayload: %v", err)
	}
	if req.UniqueIdentifier != sanitizeUniqueIdentifier("12345678") {
		t.Errorf("UniqueIdentifier = %q, want the sanitized alert_id", req.UniqueIdentifier)
	}
}

func TestCreateAlertFromDatadog_Success(t *testing.T) {
	store := &mockStore{}
	h := NewAlertHandler(store, "caller-1", "")

	body := datadogAlertJSON("Triggered", "env:production,severity:1")
	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/datadog", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateAlertFromDatadog(w, r)

	assertStatus(t, w, http.StatusAccepted)
	if len(store.enqueuedPayloads) != 1 {
		t.Fatalf("Enqueue called %d times, want 1", len(store.enqueuedPayloads))
	}
}

func TestCreateAlertFromDatadog_MalformedBodyReturns400(t *testing.T) {
	store := &mockStore{}
	h := NewAlertHandler(store, "caller-1", "")

	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/datadog", bytes.NewReader([]byte(`not json`)))
	w := httptest.NewRecorder()
	h.CreateAlertFromDatadog(w, r)

	assertStatus(t, w, http.StatusBadRequest)
	if len(store.enqueuedPayloads) != 0 {
		t.Error("Enqueue should not be called for a malformed body")
	}
}

func TestCreateAlertFromDatadog_StoreFailureReturns500(t *testing.T) {
	store := &mockStore{enqueueFn: func(ctx context.Context, id string, buildPayload func(string) ([]byte, error)) (string, error) {
		return "", errors.New("connection refused")
	}}
	h := NewAlertHandler(store, "caller-1", "")

	body := datadogAlertJSON("Triggered", "env:production,severity:1")
	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/datadog", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateAlertFromDatadog(w, r)

	assertStatus(t, w, http.StatusInternalServerError)
	assertErrorMessage(t, w, ErrMsgInternal)
}

package webhook

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	secret = "whsec_test"
	body   = `{"id":"e1","type":"webhook.ping","created_at":"2026-01-01T00:00:00Z","data":{"endpoint_id":"ep1"}}`
	// openssl dgst -sha256 -hmac whsec_test over "1767225600." + body: the
	// algorithm the server signs with, computed outside this package.
	vector = "t=1767225600,v1=2885450527e4eef3579a106907e545c4bcb5a445cb02016b420dc4c41ba0e6c1"
)

var signedAt = time.Unix(1767225600, 0)

func TestSignMatchesServerAlgorithm(t *testing.T) {
	if got := Sign(secret, signedAt, []byte(body)); got != vector {
		t.Fatalf("Sign = %s, want %s", got, vector)
	}
}

func TestVerify(t *testing.T) {
	cases := []struct {
		name   string
		secret string
		header string
		body   string
		now    time.Time
		want   bool
	}{
		{"valid", secret, vector, body, signedAt.Add(time.Minute), true},
		{"spaces after commas", secret, "t=1767225600, v1=2885450527e4eef3579a106907e545c4bcb5a445cb02016b420dc4c41ba0e6c1", body, signedAt, true},
		{"wrong secret", "other", vector, body, signedAt, false},
		{"tampered body", secret, vector, strings.Replace(body, "ep1", "ep2", 1), signedAt, false},
		{"too old", secret, vector, body, signedAt.Add(Tolerance + time.Second), false},
		{"from the future", secret, vector, body, signedAt.Add(-Tolerance - time.Second), false},
		{"no signature", secret, "t=1767225600", body, signedAt, false},
		{"no time", secret, "v1=2885450527e4eef3579a106907e545c4bcb5a445cb02016b420dc4c41ba0e6c1", body, signedAt, false},
		{"empty header", secret, "", body, signedAt, false},
		{"empty secret", "", Sign("", signedAt, []byte(body)), body, signedAt, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Verify(c.secret, c.header, []byte(c.body), c.now); got != c.want {
				t.Fatalf("Verify = %v, want %v", got, c.want)
			}
		})
	}
}

func deliver(h http.Handler, secret, payload string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/hook", strings.NewReader(payload))
	r.Header.Set(HeaderSignature, Sign(secret, time.Now(), []byte(payload)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestHandler(t *testing.T) {
	var got *Event
	ok := func(_ context.Context, e *Event) error { got = e; return nil }

	h := Handler(ok, "new", secret)
	if w := deliver(h, secret, body); w.Code != http.StatusNoContent {
		t.Fatalf("old secret during rotation: status %d", w.Code)
	}
	if got == nil || got.ID != "e1" || got.Type != Ping || !got.CreatedAt.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("event = %+v", got)
	}

	if w := deliver(h, "wrong", body); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: status %d", w.Code)
	}
	if w := deliver(h, secret, "{"); w.Code != http.StatusBadRequest {
		t.Fatalf("bad JSON: status %d", w.Code)
	}
	failing := Handler(func(context.Context, *Event) error { return errors.New("db down") }, secret)
	if w := deliver(failing, secret, body); w.Code != http.StatusInternalServerError {
		t.Fatalf("failing receiver must ask for a retry: status %d", w.Code)
	}
	if w := deliver(Handler(ok), secret, body); w.Code != http.StatusUnauthorized {
		t.Fatalf("no secrets configured must refuse: status %d", w.Code)
	}
	r := httptest.NewRequest(http.MethodGet, "/hook", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: status %d", w.Code)
	}
}

func TestParse(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/hook", strings.NewReader(body))
	r.Header.Set(HeaderSignature, Sign(secret, time.Now(), []byte(body)))
	e, err := Parse(r, secret)
	if err != nil || e.ID != "e1" {
		t.Fatalf("Parse = %+v, %v", e, err)
	}
	r = httptest.NewRequest(http.MethodPost, "/hook", strings.NewReader(body))
	r.Header.Set(HeaderSignature, vector) // signed long ago
	if _, err := Parse(r, secret); !errors.Is(err, ErrSignature) {
		t.Fatalf("stale signature: err = %v", err)
	}
}

func TestDecodeData(t *testing.T) {
	e := &Event{Type: AttemptSubmitted, Data: []byte(`{
		"attempt_id":"a1","assignment_id":"s1","exam_id":"x1","exam_version":3,"person_id":"p1",
		"started_at":"2026-01-01T09:00:00Z","submitted_at":"2026-01-01T09:40:00Z",
		"score":{"pct":80,"points":8,"max":10,"passed":true,"pending_review":false},
		"items":[{"item_id":"q1","points":8,"max":8},{"item_id":"q2","points":null,"max":2}]}`)}
	a, err := e.Attempt()
	if err != nil {
		t.Fatal(err)
	}
	if a.AttemptID != "a1" || a.ExamVersion != 3 || a.DeadlineAt != nil || a.SubmittedAt == nil ||
		a.Score == nil || a.Score.Pct != 80 || !a.Score.Passed {
		t.Fatalf("attempt = %+v", a)
	}
	if len(a.Items) != 2 || a.Items[0].Points == nil || *a.Items[0].Points != 8 || a.Items[1].Points != nil || a.Items[1].Max != 2 {
		t.Fatalf("items = %+v", a.Items)
	}
	if _, err := e.Invitation(); err == nil {
		t.Fatal("an attempt event decoded as an invitation")
	}

	e = &Event{Type: AssignmentInvited, Data: []byte(`{"assignment_id":"s1","exam_id":"x1","exam_version":1,
		"person_id":"p1","reason":"sent","expires_at":"2026-01-08T00:00:00Z"}`)}
	if i, err := e.Invitation(); err != nil || i.AssignmentID != "s1" || i.ExpiresAt.IsZero() {
		t.Fatalf("invitation = %+v, %v", i, err)
	}

	e = &Event{Type: CredentialRevoked, Data: []byte(`{"credential_id":"c1","attempt_id":"a1","exam_id":"x1",
		"person_id":"p1","url":"https://example.com/credentials/c1","reason":"misconduct"}`)}
	if c, err := e.Credential(); err != nil || c.Reason != "misconduct" {
		t.Fatalf("credential = %+v, %v", c, err)
	}

	e = &Event{Type: ExamPublished, Data: []byte(`{"exam_id":"x1","version":2,"kind":"EXAM_KIND_TEST","title":"Go"}`)}
	if x, err := e.Exam(); err != nil || x.Version != 2 {
		t.Fatalf("exam = %+v, %v", x, err)
	}
}

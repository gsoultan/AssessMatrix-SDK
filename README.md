# AssessMatrix SDK for Go

A Go client for an [AssessMatrix](https://github.com/gsoultan/AssessMatrix) server, and a
receiver for its webhooks.

```sh
go get github.com/gsoultan/assessmatrix-sdk
```

| Package | What it is |
| :--- | :--- |
| `assessmatrix` | `Client`: every service, plus staff sign-in, the session and tenant switching |
| `webhook` | Verify signatures and decode events; an `http.Handler` that does both |
| `gen/assessmatrix/v1` | Messages, generated from the schema |
| `gen/assessmatrix/v1/assessmatrixv1connect` | Connect clients and handlers, generated |

The schema in `proto/` is a copy of `packages/proto` in the AssessMatrix repository, and
`proto/SOURCE` names the commit it was taken from. Nothing here is hand-written over the
schema, so anything the studio can do, the SDK can do.

## Sign in and call the API

Staff sign in with an emailed one-time code; there are no API keys. The server answers a
verified code with a session cookie, which the `Client` keeps and sends on every call.

```go
c, err := assessmatrix.New("https://assess.example.com")
if err != nil { ... }

if err := c.RequestCode(ctx, "ops@example.com"); err != nil { ... }
staff, err := c.VerifyCode(ctx, "ops@example.com", code) // the code from the email
if errors.Is(err, assessmatrix.ErrCodeRejected) { ... }   // wrong, expired or used

// Put people on the roster, assign them a published instrument and mail the links.
people, err := c.People.EnsurePeople(ctx, connect.NewRequest(&v1.EnsurePeopleRequest{
	People: []*v1.PersonDraft{{Name: "Ana", Email: "ana@example.com", Group: "Batch 7"}},
}))
_, err = c.Assignments.AssignPeople(ctx, connect.NewRequest(&v1.AssignPeopleRequest{
	ExamId: examID, PersonIds: people.Msg.GetIds(),
}))
```

A session lasts 12 hours. To keep one across restarts, store `c.Session()` like a password and
pass it back with `assessmatrix.WithSession(token)`. When it has ended, calls fail with
`connect.CodeUnauthenticated` (`assessmatrix.Code(err)`); sign in again.

### Tenants

A session works in one tenant at a time; nothing reads two tenants in one request.
`c.Tenants.ListMyTenants` lists the ones you have access to and `c.SwitchTenant(ctx, id)`
moves the session to another. Use one `Client` per tenant if you work in several at once.

What a call may do follows your role in the session's tenant: members build, invite and
score; administrators also add staff to their tenant and share instruments; a super
administrator creates tenants and decides who administers them (`TenantService`). These
roles are for staff. Candidates are people on the roster and never sign in as staff.

### Candidates

`c.Candidates` is the API the candidate runner uses. It is authorised by the candidate's own
link and emailed code, not by a staff session, and links and codes are never readable through
the staff API. To send someone a test, assign them (`AssignPeople`) or mail a fresh link
(`SendInvites`); the server emails the link itself.

## Receive webhooks

Create an endpoint on the Webhooks screen or with `c.Webhooks.CreateWebhook`; the secret is
shown once.

```go
http.Handle("/hooks/assessmatrix", webhook.Handler(func(ctx context.Context, e *webhook.Event) error {
	if alreadyHandled(e.ID) { // the same event can arrive more than once
		return nil
	}
	switch e.Type {
	case webhook.AttemptSubmitted, webhook.AttemptExpired:
		a, err := e.Attempt()
		if err != nil {
			return err
		}
		if a.Score != nil {
			record(a.PersonID, a.ExamID, a.Score.Pct, a.Score.Passed)
		}
	}
	return nil
}, secret))
```

- The handler answers 401 to a request not signed with `secret`, or signed more than five
  minutes ago. While rotating, pass both secrets, newest first.
- Return an error to have the server try again later (ten tries over about four hours).
- Delivery is at least once: de-duplicate on `Event.ID`. One attempt's events, and its
  credential's, arrive in the order they happened; order anything else by `Event.CreatedAt`.
- `attempt.submitted`, `attempt.expired` and `attempt.scored` carry `Score` and `Items`, each
  question's points out of the points its author set (`Points` is nil while an essay waits).
- `client.Webhooks.ReplayEvents` sends an endpoint one attempt's events, or a time window's,
  again with their original ids.
- Payloads carry ids, versions, times and scores only. Fetch names and answers through the API.

| Event | Data |
| :--- | :--- |
| `exam.published` | `e.Exam()` |
| `assignment.invited` | `e.Invitation()` |
| `attempt.started` · `attempt.submitted` · `attempt.expired` · `attempt.scored` | `e.Attempt()` |
| `credential.issued` · `credential.revoked` | `e.Credential()` |
| `webhook.ping` | `{"endpoint_id"}` via `e.Decode` |

## Updating to a new server version

```sh
make sync     # copy the schema from ../AssessMatrix (AM_REPO=path to override) and regenerate
make check    # vet and test
```

`make generate` needs `buf`, `protoc-gen-go` and `protoc-gen-connect-go` on your `PATH`; the
versions CI uses are in `.github/workflows/ci.yml`. CI fails if `gen/` does not match
`proto/`.

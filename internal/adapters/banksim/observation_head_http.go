package banksim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"zhiyu.local/zhiyu-go/internal/execution/bankcredit"
)

func registerObservationHead(mux *http.ServeMux, store *Store, clock func() time.Time) {
	mux.HandleFunc("GET /v2/observation-head", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if len(q) != 2 || len(q["namespace"]) != 1 || len(q["user_id"]) != 1 {
			writeError(w, http.StatusBadRequest, "BANK_OBSERVATION_HEAD_UNAVAILABLE")
			return
		}
		head, err := store.ObservationHead(r.Context(), q.Get("namespace"), q.Get("user_id"), clock())
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "BANK_OBSERVATION_HEAD_UNAVAILABLE")
			return
		}
		writeJSON(w, http.StatusOK, head)
	})
}

// DaemonObservationClient can only be built explicitly from the three concrete
// configured readers. No optional method on an arbitrary Source implies that
// its credit, legacy, and native state belong to this bank.
type DaemonObservationClient struct {
	credit    *ExternalCreditClient
	legacy    *Client
	native    *ClientV2
	transport *http.Transport
	binding   string
}

func observationSharedTransport(credit, legacy, native *Client) (*http.Transport, bool) {
	if credit == nil || legacy == nil || native == nil || credit.http == nil || legacy.http == nil || native.http == nil {
		return nil, false
	}
	a, x := credit.http.Transport.(*http.Transport)
	b, y := legacy.http.Transport.(*http.Transport)
	c, z := native.http.Transport.(*http.Transport)
	if !x || !y || !z || a == nil || a != b || a != c || a.Proxy != nil {
		return nil, false
	}
	for _, client := range []*Client{credit, legacy, native} {
		if client.http.Jar != nil || client.http.Timeout != 5*time.Second || client.http.CheckRedirect == nil {
			return nil, false
		}
	}
	return a, true
}

func NewDaemonObservationClient(credit *ExternalCreditClient, legacy *Client, native *ClientV2) (*DaemonObservationClient, error) {
	if credit == nil || credit.transport == nil || credit.transport.transport == nil || legacy == nil || native == nil || native.transport == nil {
		return nil, errors.New("explicit daemon source readers required")
	}
	if credit.transport.transport.base != legacy.base || native.transport.base != legacy.base {
		return nil, errors.New("daemon source bank endpoints differ")
	}
	transport, ok := observationSharedTransport(credit.transport.transport, legacy, native.transport)
	if !ok {
		return nil, errors.New("daemon sources require one shared direct transport without cookie jars")
	}
	return &DaemonObservationClient{credit: credit, legacy: legacy, native: native, transport: transport, binding: observationSHA(bankcredit.ObservationHeadProtocol + "/shared-direct-transport/" + legacy.base)}, nil
}

func (c *DaemonObservationClient) ScopeBinding() string { return c.binding }
func (c *DaemonObservationClient) MatchesSources(credit, legacy, native any) bool {
	a, x := credit.(*ExternalCreditClient)
	b, y := legacy.(*Client)
	d, z := native.(*ClientV2)
	if !x || !y || !z || a != c.credit || b != c.legacy || d != c.native {
		return false
	}
	transport, ok := observationSharedTransport(a.transport.transport, b, d.transport)
	return ok && transport == c.transport
}
func (c *DaemonObservationClient) Head(ctx context.Context, namespace, user string) (bankcredit.ObservationHead, error) {
	var out bankcredit.ObservationHead
	if !c.MatchesSources(c.credit, c.legacy, c.native) {
		return out, errObservationUnavailable
	}
	if !bankcredit.Scope(namespace, user) {
		return out, bankcredit.ErrInvalid
	}
	path := "/v2/observation-head?" + url.Values{"namespace": {namespace}, "user_id": {user}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.native.transport.base+path, nil)
	if err != nil {
		return out, err
	}
	response, err := c.native.transport.http.Do(req)
	if err != nil {
		return out, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return out, errObservationUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil || len(raw) > 16384 || !uniqueJSON(raw) {
		return out, errObservationUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&out) != nil || decoder.Decode(new(any)) != io.EOF {
		return out, errObservationUnavailable
	}
	if out.Validate() != nil || out.Namespace != namespace || out.UserID != user {
		return out, bankcredit.ErrInvalid
	}
	return out, nil
}

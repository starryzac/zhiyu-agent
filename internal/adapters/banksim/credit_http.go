package banksim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"zhiyu.local/zhiyu-go/internal/execution/bankcredit"
)

func creditHTTPError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrCreditUnauthorized):
		writeError(w, http.StatusForbidden, ErrCreditUnauthorized.Error())
	case errors.Is(err, ErrCreditCapacity):
		writeError(w, http.StatusUnprocessableEntity, ErrCreditCapacity.Error())
	case errors.Is(err, bankcredit.ErrInvalid):
		writeError(w, http.StatusBadRequest, "INVALID_EXTERNAL_CREDIT")
	default:
		bankError(w, err)
	}
}

// CreditReadHandler deliberately has no write route. It may wrap unchanged
// v1/v2 handlers once the separate bank003 migration is explicitly enabled.
func CreditReadHandler(store *Store, fallback http.Handler) http.Handler {
	return CreditReadHandlerWithOptions(store, HandlerOptions{}, fallback)
}

// Clock is trusted server configuration, shared with POST/quote handlers in
// controlled simulation. No query parameter or request body supplies it.
func CreditReadHandlerWithOptions(store *Store, options HandlerOptions, fallback http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v3/income/credits", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		after, ae := number(q.Get("after"), 0)
		limit, le := number(q.Get("limit"), 100)
		var watermark *int64
		if q.Has("watermark") {
			n, err := strconv.ParseInt(q.Get("watermark"), 10, 64)
			if err != nil {
				creditHTTPError(w, bankcredit.ErrInvalid)
				return
			}
			watermark = &n
		}
		if ae != nil || le != nil || limit < 1 || limit > bankcredit.MaxPage {
			creditHTTPError(w, bankcredit.ErrInvalid)
			return
		}
		out, err := store.ExternalCreditInventory(r.Context(), q.Get("namespace"), q.Get("user_id"), after, watermark, int(limit))
		if err != nil {
			creditHTTPError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("GET /v3/income/credits/{namespace}/{authority}/{event}", func(w http.ResponseWriter, r *http.Request) {
		out, err := store.LookupExternalCredit(r.Context(), r.PathValue("namespace"), r.URL.Query().Get("user_id"), r.PathValue("authority"), r.PathValue("event"))
		if err != nil {
			creditHTTPError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("GET /v3/income/state", func(w http.ResponseWriter, r *http.Request) {
		var out bankcredit.CurrentState
		var err error
		if options.Clock == nil {
			out, err = store.CurrentIncomeState(r.Context(), r.URL.Query().Get("namespace"), r.URL.Query().Get("user_id"))
		} else {
			out, err = store.CurrentIncomeStateAt(r.Context(), r.URL.Query().Get("namespace"), r.URL.Query().Get("user_id"), options.Clock())
		}
		if err != nil {
			creditHTTPError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	})
	if fallback != nil {
		mux.Handle("/", fallback)
	}
	return mux
}

// ExternalCreditHandler is an explicitly provisioned write capability, never
// implicitly enabled by an ordinary application bank permit.
func ExternalCreditHandler(gateway *CreditGateway, options HandlerOptions, fallback http.Handler) http.Handler {
	mux := http.NewServeMux()
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	mux.HandleFunc("POST /v3/external-credits", func(w http.ResponseWriter, r *http.Request) {
		if gateway == nil {
			creditHTTPError(w, ErrCreditUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, bankcredit.MaxEventBytes)
		raw, err := io.ReadAll(r.Body)
		if err != nil || !uniqueV2JSON(raw) {
			creditHTTPError(w, bankcredit.ErrInvalid)
			return
		}
		var event bankcredit.Event
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&event) != nil {
			creditHTTPError(w, bankcredit.ErrInvalid)
			return
		}
		out, err := gateway.Submit(r.Context(), event, r.Header.Get("X-Zhiyu-External-Credit"), clock().UTC())
		if err != nil {
			creditHTTPError(w, err)
			return
		}
		if options.TestFaults && r.Header.Get("X-Zhiyu-Test-Fault") == "drop-after-commit" {
			if h, ok := w.(http.Hijacker); ok {
				connection, _, err := h.Hijack()
				if err == nil {
					_ = connection.Close()
					return
				}
			}
			writeError(w, http.StatusServiceUnavailable, "TEST_CREDIT_RESPONSE_LOST_AFTER_COMMIT")
			return
		}
		writeJSON(w, http.StatusOK, out)
	})
	if fallback != nil {
		mux.Handle("/", fallback)
	}
	return mux
}

// ExternalCreditClient is a read-only client. Only an independently authorized
// external feeder may send the write HTTP request or hold its secret.
type ExternalCreditClient struct{ transport *ClientV2 }

func NewExternalCreditClient(base string, client *http.Client) (*ExternalCreditClient, error) {
	t, err := NewClientV2(base, client)
	if err != nil {
		return nil, err
	}
	return &ExternalCreditClient{transport: t}, nil
}
func (c *ExternalCreditClient) Lookup(ctx context.Context, namespace, user, authority, event string) (bankcredit.Lookup, error) {
	var out bankcredit.Lookup
	if !bankcredit.Scope(namespace, user) || !bankcredit.Identity(authority) || !bankcredit.Identity(event) {
		return out, bankcredit.ErrInvalid
	}
	path := "/v3/income/credits/" + url.PathEscape(namespace) + "/" + url.PathEscape(authority) + "/" + url.PathEscape(event) + "?" + url.Values{"user_id": {user}}.Encode()
	err := c.transport.call(ctx, "GET", path, nil, "", "", &out)
	if err == nil && (out.Protocol != bankcredit.Protocol+"/lookup" || out.Namespace != namespace || out.UserID != user || out.AuthorityID != authority || out.EventID != event || out.Found != (out.Entry != nil)) {
		err = bankcredit.ErrInvalid
	}
	if err == nil && out.Entry != nil {
		e := out.Entry.Record.Event
		if out.Entry.Validate() != nil || e.Namespace != namespace || e.UserID != user || e.AuthorityID != authority || e.EventID != event {
			err = bankcredit.ErrInvalid
		}
	}
	return out, err
}
func (c *ExternalCreditClient) Inventory(ctx context.Context, namespace, user string, after int64, watermark *int64, limit int) (bankcredit.Inventory, error) {
	var out bankcredit.Inventory
	q := url.Values{"namespace": {namespace}, "user_id": {user}, "after": {strconv.FormatInt(after, 10)}, "limit": {strconv.Itoa(limit)}}
	if watermark != nil {
		q.Set("watermark", strconv.FormatInt(*watermark, 10))
	}
	err := c.transport.call(ctx, "GET", "/v3/income/credits?"+q.Encode(), nil, "", "", &out)
	if err == nil && (out.Namespace != namespace || out.UserID != user || out.Validate(after, watermark, limit) != nil) {
		err = bankcredit.ErrInvalid
	}
	return out, err
}
func (c *ExternalCreditClient) CurrentState(ctx context.Context, namespace, user string) (bankcredit.CurrentState, error) {
	var out bankcredit.CurrentState
	err := c.transport.call(ctx, "GET", "/v3/income/state?"+url.Values{"namespace": {namespace}, "user_id": {user}}.Encode(), nil, "", "", &out)
	if err == nil && (out.Namespace != namespace || out.UserID != user || out.Validate() != nil) {
		err = bankcredit.ErrInvalid
	}
	return out, err
}

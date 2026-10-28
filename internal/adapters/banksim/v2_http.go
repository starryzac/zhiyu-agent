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
	"strings"
	"time"

	bankv2 "zhiyu.local/zhiyu-go/internal/execution/bankv2"
)

func v2ReadJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	raw, err := io.ReadAll(r.Body)
	if err != nil || !uniqueV2JSON(raw) {
		writeError(w, 400, "INVALID_BANK_V2_REQUEST")
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		writeError(w, 400, "INVALID_BANK_V2_REQUEST")
		return false
	}
	return true
}
func uniqueV2JSON(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	var consume func(int) bool
	consume = func(depth int) bool {
		nodes++
		if depth > 20 || nodes > 10000 {
			return false
		}
		token, err := d.Token()
		if err != nil {
			return false
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					if err != nil {
						return false
					}
					s, ok := key.(string)
					if !ok || seen[s] {
						return false
					}
					seen[s] = true
					if !consume(depth + 1) {
						return false
					}
				}
				end, err := d.Token()
				return err == nil && end == json.Delim('}')
			case '[':
				for d.More() {
					if !consume(depth + 1) {
						return false
					}
				}
				end, err := d.Token()
				return err == nil && end == json.Delim(']')
			default:
				return false
			}
		}
		return true
	}
	if !consume(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}
func v2HTTPError(w http.ResponseWriter, err error) {
	if errors.Is(err, bankv2.ErrInvalid) {
		writeError(w, 400, "INVALID_BANK_V2_REQUEST")
		return
	}
	if errors.Is(err, ErrV2Capacity) {
		writeError(w, 422, ErrV2Capacity.Error())
		return
	}
	if errors.Is(err, ErrReconciliation) {
		writeError(w, 409, ErrReconciliation.Error())
		return
	}
	bankError(w, err)
}
func v2Drop(w http.ResponseWriter, r *http.Request, enabled bool) bool {
	if !enabled || r.Header.Get("X-Zhiyu-Test-Fault") != "drop-after-commit" {
		return false
	}
	if hijack, ok := w.(http.Hijacker); ok {
		conn, _, err := hijack.Hijack()
		if err == nil {
			conn.Close()
			return true
		}
	}
	writeError(w, 503, "TEST_RESPONSE_LOST_AFTER_COMMIT")
	return true
}

// HandlerV2 keeps v1 routing intact while explicitly adding v2. Opening/import
// and catalog writes stay private to trusted callers; HTTP cannot set balances.
func HandlerV2(store *Store, options HandlerOptions) http.Handler {
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	old := Handler(store, options)
	mux := http.NewServeMux()
	registerLiabilityReadV2(mux, store, clock)
	registerObservationHead(mux, store, clock)
	registerRecoverySubjects(mux, store)
	mux.HandleFunc("GET /v2/healthz", func(w http.ResponseWriter, r *http.Request) {
		if store.CheckV2(r.Context()) != nil {
			writeError(w, 503, "BANK_V2_SCHEMA_UNAVAILABLE")
			return
		}
		writeJSON(w, 200, map[string]any{"protocol": bankv2.Protocol, "simulation": true, "schema_sha256": frozenBankV2Migration})
	})
	mux.HandleFunc("POST /v2/operations", func(w http.ResponseWriter, r *http.Request) {
		var request bankv2.Request
		if !v2ReadJSON(w, r, &request) {
			return
		}
		result, err := store.SubmitV2(r.Context(), request, r.Header.Get("X-Zhiyu-Permit"), clock())
		if err != nil {
			v2HTTPError(w, err)
			return
		}
		if !v2Drop(w, r, options.TestFaults) {
			writeJSON(w, 200, result)
		}
	})
	mux.HandleFunc("GET /v2/operations/{namespace}/{key}", func(w http.ResponseWriter, r *http.Request) {
		result, err := store.LookupV2(r.Context(), r.PathValue("namespace"), r.URL.Query().Get("user_id"), r.PathValue("key"))
		if err != nil {
			v2HTTPError(w, err)
			return
		}
		writeJSON(w, 200, result)
	})
	mux.HandleFunc("POST /v2/operations/{namespace}/{key}/settle", func(w http.ResponseWriter, r *http.Request) {
		result, err := store.SettleV2(r.Context(), r.PathValue("namespace"), r.URL.Query().Get("user_id"), r.PathValue("key"), clock())
		if err != nil {
			v2HTTPError(w, err)
			return
		}
		if !v2Drop(w, r, options.TestFaults) {
			writeJSON(w, 200, result)
		}
	})
	mux.HandleFunc("GET /v2/operations", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		a, ae := number(q.Get("after"), 0)
		water, we := number(q.Get("watermark"), 0)
		limit, le := number(q.Get("limit"), 20)
		if ae != nil || we != nil || le != nil {
			writeError(w, 400, "INVALID_INVENTORY_BOUNDS")
			return
		}
		result, err := store.InventoryV2(r.Context(), q.Get("namespace"), q.Get("user_id"), a, water, int(limit))
		if err != nil {
			v2HTTPError(w, err)
			return
		}
		writeJSON(w, 200, result)
	})
	mux.HandleFunc("GET /v2/state", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var result bankv2.CurrentState
		var err error
		if options.Clock == nil {
			result, err = store.CurrentStateV2(r.Context(), q.Get("namespace"), q.Get("user_id"))
		} else {
			result, err = store.CurrentStateV2At(r.Context(), q.Get("namespace"), q.Get("user_id"), clock())
		}
		if err != nil {
			v2HTTPError(w, err)
			return
		}
		writeJSON(w, 200, result)
	})
	mux.HandleFunc("POST /v2/quotes", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Namespace  string      `json:"namespace"`
			UserID     string      `json:"user_id"`
			PositionID string      `json:"position_id"`
			Kind       bankv2.Kind `json:"kind"`
		}
		if !v2ReadJSON(w, r, &request) {
			return
		}
		result, err := store.QuoteV2(r.Context(), request.Namespace, request.UserID, request.PositionID, request.Kind, clock())
		if err != nil {
			v2HTTPError(w, err)
			return
		}
		writeJSON(w, 200, result)
	})
	mux.HandleFunc("POST /v2/goals", func(w http.ResponseWriter, r *http.Request) {
		var request bankv2.GoalRegistration
		if !v2ReadJSON(w, r, &request) {
			return
		}
		if err := store.RegisterGoalV2(r.Context(), request, r.Header.Get("X-Zhiyu-Permit"), clock()); err != nil {
			v2HTTPError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"protocol": bankv2.Protocol + "/zero-goal", "namespace": request.Namespace, "user_id": request.UserID, "goal_id": request.GoalID, "account_id": request.AccountID, "registered": true})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v2/") {
			mux.ServeHTTP(w, r)
		} else {
			old.ServeHTTP(w, r)
		}
	})
}

type ClientV2 struct{ transport *Client }

func NewClientV2(base string, httpClient *http.Client) (*ClientV2, error) {
	c, err := NewClient(base, httpClient)
	if err != nil {
		return nil, err
	}
	return &ClientV2{c}, nil
}
func (c *ClientV2) call(ctx context.Context, method, path string, input any, signature, fault string, out any) error {
	var body io.Reader
	if input != nil {
		raw, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.transport.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if signature != "" {
		req.Header.Set("X-Zhiyu-Permit", signature)
	}
	if fault != "" {
		req.Header.Set("X-Zhiyu-Test-Fault", fault)
	}
	response, err := c.transport.http.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		var data struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(response.Body, 8192)).Decode(&data)
		for _, known := range []error{ErrConflict, ErrUnauthorized, ErrNotDue, ErrNotFound, ErrPendingOrder, ErrReconciliation, ErrV2Capacity} {
			if data.Error == known.Error() {
				return known
			}
		}
		return errors.New("bank v2 HTTP " + strconv.Itoa(response.StatusCode))
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (16<<20)+1))
	if err != nil {
		return err
	}
	if len(raw) > 16<<20 {
		return ErrV2Capacity
	}
	return json.Unmarshal(raw, out)
}
func (c *ClientV2) Submit(ctx context.Context, r bankv2.Request, signature string) (bankv2.Result, error) {
	return c.SubmitWithTestFault(ctx, r, signature, "")
}
func (c *ClientV2) SubmitWithTestFault(ctx context.Context, r bankv2.Request, signature, fault string) (bankv2.Result, error) {
	var out bankv2.Result
	if r.Validate() != nil {
		return out, bankv2.ErrInvalid
	}
	err := c.call(ctx, "POST", "/v2/operations", r, signature, fault, &out)
	if err == nil {
		err = bankv2.VerifyResult(r, out)
	}
	return out, err
}
func v2OperationPath(namespace, user, key string) string {
	return "/v2/operations/" + url.PathEscape(namespace) + "/" + url.PathEscape(key) + "?" + url.Values{"user_id": {user}}.Encode()
}
func (c *ClientV2) Lookup(ctx context.Context, namespace, user, key string) (bankv2.Result, error) {
	var out bankv2.Result
	err := c.call(ctx, "GET", v2OperationPath(namespace, user, key), nil, "", "", &out)
	return out, err
}
func (c *ClientV2) Settle(ctx context.Context, namespace, user, key string) (bankv2.Result, error) {
	var out bankv2.Result
	path := "/v2/operations/" + url.PathEscape(namespace) + "/" + url.PathEscape(key) + "/settle?" + url.Values{"user_id": {user}}.Encode()
	err := c.call(ctx, "POST", path, nil, "", "", &out)
	return out, err
}
func (c *ClientV2) Inventory(ctx context.Context, namespace, user string, after, watermark int64, limit int) (bankv2.Inventory, error) {
	var out bankv2.Inventory
	q := url.Values{"namespace": {namespace}, "user_id": {user}, "after": {strconv.FormatInt(after, 10)}, "watermark": {strconv.FormatInt(watermark, 10)}, "limit": {strconv.Itoa(limit)}}
	err := c.call(ctx, "GET", "/v2/operations?"+q.Encode(), nil, "", "", &out)
	return out, err
}
func (c *ClientV2) CurrentState(ctx context.Context, namespace, user string) (bankv2.CurrentState, error) {
	var out bankv2.CurrentState
	err := c.call(ctx, "GET", "/v2/state?"+url.Values{"namespace": {namespace}, "user_id": {user}}.Encode(), nil, "", "", &out)
	return out, err
}
func (c *ClientV2) Quote(ctx context.Context, namespace, user, position string, kind bankv2.Kind) (bankv2.Quote, error) {
	var out bankv2.Quote
	input := map[string]any{"namespace": namespace, "user_id": user, "position_id": position, "kind": kind}
	err := c.call(ctx, "POST", "/v2/quotes", input, "", "", &out)
	return out, err
}
func (c *ClientV2) RegisterGoal(ctx context.Context, r bankv2.GoalRegistration, signature string) error {
	var out map[string]any
	if err := c.call(ctx, "POST", "/v2/goals", r, signature, "", &out); err != nil {
		return err
	}
	if out["protocol"] != bankv2.Protocol+"/zero-goal" || out["namespace"] != r.Namespace || out["user_id"] != r.UserID || out["goal_id"] != r.GoalID || out["account_id"] != r.AccountID || out["registered"] != true {
		return bankv2.ErrInvalid
	}
	return nil
}

func (c *ClientV2) Health(ctx context.Context) error {
	var out struct {
		Protocol   string `json:"protocol"`
		Simulation bool   `json:"simulation"`
		SchemaHash string `json:"schema_sha256"`
	}
	if err := c.call(ctx, "GET", "/v2/healthz", nil, "", "", &out); err != nil {
		return err
	}
	if out.Protocol != bankv2.Protocol || !out.Simulation || out.SchemaHash != frozenBankV2Migration {
		return bankv2.ErrInvalid
	}
	return nil
}

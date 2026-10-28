package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	assistant "zhiyu.local/zhiyu-go/internal/agent"
	"zhiyu.local/zhiyu-go/internal/agent/domain"
	"zhiyu.local/zhiyu-go/internal/app"
)

type AgentOptions struct {
	Provider assistant.Provider
	Limits   domain.Limits
}

func agentReader(s *app.Service) assistant.Reader {
	return assistant.ReaderFunc(func(ctx context.Context, scope domain.Scope) (domain.Snapshot, error) {
		p, ok := ctx.Value(principalKey{}).(app.Principal)
		if !ok || p.EnvironmentID != scope.EnvironmentID || p.UserID != scope.UserID {
			return domain.Snapshot{}, domain.ErrReference
		}
		return s.AgentSnapshot(ctx, p)
	})
}

func agentRoutes(r chi.Router, s *app.Service, options *AgentOptions) {
	// No provider credential is configured for this isolated runtime. The
	// offline tool path uses real scoped reads and remains available on its own.
	var provider assistant.Provider
	limits := domain.DefaultLimits()
	if options != nil {
		provider = options.Provider
		limits = options.Limits
	}
	engine, engineErr := assistant.New(agentReader(s), provider, limits)
	r.Get("/api/v2/agent/status", func(w http.ResponseWriter, req *http.Request) {
		if engineErr != nil {
			fail(w, "INTERNAL_ERROR")
			return
		}
		writeJSON(w, 200, engine.Status())
	})
	r.Post("/api/v2/agent/turn", func(w http.ResponseWriter, req *http.Request) {
		if engineErr != nil {
			fail(w, "INTERNAL_ERROR")
			return
		}
		var in domain.Turn
		if body(req, &in) != nil {
			agentFail(w, assistant.InvalidTurnFailure())
			return
		}
		p := req.Context().Value(principalKey{}).(app.Principal)
		result, err := engine.Run(req.Context(), domain.Scope{EnvironmentID: p.EnvironmentID, UserID: p.UserID}, in)
		if err != nil {
			agentFail(w, err)
			return
		}
		writeJSON(w, 200, result)
	})
}

func agentFail(w http.ResponseWriter, err error) {
	code, message, retry, status := "AGENT_UNAVAILABLE", "助手暂未完成请求，请使用页面表单继续", "USE_OFFLINE", 503
	switch {
	case errors.Is(err, domain.ErrInvalid), errors.Is(err, domain.ErrTool):
		code, message, retry, status = "AGENT_INVALID_INPUT", "工具或字段不符合当前约定", "NEVER", 400
	case errors.Is(err, domain.ErrReference), errors.Is(err, domain.ErrStale):
		code, message, retry, status = "AGENT_STALE_REFERENCE", "引用已失效或不属于当前用户，请重新读取", "AFTER_REFRESH", 409
	case errors.Is(err, domain.ErrBudget):
		code, message, retry, status = "AGENT_BUDGET_EXCEEDED", "本次助手预算已用尽，请改用结构化工具或表单", "USE_OFFLINE", 429
	case errors.Is(err, assistant.ErrProviderNotConfigured):
		code, message = "AGENT_PROVIDER_NOT_CONFIGURED", "当前未配置模型，结构化工具和页面表单仍可使用"
	case errors.Is(err, context.DeadlineExceeded):
		code, status = "AGENT_TIMEOUT", 504
	}
	writeJSON(w, status, Error{Code: code, Message: message, RequestID: w.Header().Get("X-Request-ID"), RetryClass: retry, Details: assistant.FailureDetails(err)})
}

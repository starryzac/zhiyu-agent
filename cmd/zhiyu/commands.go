package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"zhiyu.local/zhiyu-go/internal/adapters/banksim"
	"zhiyu.local/zhiyu-go/internal/adapters/postgres"
	assistant "zhiyu.local/zhiyu-go/internal/agent"
	agentdomain "zhiyu.local/zhiyu-go/internal/agent/domain"
	"zhiyu.local/zhiyu-go/internal/agent/providers/deepseek"
	"zhiyu.local/zhiyu-go/internal/app"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	"zhiyu.local/zhiyu-go/internal/platform"
	"zhiyu.local/zhiyu-go/internal/transport/httpapi"
)

type commandOptions struct {
	Command, Config, WebRoot string
	Amount                   int64
	BankFacts                string
	RecoveryRequest          string
	Once, Pause, Resume      bool
	ObserveWorkAttempts      bool
	DaemonIdleSkip           bool
}

func options(args []string) (commandOptions, error) {
	var result commandOptions
	if len(args) < 1 {
		return result, errors.New("explicit command required")
	}
	result.Command = args[0]
	switch result.Command {
	case "api", "worker", "standing", "native-standing", "projection", "audit-worker", "doctor", "migrate", "seed", "demo-income", "demo-bank-facts", "recovery-control":
	default:
		return result, errors.New("unsupported command")
	}
	f := flag.NewFlagSet("zhiyu", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&result.Config, "config", "", "explicit role runtime file")
	f.StringVar(&result.WebRoot, "web-root", "", "explicit package web directory; API only, disabled by default")
	f.Int64Var(&result.Amount, "amount-cents", 10000, "immutable first simulated income cents")
	f.StringVar(&result.BankFacts, "bank-facts", "", "explicit controlled bank catalog/liability fixture file")
	f.StringVar(&result.RecoveryRequest, "recovery-request", "", "explicit local operator recovery request file")
	f.BoolVar(&result.Once, "once", false, "run one independent standing-consumer step")
	f.BoolVar(&result.Pause, "pause", false, "pause independent standing admission")
	f.BoolVar(&result.Resume, "resume", false, "resume independent standing admission")
	f.BoolVar(&result.ObserveWorkAttempts, "observe-work-attempts", false, "operator-only fixed function attempt counters on stderr; disabled by default")
	f.BoolVar(&result.DaemonIdleSkip, "native-idle-skip", false, "operator opt-in: bounded daemon negative observation cursor; native-standing only")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 || result.Config == "" && !(result.Command == "api" && result.WebRoot != "") {
		return result, errors.New("command requires -config with an explicit role runtime file")
	}
	if result.WebRoot != "" && result.Command != "api" {
		return result, errors.New("-web-root is supported only for api")
	}
	if result.DaemonIdleSkip && result.Command != "native-standing" {
		return result, errors.New("-native-idle-skip is supported only for native-standing")
	}
	if result.ObserveWorkAttempts {
		switch result.Command {
		case "api", "worker", "standing", "native-standing", "projection", "audit-worker":
			if result.Config == "" {
				return result, errors.New("work attempt observation requires an explicit configured application command")
			}
		default:
			return result, errors.New("work attempt observation is supported only for application processes")
		}
	}
	if (result.Once && result.Command != "standing" && result.Command != "native-standing" && result.Command != "projection" && result.Command != "audit-worker") || ((result.Pause || result.Resume) && result.Command != "standing") || result.Pause && result.Resume || result.Once && (result.Pause || result.Resume) {
		return result, errors.New("invalid standing control options")
	}
	if (result.Command == "demo-bank-facts") != (result.BankFacts != "") {
		return result, errors.New("demo-bank-facts requires its explicit -bank-facts file; other commands reject it")
	}
	if (result.Command == "recovery-control") != (result.RecoveryRequest != "") {
		return result, errors.New("recovery-control requires its explicit -recovery-request file; other commands reject it")
	}
	return result, nil
}

func runConfigured(ctx context.Context, args []string, out io.Writer, logger *slog.Logger) error {
	opts, err := options(args)
	if err != nil {
		return err
	}
	if opts.Config == "" {
		return errors.New("configured API requires its explicit role runtime")
	}
	c, err := platform.LoadRuntime(opts.Config)
	if err != nil {
		return err
	}
	if opts.Command == "doctor" {
		return json.NewEncoder(out).Encode(map[string]any{"mode": "EXPLICIT_ROLE_CONFIG_ONLY_NO_IO", "environment": c.Environment, "namespace": c.Namespace, "role": c.Role, "simulation": true, "database_configured": c.AppDSN != "" || c.MigrationDSN != "", "database_verified": false, "financial_operations_enabled": false, "credentials_printed": false, "public_runtime_sha256": auditConfigurationDigest(c)})
	}
	if opts.Command == "migrate" {
		if c.Role != "migration" {
			return errors.New("migrate requires the separate schema-owner runtime")
		}
		if postgres.Migrate(ctx, c.MigrationDSN) != nil {
			return errors.New("application migration failed; configuration values omitted")
		}
		return json.NewEncoder(out).Encode(map[string]string{"status": "MIGRATED", "environment": c.Environment})
	}
	if (opts.Command == "api" || opts.Command == "worker" || opts.Command == "standing" || opts.Command == "native-standing" || opts.Command == "projection" || opts.Command == "audit-worker" || opts.Command == "recovery-control") && c.Role != "app" {
		return errors.New("api and worker require application-only runtime")
	}
	if (opts.Command == "seed" || opts.Command == "demo-income" || opts.Command == "demo-bank-facts") && c.Role != "seed" {
		return errors.New("trusted demo setup requires the separate seed runtime")
	}
	if opts.WebRoot != "" && c.WebOrigin != "http://"+c.HTTPConfig().ListenAddr {
		return errors.New("static web requires web_origin to equal the API listener origin")
	}
	store, err := postgres.New(ctx, c.AppDSN)
	if err != nil {
		return err
	}
	defer store.Close()
	// NewClient copies http.Client but retains the shared Transport identity.
	// Keep the original direct/no-proxy, five-second and no-redirect contract.
	bankHTTPClient := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	var bank app.Bank
	if c.Role == "app" {
		client, e := banksim.NewClient(c.BankURL, bankHTTPClient)
		if e != nil {
			return errors.New("bank client configuration invalid")
		}
		bank = client
	}
	service := app.New(store, c.Namespace, bank, []byte(c.BankPermitSecret))
	if c.Role == "app" {
		writerPin, e := configuredRecoveryWriter(opts.Config, c.Namespace)
		if e != nil {
			return e
		}
		service.WriterPin = writerPin
		nativeClient, e := banksim.NewClientV2(c.BankURL, bankHTTPClient)
		if e != nil {
			return errors.New("native bank client configuration invalid")
		}
		creditClient, e := banksim.NewExternalCreditClient(c.BankURL, bankHTTPClient)
		if e != nil {
			return errors.New("income inventory client configuration invalid")
		}
		service.NativeBank = nativeClient
		service.NativeIncomeSources = &app.NativeIncomeSources{Credit: creditClient, Legacy: bank.(*banksim.Client), Native: nativeClient}
		service.NativeBillSources = configuredNativeBills(opts.Config, logger)
		service.ForecastHistorySources = configuredForecastHistory(opts.Config, c.Namespace, logger)
		service.AuditTrust = configuredAudit(opts.Config, c, logger)
		if opts.DaemonIdleSkip {
			head, e := banksim.NewDaemonObservationClient(creditClient, bank.(*banksim.Client), nativeClient)
			if e == nil {
				e = service.EnableNativeDaemonIdle(head, auditConfigurationDigest(c))
			}
			if e != nil {
				logger.Info("native_idle_cursor_unavailable", "mode", "FULL_FALLBACK", "configuration_printed", false)
			}
		}
	}
	if opts.ObserveWorkAttempts {
		stopObservation := startWorkAttemptHeartbeat(logger, opts.Command)
		defer stopObservation()
	}
	switch opts.Command {
	case "recovery-control":
		return recoveryOperator(ctx, service, opts.RecoveryRequest, out)
	case "demo-bank-facts":
		return seedDemoBankFacts(ctx, service, c, opts.BankFacts, out)
	case "seed":
		state, err := readSeed(c.SeedState)
		if err != nil {
			return err
		}
		result, err := service.Bootstrap(ctx, state.SeedIdentity)
		if err != nil {
			return fmt.Errorf("seed failed (%s)", app.Code(err))
		}
		return json.NewEncoder(out).Encode(struct {
			app.BootstrapResult
			StatePath          string `json:"seed_state"`
			CredentialsPrinted bool   `json:"credentials_printed"`
		}{result, c.SeedState, false})
	case "demo-income":
		return demoIncome(ctx, service, c, opts.Amount, out)
	case "worker":
		if service.Check(ctx) != nil {
			return errors.New("worker application state unavailable; run explicit seed first")
		}
		owner, err := commandID()
		if err != nil {
			return errors.New("worker identity unavailable")
		}
		logger.Info("worker_start", "environment", c.Environment, "namespace", c.Namespace, "simulation", true)
		if err := service.RunWorker(ctx, owner.String()); err != nil {
			if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
				return nil
			}
			return errors.New("worker stopped with an application processing error")
		}
		return nil
	case "native-standing":
		if service.Check(ctx) != nil {
			return errors.New("native standing application state unavailable; run explicit seed first")
		}
		owner, err := commandID()
		if err != nil {
			return errors.New("native standing consumer identity unavailable")
		}
		if opts.Once {
			worked, err := service.NativeStandingStep(ctx, owner.String(), 30*time.Second)
			if err != nil {
				return errors.New("native standing step failed; original occurrence retained")
			}
			return json.NewEncoder(out).Encode(map[string]any{"status": "NATIVE_STANDING_STEP_COMPLETED", "worked": worked, "namespace": c.Namespace})
		}
		logger.Info("native_standing_start", "environment", c.Environment, "namespace", c.Namespace, "simulation", true)
		if service.RunNativeStanding(ctx, owner.String()) != nil {
			return errors.New("native standing stopped; original occurrence retained")
		}
		return nil
	case "standing":
		if opts.Pause || opts.Resume {
			if service.SetStandingPaused(ctx, opts.Pause) != nil {
				return errors.New("standing scheduling control update failed")
			}
			return json.NewEncoder(out).Encode(map[string]any{"status": "STANDING_SCHEDULING_UPDATED", "paused": opts.Pause, "namespace": c.Namespace})
		}
		if service.Check(ctx) != nil {
			return errors.New("standing application state unavailable; run explicit seed first")
		}
		owner, err := commandID()
		if err != nil {
			return errors.New("standing consumer identity unavailable")
		}
		if opts.Once {
			worked, err := service.StandingStep(ctx, owner.String(), 30*time.Second)
			if err != nil {
				return errors.New("standing consumer step failed; original inbox identity retained")
			}
			return json.NewEncoder(out).Encode(map[string]any{"status": "STANDING_STEP_COMPLETED", "worked": worked, "namespace": c.Namespace})
		}
		logger.Info("standing_consumer_start", "environment", c.Environment, "namespace", c.Namespace, "simulation", true)
		if service.RunStanding(ctx, owner.String()) != nil {
			return errors.New("standing consumer stopped; original inbox identity retained")
		}
		return nil
	case "projection":
		if opts.Once {
			worked, err := service.ProjectStep(ctx)
			if err != nil {
				return errors.New("projection step failed; source events and offset retained")
			}
			return json.NewEncoder(out).Encode(map[string]any{"status": "PROJECTION_STEP_COMPLETED", "worked": worked, "namespace": c.Namespace})
		}
		if service.RunProjection(ctx) != nil {
			return errors.New("projection consumer stopped; original source events retained")
		}
		return nil
	case "audit-worker":
		if service.AuditTrust.SourceManifestSHA256 == "" {
			return errors.New("audit worker requires source-pinned operator configuration")
		}
		owner, err := commandID()
		if err != nil {
			return errors.New("audit worker identity unavailable")
		}
		if opts.Once {
			worked, e := service.AuditStep(ctx, owner.String(), 30*time.Second)
			if e != nil {
				return errors.New("audit step failed; original run and capture retained")
			}
			return json.NewEncoder(out).Encode(map[string]any{"status": "AUDIT_STEP_COMPLETED", "worked": worked, "namespace": c.Namespace})
		}
		return service.RunAuditWorker(ctx, owner.String())
	case "api":
		if service.Check(ctx) != nil {
			return errors.New("application state unavailable; run explicit seed first")
		}
		config := c.HTTPConfig()
		server := httpapi.Server(config, logger)
		provider, limits := configuredAgent(opts.Config, logger, os.Getenv)
		server.Handler = httpapi.HandlerWithAgentProvider(config, logger, service, c.WebOrigin, provider, limits)
		handler, closeWeb, err := optionalStaticWeb(server.Handler, opts.WebRoot)
		if err != nil {
			return err
		}
		server.Handler = handler
		defer closeWeb()
		listener, err := net.Listen("tcp", config.ListenAddr)
		if err != nil {
			return errors.New("API loopback listener unavailable")
		}
		logger.Info("api_start", "environment", c.Environment, "namespace", c.Namespace, "listen_addr", config.ListenAddr, "simulation", true)
		return serve(ctx, server, listener)
	}
	return errors.New("unsupported runtime command")
}

// configuredAgent performs local configuration only. Optional model failures
// preserve offline assistance and never block the structured financial routes.
func configuredAgent(configPath string, logger *slog.Logger, getenv func(string) string) (assistant.Provider, agentdomain.Limits) {
	offline := agentdomain.DefaultLimits()
	absolute, err := filepath.Abs(configPath)
	if err != nil {
		logger.Warn("agent_provider_configuration", "status", "OFFLINE_CONFIG_REJECTED")
		return nil, offline
	}
	config, err := deepseek.Load(filepath.Dir(absolute), getenv)
	if err != nil {
		if errors.Is(err, deepseek.ErrNotConfigured) {
			logger.Info("agent_provider_configuration", "status", "OFFLINE_NOT_CONFIGURED")
		} else {
			logger.Warn("agent_provider_configuration", "status", "OFFLINE_CONFIG_REJECTED")
		}
		return nil, offline
	}
	provider, err := deepseek.New(config)
	if err != nil {
		logger.Warn("agent_provider_configuration", "status", "OFFLINE_CONFIG_REJECTED")
		return nil, offline
	}
	logger.Info("agent_provider_configuration", "status", "CONFIGURED_NOT_VERIFIED")
	return provider, deepseek.Limits()
}

func commandID() (funds.ID, error) {
	var id funds.ID
	_, err := rand.Read(id[:])
	id[6] = (id[6] & 15) | 64
	id[8] = (id[8] & 63) | 128
	return id, err
}

type seedState struct {
	app.SeedIdentity
	Income          *app.DemoIncomePreparation `json:"income,omitempty"`
	BankObservation *app.DemoBankFacts         `json:"bank_observation,omitempty"`
	ImportResult    *app.DemoIncomeResult      `json:"import_result,omitempty"`
}

func readSeed(path string) (seedState, error) {
	var result seedState
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 128*1024 {
		return result, errors.New("persistent demo seed state unavailable")
	}
	if json.Unmarshal(raw, &result) != nil || result.Protocol != app.DemoSeedProtocol {
		return result, errors.New("persistent demo seed state invalid; retained without replacement")
	}
	return result, nil
}

func saveSeed(path string, state seedState) error {
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return errors.New("cannot encode persistent demo state")
	}
	raw = append(raw, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(path), "demo-seed-*.tmp")
	if err != nil {
		return errors.New("cannot prepare persistent demo state")
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err = temporary.Chmod(0600); err == nil {
		_, err = temporary.Write(raw)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.New("cannot save persistent demo state")
	}
	if os.Rename(name, path) != nil {
		return errors.New("cannot atomically replace persistent demo state")
	}
	return nil
}

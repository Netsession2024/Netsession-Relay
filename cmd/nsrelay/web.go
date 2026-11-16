package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/auth"
	"github.com/Netsession2024/Netsession-Relay/internal/control"
	"github.com/Netsession2024/Netsession-Relay/internal/engineapi"
	"github.com/Netsession2024/Netsession-Relay/internal/gamedb"
	"github.com/Netsession2024/Netsession-Relay/internal/store"
	"github.com/Netsession2024/Netsession-Relay/internal/web"
)

func countLocalUsers(st *store.Store) (int, error) {
	var n int
	err := st.DB.QueryRow(`SELECT count(*) FROM user WHERE kind = 'local'`).Scan(&n)
	return n, err
}

func envInt(k string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return v
	}
	return def
}

// runWeb starts the web part: database + seed sync, admin UI (internal/web), /healthz, /api/v1/status.
func runWeb(args []string, _, stderr io.Writer) int {
	fs := newFlags("web", stderr)
	var af adminFlags
	af.register(fs)
	addr := fs.String("addr", envOr("NSRELAY_HTTP_ADDR", "127.0.0.1:8080"), "listen address (MGMT IP only)")
	demo := fs.Bool("demo", false, "development only: fake engine with invented traffic, throwaway database, accounts demo/op/view (password demo)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	if *demo {
		return runWebDemo(*addr, log)
	}
	st, err := store.Open(af.db)
	if err != nil {
		log.Error("database", "err", err)
		return 1
	}
	defer st.Close()
	if seed, err := gamedb.Seed(); err == nil {
		res, err := st.SyncSeed(context.Background(), seed)
		log.Info("seed sync", "added", res.Added, "updated", res.Updated, "pending", res.Pending, "err", err)
	}
	eng := engineapi.NewClient(af.socket)
	ui, err := web.New(st, eng, log, version)
	if err != nil {
		log.Error("web templates", "err", err)
		return 1
	}
	ui.Secure = os.Getenv("NSRELAY_COOKIE_SECURE") == "1"
	if n, _ := countLocalUsers(st); n == 0 {
		log.Warn("no local account yet: create one with `nsrelay admin set-password <name>`")
	}
	ui.SNMPAddr = os.Getenv("NSRELAY_SNMP_ADDR")
	ui.SetBindAddr(*addr)
	defer ui.CloseOutputs()
	defer ui.CloseAgent()
	go ui.WatchAlarms(context.Background(), 10*time.Second) // alarm open/clear events for the monitoring targets
	return serveWeb(*addr, ui, log, af.db)
}

// runWebDemo serves the UI with web.DemoEngine and a fresh database in a temporary directory. It never opens
// the real database or the engine socket, so it cannot change a running relay.
func runWebDemo(addr string, log *slog.Logger) int {
	dir, err := os.MkdirTemp("", "nsrelay-demo-")
	if err != nil {
		log.Error("demo", "err", err)
		return 1
	}
	defer os.RemoveAll(dir)
	st, err := store.Open(filepath.Join(dir, "demo.db"))
	if err != nil {
		log.Error("database", "err", err)
		return 1
	}
	defer st.Close()
	ctx := context.Background()
	if _, err := control.Init(ctx, st, "demo", "netsession", "ens19", false); err != nil {
		log.Error("demo init", "err", err)
		return 1
	}
	for name, role := range map[string]string{"demo": store.RoleAdmin, "op": store.RoleOperator, "view": store.RoleViewer} {
		h, _ := auth.Hash("demo")
		if err := st.SetLocalUser(ctx, "demo", name, h, role); err != nil {
			log.Error("demo account", "err", err)
			return 1
		}
	}
	eng := web.NewDemoEngine()
	if _, err := control.Apply(ctx, st, eng, "demo", "Demo-Start", false); err != nil {
		log.Error("demo apply", "err", err)
		return 1
	}
	ui, err := web.New(st, eng, log, version)
	if err != nil {
		log.Error("web templates", "err", err)
		return 1
	}
	ui.Demo = true
	log.Warn("DEMO MODE: invented data, nothing is relayed; accounts demo (admin), op (operator), view (viewer), password demo")
	return serveWeb(addr, ui, log, "demo")
}

func serveWeb(addr string, ui http.Handler, log *slog.Logger, db string) int {
	srv := &http.Server{Addr: addr, Handler: ui, ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("nsrelay web listening", "addr", addr, "version", version, "db", db)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("web stopped", "err", err)
		return 1
	}
	return 0
}

// runHealth exits 0 if the URL answers 200 (used as container health check; the image has no shell/curl).
func runHealth(args []string, _, stderr io.Writer) int {
	fs := newFlags("health", stderr)
	url := fs.String("url", "http://"+envOr("NSRELAY_HTTP_ADDR", "127.0.0.1:8080")+"/healthz", "health URL")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(*url)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(stderr, "status", resp.Status)
		return 1
	}
	return 0
}

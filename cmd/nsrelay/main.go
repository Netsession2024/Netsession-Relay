// Command nsrelay is the Netsession Relay: a UDP broadcast/multicast relay for
// LAN-party game discovery across VLANs, with a web UI.
//
// Subcommands (see docs/02-plan.md, section 3.1):
//
//	engine   packet data plane (Linux, needs CAP_NET_RAW + CAP_NET_ADMIN)
//	web      admin UI, API, SQLite
//	admin    local administration (emergency admin, revisions)
//	lab      lab helpers: snapshot, send, expect
//	import   import OPNsense config.xml exports
//	backup   backup and restore
//	version  print version information
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/Netsession2024/Netsession-Relay/internal/compile"
	"github.com/Netsession2024/Netsession-Relay/internal/engine"
	"github.com/Netsession2024/Netsession-Relay/internal/engineapi"
	"github.com/Netsession2024/Netsession-Relay/internal/gamedb"
	"github.com/Netsession2024/Netsession-Relay/internal/lab"
	"github.com/Netsession2024/Netsession-Relay/internal/snmp"
)

// Set at build time via -ldflags "-X main.version=... -X main.commit=...".
var (
	version = "dev"
	commit  = "unknown"
)

type command struct {
	name  string
	phase int // roadmap phase that implements it (docs/02-plan.md, section 11); 0 = available
	help  string
	run   func(args []string, stdout, stderr io.Writer) int
}

var commands = []command{
	{"engine", 0, "run the packet data plane from a snapshot file", runEngine},
	{"web", 0, "run the web part (phase 5: health + status API; UI follows in phase 6)", runWeb},
	{"admin", 0, "configuration: init, games, enable/disable, apply, revisions, rollback, status", runAdmin},
	{"lab", 0, "lab helpers: snapshot | send | expect", runLab},
	{"import", 0, "import opnsense <config.xml>...: report on existing OPNsense relay settings", runImport},
	{"health", 0, "check a health URL (container health checks; no curl in the image)", runHealth},
	{"backup", 0, "backup [-dir] | backup restore <file>", runBackup},
	{"snmp-mib", 0, "print NETSESSION-RELAY-MIB; -zabbix: the Zabbix SNMP template (deploy/zabbix/template_nsrelay_snmp.yaml)", runSNMPMIB},
}

func runSNMPMIB(args []string, stdout, _ io.Writer) int {
	if len(args) > 0 && args[0] == "-zabbix" {
		fmt.Fprint(stdout, snmp.ZabbixTemplate())
		return 0
	}
	fmt.Fprint(stdout, snmp.MIB())
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "version", "--version", "-version", "-v":
		fmt.Fprintf(stdout, "nsrelay %s (commit %s, %s, %s/%s)\n",
			version, commit, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return 0
	case "help", "--help", "-help", "-h":
		usage(stdout)
		return 0
	}
	for _, c := range commands {
		if c.name != args[0] {
			continue
		}
		if c.run == nil {
			fmt.Fprintf(stderr, "nsrelay %s: not implemented yet (planned for phase %d)\n", c.name, c.phase)
			return 1
		}
		return c.run(args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "nsrelay: unknown command %q\n\n", args[0])
	usage(stderr)
	return 2
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: nsrelay <command> [options]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-8s %s\n", c.name, c.help)
	}
	fmt.Fprintf(w, "  %-8s %s\n", "version", "print version information")
}

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("nsrelay "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func runEngine(args []string, _, stderr io.Writer) int {
	fs := newFlags("engine", stderr)
	path := fs.String("snapshot", envOr("NSRELAY_SNAPSHOT", "/var/lib/nsrelay/active.json"), "snapshot file (written by the web part or `nsrelay lab snapshot`)")
	socket := fs.String("socket", envOr("NSRELAY_SOCKET", engineapi.DefaultSocket), "engine API Unix socket (empty = off)")
	gid := fs.Int("socket-gid", envInt("NSRELAY_SOCKET_GID", -1), "group ID for the socket (web container user group)")
	debug := fs.Bool("debug", false, "debug logging")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	log.Info("nsrelay engine starting", "version", version, "commit", commit, "snapshot", *path)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	e := &engine.Engine{Path: *path, Socket: *socket, SocketGID: *gid, Version: version, Log: log}
	if err := e.Run(ctx); err != nil {
		log.Error("engine stopped", "err", err)
		return 1
	}
	return 0
}

func runLab(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: nsrelay lab snapshot|send|expect [options]")
		return 2
	}
	switch args[0] {
	case "snapshot":
		return labSnapshot(args[1:], stdout, stderr)
	case "send":
		return labSend(args[1:], stderr)
	case "expect":
		return labExpect(args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "nsrelay lab: unknown subcommand %q\n", args[0])
	return 2
}

func labSnapshot(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("lab snapshot", stderr)
	out := fs.String("out", "", "write snapshot to this file (default: stdout summary only)")
	parent := fs.String("parent", "trunk0", "trunk interface")
	mode := fs.String("mode", compile.ModeActive, "engine mode: active|observe|paused")
	relayHost := fs.Int("relay-host", 55, "host part of the relay IP in every lab VLAN")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	s, warns, err := lab.Snapshot(*parent, *mode, *relayHost)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if *out != "" {
		if err := compile.WriteSnapshotFile(*out, s); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	fmt.Fprintf(stdout, "lab snapshot %s: %d VLANs, %d rules, %d warnings\n", s.Hash[:12], len(s.VLANs), len(s.Rules), len(warns))
	return 0
}

func addr(fs *flag.FlagSet, name, usage string) *string { return fs.String(name, "", usage) }

func parseOptAddr(s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, nil
	}
	return netip.ParseAddr(s)
}

func labSend(args []string, stderr io.Writer) int {
	fs := newFlags("lab send", stderr)
	iface := fs.String("iface", "eth0", "interface")
	src := addr(fs, "src", "source IP (may be spoofed)")
	dst := addr(fs, "dst", "destination IP (255.255.255.255, subnet broadcast or multicast group)")
	sport := fs.Uint("sport", 50000, "source port")
	dport := fs.Uint("dport", 0, "destination port")
	payload := fs.String("payload", "", "payload text")
	payloadHex := fs.String("payload-hex", "", "payload as hex (overrides -payload)")
	size := fs.Int("size", 0, "payload of N zero bytes (overrides -payload)")
	count := fs.Int("count", 1, "number of frames")
	interval := fs.Int("interval", 0, "milliseconds between frames")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	o := lab.SendOptions{Iface: *iface, SrcPort: uint16(*sport), DstPort: uint16(*dport), Payload: []byte(*payload),
		Count: *count, Interval: *interval}
	var err error
	if o.Src, err = netip.ParseAddr(*src); err != nil {
		fmt.Fprintln(stderr, "-src:", err)
		return 2
	}
	if o.Dst, err = netip.ParseAddr(*dst); err != nil {
		fmt.Fprintln(stderr, "-dst:", err)
		return 2
	}
	if *payloadHex != "" {
		if o.Payload, err = hex.DecodeString(*payloadHex); err != nil {
			fmt.Fprintln(stderr, "-payload-hex:", err)
			return 2
		}
	}
	if *size > 0 {
		o.Payload = make([]byte, *size)
	}
	if err := lab.Send(o); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func labExpect(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("lab expect", stderr)
	iface := fs.String("iface", "eth0", "interface")
	dport := fs.Uint("dport", 0, "destination port")
	src := addr(fs, "src", "only frames from this source IP")
	dst := addr(fs, "dst", "only frames to this destination IP")
	count := fs.Int("count", 1, "frames needed")
	maxN := fs.Int("max", 0, "collect until timeout; succeed if count..max frames arrived")
	none := fs.Bool("none", false, "succeed only if nothing arrives")
	timeout := fs.Int("timeout", 1500, "timeout in milliseconds")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	o := lab.ExpectOptions{Iface: *iface, DstPort: uint16(*dport), Count: *count, Max: *maxN, None: *none, Timeout: *timeout}
	var err error
	if o.Src, err = parseOptAddr(*src); err != nil {
		fmt.Fprintln(stderr, "-src:", err)
		return 2
	}
	if o.Dst, err = parseOptAddr(*dst); err != nil {
		fmt.Fprintln(stderr, "-dst:", err)
		return 2
	}
	got, err := lab.Expect(o)
	for _, f := range got {
		fmt.Fprintf(stdout, "%s:%d -> %s:%d len=%d ttl=%d srcmac=%s\n", f.Src, f.SrcPort, f.Dst, f.DstPort, len(f.Payload), f.TTL, f.SrcMAC)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func gameSeed() (*gamedb.DB, error) { return gamedb.Seed() }

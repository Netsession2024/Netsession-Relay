package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/auth"
	"github.com/Netsession2024/Netsession-Relay/internal/control"
	"github.com/Netsession2024/Netsession-Relay/internal/engineapi"
	"github.com/Netsession2024/Netsession-Relay/internal/store"

	"gopkg.in/yaml.v3"
)

const defaultDB = "/var/lib/nsrelay-web/nsrelay.db"

// common flags of admin/backup subcommands
type adminFlags struct {
	db, socket, user string
}

func (a *adminFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&a.db, "db", envOr("NSRELAY_DB", defaultDB), "SQLite database")
	fs.StringVar(&a.socket, "socket", envOr("NSRELAY_SOCKET", engineapi.DefaultSocket), "engine API socket")
	fs.StringVar(&a.user, "user", defaultUser(), "user name for audit log and revisions")
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func defaultUser() string {
	if u, err := user.Current(); err == nil {
		return "cli:" + u.Username
	}
	return "cli"
}

const adminUsage = `usage: nsrelay admin <command> [flags]

  init -preset netsession|lab [-parent trunk0] [-force]   create configuration (seed games + preset)
  status                                                  engine status (via socket)
  games [-enabled]                                        list games
  enable <game-id>...  /  disable <game-id>...            switch games in the active event
  vlans                                                   list VLANs
  mode active|observe|paused                              engine mode for the next apply
  apply [-note text] [-dry-run]                           compile and send to the engine (new revision)
  revisions                                               list revisions
  rollback <revision-id>                                  restore and apply an earlier revision
  audit                                                   audit log
  export [file]                                           configuration of the active event as YAML (stdout or file)
  import <file>                                           replace VLANs, profiles and event games from a YAML export; then apply
  set-password <name> [-role admin|operator|viewer]       local account (emergency login); prints a new password once
  seed                                                    sync games.yaml into the database
  finder-start [-vlans 1101,1102] [-src IP] [-seconds 300] port finder session (via socket)
  finder                                                  port finder results
  finder-stop                                             end the session early
  finder-pcap <file>                                      capture of the last session (Wireshark)

common flags: -db (env NSRELAY_DB), -socket (env NSRELAY_SOCKET), -user`

func runAdmin(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, adminUsage)
		return 2
	}
	cmd, args := args[0], args[1:]
	fs := newFlags("admin "+cmd, stderr)
	var af adminFlags
	af.register(fs)
	preset := fs.String("preset", "netsession", "init: preset")
	parent := fs.String("parent", "trunk0", "init: trunk interface")
	force := fs.Bool("force", false, "init: replace an existing configuration")
	onlyEnabled := fs.Bool("enabled", false, "games: only enabled")
	note := fs.String("note", "", "apply: note for the revision")
	dry := fs.Bool("dry-run", false, "apply: only compile and show warnings")
	role := fs.String("role", "admin", "set-password: role of the account")
	fVLANs := fs.String("vlans", "", "finder-start: VLAN IDs, comma separated (empty: all)")
	fSrc := fs.String("src", "", "finder-start: only this sender")
	fSecs := fs.Int("seconds", 300, "finder-start: session length (max 600)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if cmd == "status" {
		return adminStatus(ctx, af, stdout, stderr)
	}
	if strings.HasPrefix(cmd, "finder") {
		req := engineapi.FinderStart{Src: *fSrc, Seconds: *fSecs}
		for _, x := range strings.Split(*fVLANs, ",") {
			if id, err := strconv.Atoi(strings.TrimSpace(x)); err == nil {
				req.VIDs = append(req.VIDs, id)
			}
		}
		return adminFinder(ctx, af, cmd, req, fs.Arg(0), stdout, stderr)
	}
	st, err := store.Open(af.db)
	if err != nil {
		fmt.Fprintln(stderr, "database:", err)
		return 1
	}
	defer st.Close()
	eng := engineapi.NewClient(af.socket)
	fail := func(err error) int { fmt.Fprintln(stderr, err); return 1 }

	switch cmd {
	case "init":
		res, err := control.Init(ctx, st, af.user, *preset, *parent, *force)
		if err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "initialised with preset %s: %d games added; run `nsrelay admin apply`\n", *preset, res.Added)
	case "seed":
		seed, err := gameSeed()
		if err != nil {
			return fail(err)
		}
		res, err := st.SyncSeed(ctx, seed)
		if err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "seed: %d added, %d updated, %d locally modified (seed differs)\n", res.Added, res.Updated, res.Pending)
	case "games":
		games, err := st.Games(ctx)
		if err != nil {
			return fail(err)
		}
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ON\tID\tNAME\tRELAY\tCONF\tPORTS")
		for _, g := range games {
			if *onlyEnabled && !g.Enabled {
				continue
			}
			var ports []string
			for _, d := range g.Discovery {
				p := d.Ports
				if d.Group != "" {
					p = d.Group + ":" + p
				}
				ports = append(ports, p)
			}
			on := ""
			if g.Enabled {
				on = "x"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", on, g.ID, g.Name, g.RelayNeeded, g.Confidence, strings.Join(ports, " "))
		}
		tw.Flush()
	case "enable", "disable":
		if fs.NArg() == 0 {
			return fail(fmt.Errorf("admin %s: game id missing", cmd))
		}
		for _, id := range fs.Args() {
			if err := st.SetGameEnabled(ctx, af.user, id, cmd == "enable"); err != nil {
				return fail(err)
			}
		}
		fmt.Fprintf(stdout, "%sd: %s (takes effect with `nsrelay admin apply`)\n", cmd, strings.Join(fs.Args(), ", "))
	case "vlans":
		c, err := st.ExportConfig(ctx)
		if err != nil {
			return fail(err)
		}
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ON\tVID\tNAME\tGROUP\tNETWORK\tRELAY IP\tINTERFACE")
		for _, v := range c.VLANs {
			on, ifn := "", v.Device
			if v.Enabled {
				on = "x"
			}
			if v.Attach == "trunk" {
				ifn = fmt.Sprintf("%s.%d", v.Parent, v.VID)
			}
			fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\t%s\n", on, v.VID, v.Name, v.Group, v.CIDR, v.RelayIP, ifn)
		}
		tw.Flush()
	case "mode":
		if fs.NArg() != 1 {
			return fail(fmt.Errorf("admin mode: active|observe|paused"))
		}
		if err := st.SetMode(ctx, af.user, fs.Arg(0)); err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "mode %s (takes effect with `nsrelay admin apply`)\n", fs.Arg(0))
	case "apply":
		res, err := control.Apply(ctx, st, eng, af.user, *note, *dry)
		for _, w := range res.Warnings {
			if w.Code != "shared_port" {
				fmt.Fprintln(stdout, "warning:", w)
			}
		}
		if err != nil {
			return fail(err)
		}
		if *dry {
			fmt.Fprintf(stdout, "dry run: %d VLANs, %d rules, hash %s\n", len(res.Snapshot.VLANs), len(res.Snapshot.Rules), res.Snapshot.Hash[:12])
		} else {
			fmt.Fprintf(stdout, "applied revision %d: %d VLANs, %d rules, hash %s\n", res.Revision, len(res.Snapshot.VLANs), len(res.Snapshot.Rules), res.Snapshot.Hash[:12])
		}
	case "revisions":
		revs, err := st.Revisions(ctx, 30)
		if err != nil {
			return fail(err)
		}
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tTIME\tUSER\tOK\tHASH\tNOTE")
		for _, r := range revs {
			ok := "yes"
			if !r.AppliedOK {
				ok = "NO: " + r.EngineMessage
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.TS[:19], r.User, ok, r.Hash[:12], r.Note)
		}
		tw.Flush()
	case "rollback":
		id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
		if err != nil {
			return fail(fmt.Errorf("admin rollback <revision-id>"))
		}
		res, err := control.Rollback(ctx, st, eng, af.user, id)
		if err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "rolled back to revision %d as new revision %d (hash %s)\n", id, res.Revision, res.Snapshot.Hash[:12])
	case "set-password":
		if fs.NArg() != 1 {
			return fail(fmt.Errorf("admin set-password <name>"))
		}
		pw := auth.Password()
		hash, err := auth.Hash(pw)
		if err != nil {
			return fail(err)
		}
		if err := st.SetLocalUser(ctx, af.user, fs.Arg(0), hash, *role); err != nil {
			return fail(err)
		}
		fmt.Fprintln(stdout, fmt.Sprintf("account %q (%s) - password (shown only now):", fs.Arg(0), *role), pw)
	case "audit":
		log, err := st.AuditLog(ctx, 50)
		if err != nil {
			return fail(err)
		}
		for _, e := range log {
			fmt.Fprintf(stdout, "%s  %-18s %-16s %s\n", e.TS[:19], e.User, e.Action, e.Object)
		}
	case "export":
		c, err := st.ExportConfig(ctx)
		if err != nil {
			return fail(err)
		}
		b, err := yaml.Marshal(c)
		if err != nil {
			return fail(err)
		}
		if fs.NArg() == 0 {
			_, _ = stdout.Write(b)
			break
		}
		if err := os.WriteFile(fs.Arg(0), b, 0o600); err != nil {
			return fail(err)
		}
		fmt.Fprintln(stdout, "written:", fs.Arg(0))
	case "import":
		if fs.NArg() != 1 {
			return fail(fmt.Errorf("admin import: file missing"))
		}
		b, err := os.ReadFile(fs.Arg(0))
		if err != nil {
			return fail(err)
		}
		var c store.Config
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true)
		if err := dec.Decode(&c); err != nil {
			return fail(fmt.Errorf("admin import: %w", err))
		}
		if c.Event == "" || len(c.VLANs) == 0 {
			return fail(fmt.Errorf("admin import: no event or no VLANs in %s", fs.Arg(0)))
		}
		if err := st.ImportConfig(ctx, af.user, c); err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "imported event %q (%d VLANs, %d profiles, %d games); run `nsrelay admin apply`\n", c.Event, len(c.VLANs), len(c.Profiles), len(c.Games))
	default:
		fmt.Fprintln(stderr, adminUsage)
		return 2
	}
	return 0
}

func adminStatus(ctx context.Context, af adminFlags, stdout, stderr io.Writer) int {
	st, err := engineapi.NewClient(af.socket).Status(ctx)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "engine %s, started %s\n", st.Version, st.Started.Format(time.RFC3339))
	fmt.Fprintf(stdout, "mode %s, sending %v, standby %v, snapshot %s, %d VLANs, %d rules\n",
		cmpStr(st.Mode, "(none)"), st.Sending, st.Standby, shortHash(st.SnapshotHash), st.VLANs, st.Rules)
	fmt.Fprintf(stdout, "rx %d, sent %d, reasons %v\n", st.RX, st.Sent, st.Reasons)
	for _, a := range st.Alarms {
		fmt.Fprintf(stdout, "ALARM %s %s x%d: %s\n", a.Kind, a.Key, a.Count, a.Detail)
	}
	for _, p := range st.TopUnknown {
		fmt.Fprintf(stdout, "unknown broadcast port %d: %d\n", p.Port, p.Count)
	}
	for _, f := range st.SelfTest {
		fmt.Fprintln(stdout, "self-test:", f)
	}
	return 0
}

func cmpStr(a, b string) string {
	if a == "" {
		return b
	}
	return a
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return cmpStr(h, "-")
}

func runBackup(args []string, stdout, stderr io.Writer) int {
	restore := len(args) > 0 && args[0] == "restore"
	if restore {
		args = args[1:]
	}
	fs := newFlags("backup", stderr)
	var af adminFlags
	af.register(fs)
	dir := fs.String("dir", envOr("NSRELAY_BACKUP_DIR", "/backups"), "backup directory")
	keep := fs.Int("keep", 14, "number of backups to keep")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if restore {
		if fs.NArg() != 1 {
			fmt.Fprintln(stderr, "usage: nsrelay backup restore [-db path] <backup.db>   (stop the web part first)")
			return 2
		}
		old, err := control.Restore(af.db, fs.Arg(0))
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stdout, "restored %s into %s (previous database kept as %s); run `nsrelay admin apply`\n", fs.Arg(0), af.db, cmpStr(old, "-"))
		return 0
	}
	st, err := store.Open(af.db)
	if err != nil {
		fmt.Fprintln(stderr, "database:", err)
		return 1
	}
	defer st.Close()
	path, err := control.Backup(context.Background(), st, *dir, *keep)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, "backup written:", path)
	return 0
}

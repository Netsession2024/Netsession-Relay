# Changelog

All notable changes to the public Netsession Relay. Versions follow [Semantic Versioning](https://semver.org/);
before 1.0 minor versions may change behaviour.

## [0.3.0] – 2026-11-17

### Monitoring
- **Several syslog targets** (UDP/TCP/TLS, RFC 5424/3164), **OpenTelemetry** export (OTLP gRPC/HTTP, metrics and
  logs, without the OTel SDK), **SNMP traps/informs** (v2c/v3) and a read-only **SNMP agent** (v3/v2c) with
  `NETSESSION-RELAY-MIB`. Alarms are sent when they open and when they clear, plus `engine_down`.
- New page System → Monitoring; Zabbix template item and trigger for failing targets; a second Zabbix template
  for SNMP (`deploy/zabbix/template_nsrelay_snmp.yaml`).

### Web UI
- **Finer, quieter design**: smaller type and headings, fewer uppercase labels, buttons without glow.
- **Service hosts** (admin): mark addresses that query games without playing (e.g. a Discord game server
  notifier); the players page lists them separately. An address seen in 3 or more games is suggested.
- **Redesign** after a review of the rendered pages: no coloured edge stripes, alarms and network tiles link to each
  other, games list with views (on / off / all) and groups, players grouped by game, tables become cards on phones.
- **Games in the UI** (operator): create, edit (several discovery rows) and delete own games; the port finder uses
  the same form. Edited seed games are kept on seed sync.
- **Flow profiles in the UI** (admin): edit the matrix, create, rename, delete, set default, pick a profile per game.
- **Emergency stop release** by operators: restores the mode that was set before the stop.
- **Verifications** per game ("tested at event X": works / partial / fails) and **YAML exports** in the seed format
  (one game, all checked or changed games) plus the configuration (`nsrelay admin export|import`).
- **Syslog** (UDP, RFC 5424): audit entries and newly opened alarms.
- **Networks in the UI** (admin): add, edit and delete VLANs on the Netz page. The whole configuration is
  compiled before anything is stored (overlaps, relay IP inside the network), then applied right away; the engine
  creates or removes the VLAN interface.

## [0.2.0] – 2026-11-16

### Web UI
- **Players page** ("Wer spielt was"): who searched for or hosted which game in the last 15 minutes, with network,
  address and role (hosts / searches / active), refreshed every 5 seconds.
- **Acknowledge alarms** ("Gesehen", operator and up): acknowledged alarms move to a "seen, still running" list
  and stop counting; after 60 quiet seconds a new incident opens again. Audited.

- **Port finder** (operator): sniffer sessions per VLAN and sender (up to 10 minutes) show every broadcast and
  multicast destination with count, interval, size, senders, first bytes and "new since start"; known noise can be
  hidden; unknown ports become a game with one click (`origin: sniffer`, `confidence: low`, optionally switched on);
  capture download as `.pcap`. Also `nsrelay admin finder-start | finder | finder-stop | finder-pcap`.
- "Unknown ports since engine start" names games of the database that use the port but are switched off.

### Monitoring
- `GET /api/v1/monitoring` (JSON for Zabbix) and `GET /metrics` (Prometheus text format), protected by a bearer
  token that an admin creates on the System page (shown once, stored as SHA-256).
- New alarm `vlan_silent`: no broadcast on a VLAN for 10 minutes during an active event in mode `active`.
  The engine status now has `last_in` per VLAN.
- Zabbix template `deploy/zabbix/template_nsrelay.yaml` (items, VLAN discovery, triggers for every alarm) and its
  generator `tools/gen_zabbix_template.py`. A test checks every JSONPath of the template against the report.

### Project
- GitHub Actions updated (checkout, setup-go, Docker actions).

## [0.1.0] – 2026-11-16

First public preview. Running at Netsession in observe mode next to the previous OPNsense relays.

### Engine
- One process relays broadcast and multicast discovery for all ports and VLANs (AF_PACKET, kernel BPF filter),
  ~0.2 µs per frame.
- Original sender IP kept by default; per-rule destination mode (`keep`, `subnet`, `limited`) and TTL mode.
- Loop and storm protection: source-subnet check with *foreign relay* alarm, dedup across VLANs, token buckets per
  game/source and per VLAN, storm brake, dual-active guard with beacons and start holdoff.
- IGMP group membership per VLAN for multicast games.
- VLAN subinterfaces created and removed via netlink; starts from the last snapshot without the web part.
- Modes: active, observe, paused, standby.

### Game database
- 149 games and services, 65 enabled by default; FlatOut 1/2 first. Verified against source code, protocol
  specifications and LAN-party port lists; confidence and source-IP requirement per game.

### Web UI
- Live overview (server-sent events), games on/off with search and filters, per-game diagnosis
  ("will it be found?"), networks and matrix, history with rollback, system page, emergency stop.
- Local accounts with Argon2id, lockout, roles viewer/operator/admin, CSRF, strict CSP; WCAG 2.2 AA target.
- Demo mode (`nsrelay web -demo`).

### Tools
- `nsrelay admin …` command line, `nsrelay backup` / `backup restore`.
- `nsrelay import opnsense` report for migrating from OPNsense `udpbroadcastrelay`.
- Network-namespace lab with 30 end-to-end cases, Docker image, host hardening script, systemd units.

[0.2.0]: https://github.com/Netsession2024/Netsession-Relay/releases/tag/v0.2.0
[0.1.0]: https://github.com/Netsession2024/Netsession-Relay/releases/tag/v0.1.0

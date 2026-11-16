# Changelog

All notable changes to the public Netsession Relay. Versions follow [Semantic Versioning](https://semver.org/);
before 1.0 minor versions may change behaviour.

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

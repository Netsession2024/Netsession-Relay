#!/bin/sh
# One-time (idempotent) host preparation of the relay VM (docs/02-plan.md 4.1/4.2, docs/betrieb.md).
# Run as root:  sh deploy/host/setup.sh <trunk-interface> [mgmt-interface]     e.g. ens19 eth0
#
# - sysctls: no routing, sane ARP on multi-VLAN hosts, IPv6 off for new (VLAN) interfaces
# - Docker daemon hardening: no ip-forward, no iptables, no default bridge (host networking only)
# - nftables: game VLANs may only reach the relay with ICMP echo and IGMP; nothing is forwarded
# - trunk interface up without address; /srv/nsrelay with backups/ owned by the web user (10001)
# - nightly configuration backup (systemd timer)
set -eu
TRUNK="${1:?usage: setup.sh <trunk-interface> [mgmt-interface]}"
MGMT="${2:-}"
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
say() { printf '==> %s\n' "$*"; }
HERE=$(cd "$(dirname "$0")" && pwd)

say "sysctl"
cat > /etc/sysctl.d/90-nsrelay.conf <<EOF
# Netsession Relay: the VM must never route between game VLANs
net.ipv4.ip_forward = 0
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
# interfaces created later (VLAN subinterfaces of the engine) start without IPv6
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.${TRUNK}.disable_ipv6 = 1
# more IGMP memberships per socket (one socket per VLAN, a few groups each)
net.ipv4.igmp_max_memberships = 64
# the SNMP agent of the web part (uid 10001, no capabilities) binds UDP 161 on the MGMT address
net.ipv4.ip_unprivileged_port_start = 161
EOF
sysctl -q --system

say "Docker daemon hardening (merged into an existing daemon.json)"
mkdir -p /etc/docker
[ -f /etc/docker/daemon.json ] && cp -n /etc/docker/daemon.json /etc/docker/daemon.json.before-nsrelay
python3 - <<'PY'
import json, os
p = "/etc/docker/daemon.json"
cfg = json.load(open(p)) if os.path.exists(p) and os.path.getsize(p) else {}
cfg.update({
    "ip-forward": False, "iptables": False, "ip6tables": False, "bridge": "none",
    "log-driver": "json-file", "log-opts": {"max-size": "10m", "max-file": "3"},
})
# Docker 29: keep overlay2; the containerd snapshotter lost containers after reboots on the Screens VM
cfg.setdefault("features", {})["containerd-snapshotter"] = False
json.dump(cfg, open(p, "w"), indent=2)
PY
systemctl restart docker
sysctl -q -w net.ipv4.ip_forward=0

say "trunk interface $TRUNK (no address, up)"
ip link set "$TRUNK" up
if [ -d /etc/network/interfaces.d ] && ! grep -qs "$TRUNK" /etc/network/interfaces /etc/network/interfaces.d/* 2>/dev/null; then
    printf 'auto %s\niface %s inet manual\n' "$TRUNK" "$TRUNK" > /etc/network/interfaces.d/nsrelay-trunk
fi

say "nftables"
command -v nft >/dev/null || { apt-get update -qq && apt-get install -y -qq nftables >/dev/null; }
cat > /etc/nftables.d-nsrelay.nft <<EOF
# Netsession Relay host filter (the relay itself uses AF_PACKET before netfilter and is not affected)
table inet nsrelay {
    chain input {
        type filter hook input priority 0; policy accept;
        iifname "${TRUNK}.*" icmp type echo-request accept
        iifname "${TRUNK}.*" ip protocol igmp accept
        iifname "${TRUNK}.*" ct state established,related accept
        iifname "${TRUNK}.*" drop
        iifname "${TRUNK}" drop
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
}
EOF
nft list table inet nsrelay >/dev/null 2>&1 && nft delete table inet nsrelay
nft -f /etc/nftables.d-nsrelay.nft
if ! grep -qs nftables.d-nsrelay /etc/nftables.conf; then
    printf '\ninclude "/etc/nftables.d-nsrelay.nft"\n' >> /etc/nftables.conf
fi
systemctl enable -q nftables

say "/srv/nsrelay"
mkdir -p /srv/nsrelay/backups
chown 10001:10001 /srv/nsrelay/backups
if id deploy >/dev/null 2>&1; then chown deploy:deploy /srv/nsrelay; fi

say "nightly backup timer"
install -m 0644 "$HERE/nsrelay-backup.service" /etc/systemd/system/nsrelay-backup.service
install -m 0644 "$HERE/nsrelay-backup.timer" /etc/systemd/system/nsrelay-backup.timer
systemctl daemon-reload
systemctl enable -q --now nsrelay-backup.timer

say "done. Check: sysctl net.ipv4.ip_forward (0), nft list table inet nsrelay, systemctl list-timers nsrelay-backup"
[ -n "$MGMT" ] && say "MGMT interface: $MGMT (SSH, web :8080 and Zabbix only there)"
exit 0

#!/bin/bash
# Mandatory lab cases (docs/02-plan.md 8.2, phase 2 acceptance). Expects up.sh to have run and the
# engine to be running in ns "relay". Usage: test.sh <path-to-nsrelay>
set -uo pipefail
NS=${1:-nsrelay}
fail=0
pass=0

nsx() { local ns=$1; shift; ip netns exec "$ns" "$NS" "$@"; }

# case NAME SENDER SEND-ARGS -- EXPECTATION...
# each expectation: "<ns> <expect-args>" run in background before sending
run_case() {
  local name=$1 sender=$2 send=$3; shift 3
  local pids=() logs=()
  for exp in "$@"; do
    local ns=${exp%% *} args=${exp#* }
    local log; log=$(mktemp)
    # shellcheck disable=SC2086
    nsx "$ns" lab expect -iface eth0 $args >"$log" 2>&1 &
    pids+=($!); logs+=("$ns: $log")
  done
  sleep 0.3
  # shellcheck disable=SC2086
  nsx "$sender" lab send -iface eth0 $send
  local ok=1 i=0
  for pid in "${pids[@]}"; do
    if ! wait "$pid"; then ok=0; echo "    ${logs[$i]%%:*}: $(cat "${logs[$i]#*: }")"; fi
    i=$((i+1))
  done
  if [ $ok = 1 ]; then echo "PASS  $name"; pass=$((pass+1)); else echo "FAIL  $name"; fail=$((fail+1)); fi
}

# 1. FlatOut query from t1 reaches t2, t3, gs with original source; never back into t1
run_case "FlatOut-Anfrage t1 -> t2,t3,gs (Original-IP, nicht zurück nach t1)" t1 \
  "-src 10.10.1.10 -dst 255.255.255.255 -sport 50000 -dport 23757 -payload FO2-query" \
  "t2 -dport 23757 -src 10.10.1.10 -dst 255.255.255.255" \
  "t3 -dport 23757 -src 10.10.1.10 -dst 255.255.255.255" \
  "gs -dport 23757 -src 10.10.1.10 -dst 255.255.255.255" \
  "t1 -dport 23757 -src 10.10.1.10 -none -timeout 800"

# 2. FlatOut answer (106 bytes, subnet broadcast) from t2 reaches t1 as t1's subnet broadcast
run_case "FlatOut-Antwort t2 -> t1 (Subnetz-Broadcast umgeschrieben)" t2 \
  "-src 10.10.2.10 -dst 10.10.2.255 -sport 23757 -dport 23757 -size 106" \
  "t1 -dport 23757 -src 10.10.2.10 -dst 10.10.1.255"

# 3. Source engine query to 255.255.255.255:27015 keeps the limited broadcast (dst_mode keep)
run_case "Source-Anfrage t3 -> gs (255.255.255.255 bleibt)" t3 \
  "-src 10.10.3.10 -dst 255.255.255.255 -sport 27005 -dport 27015 -payload-hex ffffffff54536f7572636520456e67696e6520517565727900" \
  "gs -dport 27015 -src 10.10.3.10 -dst 255.255.255.255"

# 4. DHCP discover is never relayed
run_case "DHCP-Discover wird nie weitergeleitet" t1 \
  "-src 0.0.0.0 -dst 255.255.255.255 -sport 68 -dport 67 -size 300" \
  "t2 -dport 67 -none -timeout 800" \
  "gs -dport 67 -none -timeout 800"

# 5. Source IP from another VLAN's network (another relay) is dropped
run_case "Fremde Quell-IP (anderes Relay) wird verworfen" t1 \
  "-src 10.10.2.99 -dst 255.255.255.255 -sport 50000 -dport 23757 -payload foreign" \
  "t3 -dport 23757 -src 10.10.2.99 -none -timeout 800" \
  "gs -dport 23757 -src 10.10.2.99 -none -timeout 800"

# 6. Minecraft Java LAN beacon (multicast 224.0.2.60:4445)
run_case "Minecraft-Multicast t1 -> t2" t1 \
  "-src 10.10.1.10 -dst 224.0.2.60 -sport 4445 -dport 4445 -payload [MOTD]lab[/MOTD][AD]25565[/AD]" \
  "t2 -dport 4445 -src 10.10.1.10 -dst 224.0.2.60"

# 7. Port without rule is not relayed
run_case "Unbekannter Port wird nicht weitergeleitet" t1 \
  "-src 10.10.1.10 -dst 255.255.255.255 -sport 1234 -dport 4711 -payload x" \
  "t2 -dport 4711 -none -timeout 800"

# ---- phase 3: protection ----
SNAP=${SNAP:-/tmp/nsrelay/active.json}
ENGINE_PID=${ENGINE_PID:-}

# 8. Rate limit: 200 frames at once from one source -> at most burst (10) per target
run_case "Rate-Limit: 200 Pakete auf einmal -> höchstens 10 kommen an" t1   "-src 10.10.1.10 -dst 255.255.255.255 -sport 50001 -dport 27015 -size 40 -count 200"   "t2 -dport 27015 -src 10.10.1.10 -max 10 -timeout 1500"

# 9. IGMP: the relay joined the Minecraft group on every VLAN interface (IGMP snooping lets it through)
if ip -n relay maddr show dev trunk0.1102 | grep -q 224.0.2.60; then
  echo "PASS  IGMP-Mitgliedschaft 224.0.2.60 auf trunk0.1102"; pass=$((pass+1))
else
  echo "FAIL  IGMP-Mitgliedschaft 224.0.2.60 fehlt"; ip -n relay maddr show dev trunk0.1102; fail=$((fail+1))
fi

if [ -n "$ENGINE_PID" ]; then
  # 10. observe mode via snapshot reload: counted, nothing sent
  ip netns exec relay "$NS" lab snapshot -out "$SNAP" -mode observe >/dev/null
  kill -HUP "$ENGINE_PID"; sleep 0.5
  run_case "Betriebsart observe: nichts verlässt das Relay" t1     "-src 10.10.1.10 -dst 255.255.255.255 -sport 50002 -dport 23757 -payload observe"     "t2 -dport 23757 -src 10.10.1.10 -none -timeout 800"
  ip netns exec relay "$NS" lab snapshot -out "$SNAP" -mode active >/dev/null
  kill -HUP "$ENGINE_PID"; sleep 0.5

  # 11. snapshot change under load: 15 frames over ~3 s (within the rate), reload in the middle, all arrive
  ( sleep 1.2; kill -HUP "$ENGINE_PID" ) &
  run_case "Snapshot-Wechsel unter Last: keine Verluste" t3     "-src 10.10.3.10 -dst 255.255.255.255 -sport 50003 -dport 23757 -payload load -count 15 -interval 200"     "t1 -dport 23757 -src 10.10.3.10 -count 15 -timeout 5000"
  wait

  # 12. second engine (cloned VM): the later one goes to standby, no frame arrives twice
  ip netns exec relay2 "$NS" lab snapshot -out /tmp/nsrelay/relay2.json -relay-host 56 >/dev/null
  ip netns exec relay2 "$NS" engine -snapshot /tmp/nsrelay/relay2.json -socket "" >/tmp/nsrelay/engine2.log 2>&1 &
  echo $! > /tmp/nsrelay/engine2.pid
  sleep 3
  run_case "Zweite Engine: geht in standby, kein Paket doppelt" t1     "-src 10.10.1.10 -dst 255.255.255.255 -sport 50004 -dport 23757 -payload dual"     "t2 -dport 23757 -src 10.10.1.10 -count 1 -max 1 -timeout 1500"     "gs -dport 23757 -src 10.10.1.10 -count 1 -max 1 -timeout 1500"
  if grep -q STANDBY /tmp/nsrelay/engine2.log; then
    echo "PASS  Engine 2 meldet STANDBY"; pass=$((pass+1))
  else
    echo "FAIL  Engine 2 meldet kein STANDBY"; fail=$((fail+1))
  fi
  kill -TERM "$(cat /tmp/nsrelay/engine2.pid)"; rm -f /tmp/nsrelay/engine2.pid; sleep 0.5

  # ---- phase 4: control plane (store, engine API, revisions, rollback, backup) ----
  export NSRELAY_DB=/tmp/nsrelay/relay.db NSRELAY_SOCKET=/tmp/nsrelay/engine.sock
  check() { # name command...
    local name=$1; shift
    if out=$("$@" 2>&1); then echo "PASS  $name"; pass=$((pass+1)); else echo "FAIL  $name"; echo "$out" | sed 's/^/    /'; fail=$((fail+1)); fi
  }
  flatout() { # expectation for t2: "" (arrives) or "-none"
    run_case "$1" t1 "-src 10.10.1.10 -dst 255.255.255.255 -sport $2 -dport 23757 -payload p4"       "t2 -dport 23757 -src 10.10.1.10 $3 -timeout 1000"
  }
  check "admin init -preset lab" "$NS" admin init -preset lab -parent trunk0
  check "admin apply (Revision 1)" "$NS" admin apply -note "lab start"
  check "admin status über den Socket" sh -c "\"$NS\" admin status | grep -q 'mode active'"
  check "admin disable flatout1 flatout2" "$NS" admin disable flatout1 flatout2
  check "admin apply (Revision 2)" "$NS" admin apply -note "flatout off"
  flatout "FlatOut per CLI aus -> nicht weitergeleitet" 50010 "-none"
  check "admin enable flatout1 flatout2 + apply (Revision 3)" sh -c "\"$NS\" admin enable flatout1 flatout2 && \"$NS\" admin apply -note 'flatout on'"
  flatout "FlatOut per CLI ein -> weitergeleitet" 50011 ""
  check "admin rollback 2 (Revision 4)" "$NS" admin rollback 2
  flatout "Rollback auf Revision 2 -> FlatOut wieder aus" 50012 "-none"
  check "admin rollback 3 (Revision 5)" "$NS" admin rollback 3
  check "admin revisions zeigt 5 Stände" sh -c "\"$NS\" admin revisions | grep -c '^[0-9]' | grep -qx 5"
  # port finder (phase 8): session on table 1 only, unknown port 41234 shows up, table 2 is filtered out
  check "finder-start auf Tisch 1" "$NS" admin finder-start -vlans 1101 -seconds 30
  ip netns exec t1 "$NS" lab send -iface eth0 -src 10.10.1.10 -dst 255.255.255.255 -sport 50030 -dport 41234 -size 20 -count 3
  ip netns exec t2 "$NS" lab send -iface eth0 -src 10.10.2.10 -dst 255.255.255.255 -sport 50030 -dport 41235 -size 20 -count 3
  sleep 0.3
  check "finder zeigt Port 41234 als unbekannt" sh -c "\"$NS\" admin finder | grep -q '41234  UNKNOWN'"
  check "finder ignoriert Tisch 2" sh -c "! \"$NS\" admin finder | grep -q 41235"
  check "finder-pcap schreibt den Mitschnitt" sh -c "\"$NS\" admin finder-pcap /tmp/nsrelay/finder.pcap && [ \$(stat -c %s /tmp/nsrelay/finder.pcap) -gt 150 ]"
  check "finder-stop" "$NS" admin finder-stop
  check "backup schreibt .db und .yaml" sh -c "\"$NS\" backup -dir /tmp/nsrelay/backups -keep 3 && ls /tmp/nsrelay/backups/*.db /tmp/nsrelay/backups/*.yaml"

  # engine restarts without web and database from active.json (written by the last apply)
  kill -TERM "$ENGINE_PID"; rm -f /tmp/nsrelay/engine.pid; sleep 0.5
  mv "$NSRELAY_DB" "$NSRELAY_DB.away"
  ip netns exec relay "$NS" engine -snapshot "$SNAP" -socket /tmp/nsrelay/engine.sock >/tmp/nsrelay/engine-restart.log 2>&1 &
  echo $! > /tmp/nsrelay/engine-restart.pid
  sleep 2.5
  flatout "Engine-Neustart ohne Web/DB aus active.json -> FlatOut läuft" 50013 ""
  mv "$NSRELAY_DB.away" "$NSRELAY_DB"

  # first apply while broadcasts flow (live network 2026-11-16: receivers started before the first state -> panic)
  kill -TERM "$(cat /tmp/nsrelay/engine-restart.pid)"; rm -f /tmp/nsrelay/engine-restart.pid "$SNAP"; sleep 0.5
  ip netns exec relay "$NS" engine -snapshot "$SNAP" -socket /tmp/nsrelay/engine.sock >/tmp/nsrelay/engine-first.log 2>&1 &
  echo $! > /tmp/nsrelay/engine-first.pid
  sleep 1
  SENDERS=""
  for c in gs:0 t1:1 t2:2 t3:3; do # flood every VLAN without pause while the first state is built
    ip netns exec "${c%%:*}" "$NS" lab send -iface eth0 -src "10.10.${c##*:}.10" -dst 255.255.255.255 -sport 50020 -dport 27015 -size 30 -count 20000 &
    SENDERS="$SENDERS $!"
  done
  sleep 0.2
  check "Erstes apply unter laufendem Broadcast-Verkehr" "$NS" admin apply -note "first apply under traffic"
  for p in $SENDERS; do wait "$p"; done
  check "Engine lebt danach und ist aktiv" sh -c "\"$NS\" admin status | grep -q 'mode active'"
  check "Kein panic im Engine-Log" sh -c "! grep -q panic /tmp/nsrelay/engine-first.log"
fi

echo
echo "lab: $pass passed, $fail failed"
[ $fail = 0 ]

# Game database

`games/games.yaml` lists 149 games and services with the ports they use to **find** each other on a LAN. It is
compiled into the binary and synced into the web database on start.

## Where the data comes from

Ports were researched from source code (ioquake3, Unreal Tournament, Doom ports, Warsow/Warfork, Minecraft protocol
documentation, FlatOut community plugins), protocol specifications (e.g. Microsoft DirectPlay MC-DPL4CS, Valve A2S),
established LAN-party port lists (OpenSourceLAN service-discovery-helper, NETWAR gamebridge) and captures. Notes and
sources per game are in the YAML; the research reports (German) are in `docs/research/`.

Each entry has a **confidence**:

| Confidence | Meaning |
|---|---|
| `high` | source code, protocol documentation or a port list tested at a large LAN |
| `medium` | several consistent secondary sources or an engine default |
| `low` | single or unverified source — on by default only after a check at a LAN |

and says whether the game **needs the original sender IP** (`source_ip: original`): if the host answers the sender
directly, rewriting the source to the relay's address breaks discovery.

`relay_needed: no` marks games without LAN broadcast (e.g. Steam-lobby-only games) — a relay cannot help there.
`relay_needed: unknown` marks games whose LAN ports are not documented yet.

## Format

```yaml
- id: flatout2
  name: FlatOut 2 (2006)
  category: game            # game | platform (Steam, DirectPlay …) | noise (NetBIOS, mDNS …)
  relay_needed: 'yes'
  default_enabled: true     # on in a new event
  confidence: high
  source_ip: relay          # original | relay | unknown
  discovery:
  - kind: broadcast         # or multicast + group: 224.0.2.60
    ports: '23757'          # "27015-27020", "2302-2470/12", "6111,6112"
    direction: both         # query | announce | both
  game_ports:
    udp: '23756'            # must be routable between VLANs, not relayed
  notes: '…'
  sources: [https://…]
```

Optional per discovery entry: `dst_mode` (`keep` | `subnet` | `limited`), `ttl_mode`, `rate_pps`, `rate_burst`,
`payload_max`. DHCP ports are always refused.

## Adding or correcting a game

1. Find the discovery port with a capture: start a LAN host on one PC, open the LAN browser on another PC **in the
   same subnet**, capture UDP on the client (`udp and (broadcast or multicast)`). Note destination port and address,
   who sends first, and whether the host answers by unicast to the sender.
2. Add or edit the entry, put the capture summary or a link in `notes`/`sources`, set `confidence` honestly.
3. Run `go test ./internal/gamedb ./internal/compile` (validation and the example event). If the example snapshot
   changes on purpose, update it with `go test ./internal/compile -update`.
4. Open a pull request, or use the issue template "New game / port correction" if you only have the facts.

At the LAN the **Port-Finder** page does step 1 without Wireshark: pick the VLAN (and the test PC's address), start a
session (up to 10 minutes), open the game's LAN browser. Every broadcast/multicast destination shows up with packet
count, interval, size, senders and the first 64 bytes; destinations that appear after the start are marked *neu*,
common noise (Steam 27036, mDNS, SSDP, NetBIOS …) can be hidden, and ports that belong to a game in the database
but switched off are named. **Spiel anlegen** turns an unknown port into a game (`origin: sniffer`,
`confidence: low`) and can switch it on right away. Download the capture as `.pcap` and attach it to the pull request
or issue. On the command line: `nsrelay admin finder-start -vlans 1101 -src 10.10.1.23 -seconds 300`,
`nsrelay admin finder`, `nsrelay admin finder-pcap capture.pcap`.

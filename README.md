# jamulus-proxyguard

Keeps VPN and proxy exits off a Jamulus server. It drops their UDP at the firewall, so they cannot connect, chat,
or even see the server's ping time. One Python file (188 lines, standard library only) plus a 43-line installer.
Jamulus itself is untouched.

## Why

Public Jamulus rooms are being chat-spammed by someone who rotates names and hides behind commercial VPN exits.
A new name costs nothing; a new network costs something. Real musicians almost never play through a VPN, because
it adds latency to a latency-critical app, so refusing VPN exits takes the harasser's tool away and costs your
players almost nothing. A player who does need a VPN goes in `allow.txt`.

This is the shape the Jamulus team asked for: a countermeasure **outside the Jamulus binary**, in the OS firewall,
that interested operators can choose to run.

## Install

```
git clone https://github.com/mcfnord/jamulus-proxyguard
cd jamulus-proxyguard
sudo ./install.sh
```

The installer finds the UDP port(s) your running Jamulus server listens on, installs `nftables` and `python3` if
missing, and starts a systemd service.

```
sudo ./install.sh --port 22124 --port 22125   # name the ports yourself
sudo ./install.sh --dry                       # watch first: logs WOULD-BLOCK, drops nothing
sudo ./install.sh                             # later: enforce
sudo ./install.sh --uninstall
```

Check it:

```
journalctl -fu jamulus-proxyguard      # START dry=0 means enforcing; BLOCK lines name each address
sudo jamulus-proxyguard status         # the live firewall table, with a drop counter
jamulus-proxyguard check 1.2.3.4       # what would happen to one address
```

To let a specific player through, add their address (or a CIDR) to `/etc/jamulus-proxyguard/allow.txt` and run
`sudo systemctl restart jamulus-proxyguard`.

## How it works

It adds one nftables table, `inet jamulus_proxyguard`, matching **only UDP to your Jamulus port(s)**. It sits
beside ufw, firewalld or iptables and changes none of them.

1. The kernel records every address that sends a packet to the port. That includes the ping a client sends
   while just *browsing* the server list, so most addresses are judged before they join.
2. The script reads that list twice a second and looks each new address up once at ip-api.com. Verdicts are
   kept for 7 days in `/var/lib/jamulus-proxyguard/cache.json`.
3. A `proxy` verdict puts the address in the block set. Every later packet from it is dropped before Jamulus
   sees it; a client already connected goes silent and times out.

**It fails open.** A lookup error, a rate limit, a crashed script or a stopped service blocks nobody. Stopping the
service deletes the table. If a firewall reload wipes the table, it is rebuilt within half a second with every
cached block in place.

## Tested (2026-10-14)

On Ubuntu 24.04 with a stock Jamulus 3.12.3dev server, a victim client, and an attacker client whose source address
was a real Proton VPN exit, sending a chat 3 seconds after connecting:

| Run | Victim received the chat? |
|---|---|
| `--dry` (control) | **yes** |
| enforce, address never seen before | **no**; blocked under 1 s after the attacker started; 1,990 packets dropped |
| enforce, address already cached | **no**; the attacker never connected |
| table deleted mid-run (a firewall reload) | rebuilt within 0.5 s, block restored, next attacker got nothing |

The same real-lookup block test passed in containers on **Oracle Linux 8** (Python 3.6.8, nftables 1.0.4),
**Oracle Linux 9**, **Debian 12** and **Ubuntu 20.04** (nftables 0.9.3). The installer was tested on Ubuntu 24.04
only. Not yet tested: the installer on Oracle Linux and Debian, a live firewalld, and arm64.

## Things to know

- **Privacy:** each new client address is sent to ip-api.com over plain HTTP (free, non-commercial use).
  Private, CGNAT and loopback addresses are never sent.
- **"Proxy" is ip-api's call**, and it is broader than "VPN": Google's public DNS `8.8.8.8` reads as a proxy.
  On our own servers about one flagged address in fifty was a real player over ten days. `allow.txt` is the fix.
- **IPv4 only.** A client reaching the server over IPv6 is never judged.
- ip-api allows 15 lookups a minute (100 addresses each). Past that, new addresses wait unjudged, which means
  allowed.
- Needs Linux with nftables (any distribution from about 2020 on), Python 3.6+, systemd and root.

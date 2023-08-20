# wg2gue

Tool that converts between Wireguard-secured IP packets and plain IP-over-UDP (i.e. FOU/GUE) datagrams. Someting like a [boringtun-cli](https://github.com/cloudflare/boringtun), but instead of a tun interface there is another UDP socket.

## Features

* Maintain connection with one Wireguard peer
* Send and receive FOU or GUE IPv4 or IPv6 packets.
* Periodically send empty UDP datagrams to FOU port to avoid stale NAT entries.
* Periodic printing of statistics

<details><summary> Example session </summary>

```
# ip netns add peer1
$ wg genkey | tee /dev/stderr | wg pubkey
OGCvzGq9bbbiuiEXwHpdsK9QXEc13/2az0we5z7DCls=
tGk/3hzFBUuG21EZ4iTN/ZChl4PYKtkfx31TDCz8wgI=
$ wg genkey | tee /dev/stderr | wg pubkey
GKLlQK+pdrdmX6M/1eujcZcjlBC8kvHPsQFznW6vuWI=
IVbkRatA+KK2nE7GYuM+vPr/aWUK3VjmDQNAHaP21S8=
# ip link add peer1 type wireguard
# wg set peer1 listen-port 1929 private-key <(echo OGCvzGq9bbbiuiEXwHpdsK9QXEc13/2az0we5z7DCls=) peer IVbkRatA+KK2nE7GYuM+vPr/aWUK3VjmDQNAHaP21S8= endpoint 127.0.0.1:1930  allowed-ips fd00::2/128
# ip link set peer1 netns peer1
# ip netns exec peer1 ip link set peer1 up
# ip netns exec peer1 ip addr add fd00::1/128 dev peer1
# ip netns exec peer1 ip route add fd00::2/128 dev peer1

$ wg2gue -k GKLlQK+pdrdmX6M/1eujcZcjlBC8kvHPsQFznW6vuWI= -K tGk/3hzFBUuG21EZ4iTN/ZChl4PYKtkfx31TDCz8wgI=  -b 127.0.0.1:1930 --gue-bind-ip-port 127.0.0.1:1931 --gue-peer-endpoint 127.0.0.1:1932

# ip netns add peer2
# ip fou add port 1932 gue
# ip link add peer2  type sit remote 127.0.0.1 local 127.0.0.1 encap gue encap-sport 1932 encap-dport 1931 encap-csum
# ip link set peer2 netns peer2
# ip netns exec peer2 ip link set peer2 up
# ip netns exec peer2 ip addr add fd00::2/128 dev peer2
# ip netns exec peer2 ip route add fd00::1/128 dev peer2

# ip netns exec peer2 ping fd00::1
64 bytes from fd00::1: icmp_seq=1 ttl=64 time=48.7 ms
64 bytes from fd00::1: icmp_seq=2 ttl=64 time=0.960 ms
```

</details>

## Installation

Download a pre-built executable from [Github releases](https://github.com/vi/wg2gue/releases) or install from source code with `cargo install --path .`  or `cargo install wg2gue`.


## CLI options

<details><summary> wg2gue --help output</summary>

```
Usage: wg2gue [-k <private-key>] [-f <private-key-file>] -K <peer-key> [-p <wg-peer-endpoint>] [-a <wg-keepalive-interval>] -b <wg-bind-ip-port> -g <gue-bind-ip-port> [-G <gue-peer-endpoint>] [-A <gue-keepalive-interval>] [--print-stats-interval <print-stats-interval>]

Expose internet access without root using Wireguard

Options:
  -k, --private-key main private key of this Wireguard node, base64-encoded
  -f, --private-key-file
                    main private key of this Wireguard node (content of a
                    specified file), base64-encoded
  -K, --peer-key    peer's public key
  -p, --wg-peer-endpoint
                    address of the peer's UDP socket, where to send keepalives
  -a, --wg-keepalive-interval
                    wireguard keepalive interval, in seconds
  -b, --wg-bind-ip-port
                    where to bind UDP socket for Wireguard connection
  -g, --gue-bind-ip-port
                    where to bind UDP socket for GUE/FOU
  -G, --gue-peer-endpoint
                    send GUE/FOU datagrams to that socket address, not use
                    remembered recvfrom address.
  -A, --gue-keepalive-interval
                    send empty UDP datagrams to the GUE/FOU peer with this
                    interval, in seconds
  --print-stats-interval
                    print stats to stdout each N milliseconds
  --help            display usage information

```
</details>

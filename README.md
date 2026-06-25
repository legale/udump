# udump

`udump` is a small Linux packet capture tool with no build dependencies beyond
`libc`. It writes classic `pcap` files and supports a minimal filter set close
to `tcpdump` syntax.

## Build

Default build uses `musl-gcc` and links a static binary.

```sh
make
```

Result:

```text
./udump
```

Sanitizer build:

```sh
make san
```

## Usage

```sh
./udump [-d] [-i <ifname> -w <output_file>] [-c <count>] [-G <seconds>] \
  [--filter-mode <bpf|user>] [filter...]
```

Examples:

```sh
./udump -i br-eth0 -w out.pcap
./udump -i br-eth0 -w ssh.pcap -c 10 tcp port 22
./udump -i br-eth0 -w short.pcap -G 5 udp
./udump -i br-eth0 -w host.pcap ether host aa:bb:cc:dd:ee:ff
./udump -i br-eth0 -w ip-host.pcap host 192.168.1.1
./udump -i br-eth0 -w debug-user.pcap --filter-mode user tcp port 22
./udump -i br-eth0 -w radius.pcap \
  "(port 1812 or port 1813 or port 1700 or port 3799) and (host 172.16.140.4)"
./udump -d udp port 67 or udp port 68
./udump -d \( tcp or udp \) and port 53
```

Options:

- `-d`: compile-only mode, print filter tokens, parsed AST, normalized AST, and final classic BPF disassembly, then exit.
- `-i <ifname>`: Linux interface name.
- `-w <output_file>`: write captured packets to classic `pcap`; use `-w -` for stdout.
- `-c <count>`: stop after writing this many matched packets.
- `-G <seconds>`: stop after this many seconds.
- `--filter-mode <bpf|user>`: `bpf` by default, `user` for explicit userspace fallback.

Supported filters:

- `tcp`
- `udp`
- `port <n>`
- `host <ip>`
- `src host <ip>`
- `dst host <ip>`
- `ether src <mac>`
- `ether dst <mac>`
- `ether host <mac>`
- `not`
- explicit `and`
- explicit `or`
- parentheses for grouping

Grammar notes:

- `and`, `or`, and implicit concatenation have the same precedence.
- Evaluation is left-associative, like libpcap/tcpdump.
- `not` is unary and applies to the next term or parenthesized group.
- Parentheses are required if you want a different grouping.
- `tcp port 22` and `udp port 67` are parsed as protocol-qualified port terms, matching libpcap semantics.
- `host` matches source or destination IP address.
- `src host` and `dst host` restrict the match to one side only.

Examples:

```sh
tcp port 22
host 192.168.1.1
src host 10.0.0.1
udp ether host aa:bb:cc:dd:ee:ff
tcp port 443 ether dst 00:11:22:33:44:55
tcp or udp and port 53
\( tcp or udp \) and port 53
udp port 67 or udp port 68
not port 22
```

The whole filter can be passed as one quoted argument:

```sh
./udump -i eth0 -w radius.pcap \
  "(port 1812 or port 1813 or port 1700 or port 3799) and (host 172.16.140.4)"
```

Without quotes, parentheses must be escaped from the shell:

```sh
./udump -i eth0 -w radius.pcap \
  \( port 1812 or port 1813 or port 1700 or port 3799 \) \
  and \( host 172.16.140.4 \)
```

Write the pcap stream to Wireshark over SSH:

```sh
ssh sysadmin@10.241.200.132 \
  'sudo udump -w - -i eth0 not port 22' |
wireshark -k -i -
```

Bash process substitution is also supported:

```sh
wireshark -k -i <(
  ssh sysadmin@10.241.200.132 \
    'sudo udump -w - -i eth0 not port 22'
)
```

By default `udump` compiles the filter into classic BPF and attaches it to the
socket with `SO_ATTACH_FILTER`, so unmatched traffic is dropped in kernel space
before it reaches userspace. If that compilation or attach step fails, `udump`
exits with an error and does not silently fall back to userspace mode.

## Notes

- Capture path is Linux-only and uses `AF_PACKET`.
- Runtime requires `root` or `CAP_NET_RAW`.
- Output files are readable by `tcpdump -r` and Wireshark.
- Default filtering path is kernel classic BPF attached to the socket.
- Userspace filtering is kept only as an explicit fallback via `--filter-mode user`.
- `-d` does not require `-i` or `-w`; it only compiles and prints the filter.
- `-d` prints the final BPF in a tcpdump-style disassembly format.
- There is no packet pretty-printing to stdout.

## Limitations

- Only Ethernet L2 is supported.
- `tcp`, `udp`, `port`, and `host` support Ethernet + IPv4 and minimal Ethernet + IPv6.
- IPv6 support is limited to direct TCP/UDP next-header handling; no extension header walk.
- Filter compiler is a minimal `pcap_compile` analogue for the supported subset only.
- No VLAN parsing or full `tcpdump` grammar.
- No `pcapng`, only classic `pcap`.

## Tests

Run module tests:

```sh
make test
```

The test suite includes:

- parser and matcher checks on crafted packets
- classic BPF compile checks and kernel/userspace parity checks
- precedence and grouping checks for `and`/`or`
- BPF disassembly smoke test for `-d`
- `pcap` writer smoke test
- offline fixture check against
  `tests/fixtures/br-eth0-30-tcp-port-22-host-172.16.133.8.pcap`

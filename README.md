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
cmd/udump/udump
```

Sanitizer build:

```sh
make san
```

## Usage

```sh
./cmd/udump/udump -i <ifname> -w <output_file> [-c <count>] [-G <seconds>] \
  [--filter-mode <bpf|user>] [filter...]
```

Examples:

```sh
./cmd/udump/udump -i br-eth0 -w out.pcap
./cmd/udump/udump -i br-eth0 -w ssh.pcap -c 10 tcp port 22
./cmd/udump/udump -i br-eth0 -w short.pcap -G 5 udp
./cmd/udump/udump -i br-eth0 -w host.pcap ether host aa:bb:cc:dd:ee:ff
./cmd/udump/udump -i br-eth0 -w debug-user.pcap --filter-mode user tcp port 22
```

Options:

- `-i <ifname>`: Linux interface name.
- `-w <output_file>`: write captured packets to classic `pcap`.
- `-c <count>`: stop after writing this many matched packets.
- `-G <seconds>`: stop after this many seconds.
- `--filter-mode <bpf|user>`: `bpf` by default, `user` for explicit userspace fallback.

Supported filters:

- `tcp`
- `udp`
- `port <n>`
- `ether src <mac>`
- `ether dst <mac>`
- `ether host <mac>`

Filter terms are combined by implicit `and`. Examples:

```sh
tcp port 22
udp ether host aa:bb:cc:dd:ee:ff
tcp port 443 ether dst 00:11:22:33:44:55
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
- `port` filter is applied only to IPv4 TCP/UDP packets with present L4 ports.
- There is no packet pretty-printing to stdout.

## Limitations

- Only Ethernet L2 is supported.
- Only IPv4 is parsed for `tcp`, `udp`, and `port`.
- Filter compiler is a minimal `pcap_compile` analogue for the supported subset only.
- No `or`, `not`, parentheses, VLAN parsing, or full `tcpdump` grammar.
- No `pcapng`, only classic `pcap`.

## Tests

Run module tests:

```sh
make test
```

The test suite includes:

- parser and matcher checks on crafted packets
- classic BPF compile checks and kernel/userspace parity checks
- `pcap` writer smoke test
- offline fixture check against
  `cmd/udump/tests/fixtures/br-eth0-30-tcp-port-22-host-172.16.133.8.pcap`

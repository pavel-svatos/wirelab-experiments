# Runtime architecture

```text
src/main.cpp       CLI validation and daemon startup
src/server.cpp     Drogon HTTP/WS, serialized control worker, aggregation
src/engine.cpp     RAII capture jthread, bounded metadata queue and counters
src/capture.cpp    libpcap RAII handle and bounds-checked packet dissection
src/config.cpp     interface, MAC, IPv4 and topology validation
src/json.cpp       strict JSON serialization and configuration conversion
src/network.cpp    acknowledged libmnl Netlink + atomic nftables batches
src/process.cpp    bounded posix_spawn execution without a shell
src/store.cpp      SQLite WAL, settings/journal, metrics and flow history
include/magicbox/  domain contracts and runtime interfaces
web/              offline Vue dashboard and vendored runtime
deploy/           systemd unit and installation script
tests/             core/runtime units and namespace integration test
```

The kernel routes/NATs traffic. Capture is observational and cannot block kernel
forwarding. `CaptureEngine` owns a `CaptureSource` and joins its jthread before any
capture resource is destroyed. libpcap is nonblocking with bounded polling. Parsing
uses borrowed spans only while the buffer is valid, then moves owned metadata into
an 8192-record queue. Queue overflow and libpcap kernel drops are separate counters.
The parser handles Ethernet/VLAN, IPv4/basic IPv6 and TCP/UDP/ICMP plus packet-local
HTTP/DNS/TLS hints; there is no stream reassembly or PcapPlusPlus dependency yet.
IPv4 fragments and IPv6 extension chains retain address metadata only. Truncated
IP packets and UDP lengths exceeding available data do not produce application hints.

One application worker serializes control jobs, SQLite writes and periodic metrics.
Drogon event-loop callbacks authenticate and enqueue work; they never execute network
commands or SQL. The queue is capped at 64. Capture continues independently during
network/storage operations. Slow control/storage operations can lose telemetry;
those limits are explicit, not an assertion of zero drops. Top talkers, flows, recent
packets and client connections are all bounded.

Netlink changes MACs, VLAN interfaces, addresses, policy rules and routes. Every
operation requests a kernel acknowledgement and has a receive timeout. nftables
batches run through argv-based posix_spawn with bounded output and execution time;
no user input is interpreted by a shell. nft parsing occurs before mutations.
Netlink and nftables cannot form a single atomic transaction, so a forwarding guard
covers intermediate states and SQLite stores a write-ahead recovery journal.
The controller refuses already addressed or enslaved interfaces and occupied
reserved resources. It restores the initial port state on failure, timeout or explicit
rollback. Matching marked connection entries are removed without flushing unrelated
conntrack state. Existing external firewall policy can still reject traffic.

SQLite stores settings/network recovery state, one-second metric samples, and
bounded directed connection summaries. Prepared statements, WAL, FULL synchronous
writes and a single writer avoid unsafe connection sharing. Retention is seven days,
with at most 10,000 flow summaries. History buckets sum packet/byte counts and
protocol observations. A file lock prevents two processes using the same database.

The default service runs management on loopback with a file-backed bearer token and
network mutation disabled. A local Vue dashboard is shipped with the binary. SSH
forwarding supplies encrypted remote access. Live mode needs CAP_NET_ADMIN; capture
needs CAP_NET_RAW. The current service is one privileged process with a capability
bounding set, not a privilege-separated helper architecture. Preserve that distinction
when deciding where to expose management.

SIGINT/SIGTERM stops Drogon's event loop, then explicitly stops the application worker,
joins capture, flushes final samples, and rolls back unconfirmed network state.
Confirmed state remains active and is reconciled after restart with --allow-network.

References used for adapter implementation:
- [libpcap nonblocking operation](https://www.man7.org/linux/man-pages/man3/pcap_setnonblock.3pcap.html)
- [Drogon WebSocket controllers](https://github.com/drogonframework/drogon/wiki/ENG-04-3-Controller-WebSocketController)
- [Netfilter connection tracking](https://netfilter.org/projects/conntrack-tools/conntrack-manpage.html)

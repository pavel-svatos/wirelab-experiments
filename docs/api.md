# Implemented API v1

The daemon serves this API and the local dashboard through Drogon. All REST requests
require `Authorization: Bearer <token>`. Token files must be mode 0600/0400 and contain
32–256 characters. Remote access should use an SSH tunnel or TLS proxy. Cross-origin
browser requests are rejected. JSON request bodies are limited to 16 KiB; WebSocket
messages to 1 KiB. The server caps connections at 64 and queued control jobs at 64.

| Method | Path | Result |
| --- | --- | --- |
| GET | `/api/v1/status` | Runtime, network, capture and storage status |
| GET | `/api/v1/interfaces` | Linux interface/address inventory |
| GET | `/api/v1/config` | Network state, configuration and confirmation deadline |
| POST | `/api/v1/config/validate` | Pure syntax/subnet validation |
| PUT | `/api/v1/config` | Apply configuration; returns awaiting_confirmation |
| POST | `/api/v1/config/confirm` | Keep pending configuration |
| POST | `/api/v1/config/rollback` | Deactivate and restore original state |
| PUT | `/api/v1/capture` | Start capture: `{"interface":"inner0"}` |
| DELETE | `/api/v1/capture` | Stop capture |
| GET | `/api/v1/metrics` | Current metrics snapshot |
| GET | `/api/v1/packets` | Last 200 packet metadata records |
| GET | `/api/v1/history` | Bucketed totals; epoch-second from/to; interval=60/300/3600 |
| GET | `/api/v1/flows` | Latest 200 persistent directed connection summaries |
| GET | `/api/v1/live` | WebSocket upgrade |

Configuration example (`outer0` and `inner0` are placeholders for your interface names):

```json
{
  "outer_interface":"outer0", "inner_interface":"inner0",
  "device_ipv4":"10.0.0.5", "inner_gateway_ipv4":"10.0.0.1", "inner_prefix":24,
  "outer_ipv4":"192.168.50.99", "outer_prefix":24,
  "outer_gateway_ipv4":"192.168.50.1", "outer_mac":"02:11:22:33:44:55", "vlan_id":100
}
```

VLAN null means untagged. Unknown config fields, duplicate JSON keys, invalid types,
multicast MACs, unusable host addresses, off-link gateways, and overlapping subnets
are rejected. Apply also checks actual link and reserved-resource availability.
Only one configuration can be active; rollback before replacement. This deliberately
avoids concurrent revision races. The earlier architecture's operation resources,
ETags and idempotency keys are not implemented; GET state after a lost response
before retrying. All mutations are serialized and synchronous.

State machine: `inactive -> applying -> awaiting_confirmation -> confirmed`.
Rollback transitions through `rolling_back` to `inactive` or `rollback_failed`.
Confirmation expires 60 seconds after successful apply, using a monotonic clock.
Recovery metadata is persisted before mutations. An interrupted/unconfirmed apply
is rolled back when restarted with network control enabled. A confirmed configuration
is restored then reapplied. Errors use `{"error":"message"}` with 401 for authentication,
422 for validation, 409 for operational failure, or 429 for a full control queue.

For WebSockets, send the token in the **message**, not the URL:

```json
{"token":"your-management-token","ack":"0"}
```

The server returns one complete metrics snapshot with a decimal-string `sequence`.
Request another snapshot by acknowledging the last sequence. The dashboard does
this once per second. Only one request is in progress per client; a client cannot
queue snapshots without acknowledging delivery. Reconnect starts at ack `"0"`.
Nonmatching origins and invalid tokens close the socket. Example response fields:

```json
{
  "type":"metrics", "schema_version":1, "sequence":"1",
  "capture_interface":"inner0", "running":true, "timestamp":1790000000,
  "packets":"10000", "wire_bytes":"12000000",
  "bits_per_second":9600000.0, "packets_per_second":1000.0,
  "elapsed_seconds":1.0, "metadata_dropped":"0", "kernel_dropped":"0",
  "protocols":{"tcp":"900","udp":"90","icmp":"10"},
  "top_talkers":[{"ip":"10.0.0.5","wire_bytes":"1200000"}],
  "talkers_omitted":"0", "flows_omitted":"0", "breakdown_complete":true,
  "network":{"status":"inactive","enabled":false}
}
```

Counters are decimal strings to preserve JavaScript precision. Totals reset when
capture restarts. Rates and protocol/talker breakdowns cover the last sampling
interval; byte totals derive from wire length, not captured payload size. Unknown
kernel loss is null, never an assumed zero. Capture only one port for appliance-wide
statistics. Flow histories are directed tuples, not reconstructed TCP sessions.

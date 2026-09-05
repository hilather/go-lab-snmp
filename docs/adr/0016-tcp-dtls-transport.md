# ADR 0016 — TCP and DTLS transport

Status: Accepted

## Context

1.0 schema keys `spec.listeners.tcp` and `spec.listeners.dtls` exist
but `enabled: true` rejects with `tls_unsupported` (TLS-001 deferred).
v1.1 implements those listeners at lab fidelity. Changing invariant 10
requires this ADR first. See `IMPLEMENTATION-DESIGN-v1.1.md` K1.3–K1.22.

## Decision

- **TCP** is RFC 3430 SNMP over TCP on 161/tcp and 162/tcp. Stream
  framing is the **BER length** of a single SNMP message (RFC 3430
  §2.1). There is **no** 32-bit length prefix. `snmpwire.ReadTCP` /
  `WriteTCP` implement framing. A 4-byte prefix is a different,
  non-RFC framing and MUST NOT be named RFC 3430. Framing loss closes
  the connection (RFC 3430 §2.1 SHOULD). No pipelining.
  `SetNoDelay(true)`. Idle timeout is a lab constant (30s), not YAML.
- **DTLS** is a **DTLS 1.2 record layer** on IANA 10161/10162. Inner
  PDU is community or USM. **TLSTM/TSM is not implemented.** Do not
  describe this as RFC 6353 implemented.
- **TLS-over-TCP** (snmp-tls) remains residual. No
  `spec.listeners.tls` (`unknown_field`). Catalog code
  `tls_unsupported` is retained for that residual and is **not**
  emitted on `tcp`/`dtls` enable. TSM-on-the-wire is `auth_fail` /
  Drop, not `tls_unsupported`.
- `enabled: true` is legal in 1.1 when per-listener constraints hold:
  TCP enablement is per listener; empty `tcp.address` inherits the
  effective UDP host:port **only if** that UDP listener is on;
  `tcp.enabled` with both resulting TCP addresses off is
  `validation_failed`. DTLS has its own addresses (default `:10161` /
  `:10162` when enabled), file-ref `certFile`/`keyFile`, optional
  `clientCAFile`.
- LabSNMP **implements** the UDP mapping (RFC 3430 §1). A process
  **instance** may disable the UDP agent when TCP or DTLS agent is on.
- DTLS cipher allowlist is **AEAD only**: ECDHE + AES-GCM and
  ChaCha20-Poly1305. No PSK, no CBC. pion/dtls v3
  `ListenWithOptions` (inbound Accept, never production Dial).
- Serve and Reset share one `SyncDataPlane(desired)`: bind-all-new,
  then commit; failed bind rolls back and keeps old sockets. Empty
  address is off. `DesiredListeners` is filled from the candidate
  snapshot, not `Active()`.
- View identity remains community string or v3 user, not client IP
  or client cert. No `dtls`/`tcp` feature catalog ids. INFORM stays
  store-then-ack (ADR 0007); TCP/DTLS INFORM/Report ack is `Write` /
  `WriteTCP` on the accepted connection, never Dial.
- UDP and DTLS cannot share a socket (fail closed). Ready includes
  every **enabled** listener; Off flags overlay from the snapshot so
  disabled transports do not demand a bind. Cap accepted TCP/DTLS
  conns at 1024 per stream listener including in-handshake. Bind
  failure of an enabled listener is process exit 1.

## Consequences

- AGENTS.md §11 and `scripts/checkdocs` phrases flip in CFG-110 with
  the validate change, not with this ADR.
- Remaining residuals: TLSTM/TSM, TLS-over-TCP, DTLS 1.3, client cert
  as map identity. ADR 0014 host residual 10161/10162 is unchanged;
  in-container DTLS listens `:10161`/`:10162` and must not be confused
  with host UDP 10161→161. Default overlay keeps `tcp`/`dtls` false.
  Optional DTLS host map is `2161:10161/udp`. Integrator compose does
  not publish `10161/tcp` by default. linux/arm64 is a publish-matrix
  change only.

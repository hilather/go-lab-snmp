# ADR 0007 — Receive-only traps

Status: Accepted

UDP 162 `ListenPacket` + INFORM `WriteTo` to the source address on that
socket. No `Dial`. No trap originator. No forwarder.

v1 TRAPv1, SNMPv2-TRAP, and INFORM (including v3 USM) are stored in the
ephemeral ring. INFORM is stored first, then acknowledged. Reserved
keys: `trapdest*`, `notifytarget*`, `forward*`, `proxy*`, `manager*`.

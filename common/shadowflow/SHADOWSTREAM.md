# ShadowStream Framed Transport — Wire Spec v1

The contract both ends (v2node node ⇄ mihomo client) MUST implement identically.
ShadowStream is a thin framing layer that lives **inside the Reality TLS
connection, beneath the proxy protocol (VLESS)**:

```
app data ─▶ [VLESS] ─▶ [ShadowStream frames] ─▶ [Reality TLS record] ─▶ wire
```

Reality TLS provides confidentiality, integrity and replay protection; the
framing layer carries no crypto of its own. Its sole job is **fingerprint
elimination**: it can pad any record up to a target size and inject cover
records, which a byte-preserving re-chunker cannot.

## Frame

```
+--------+-----------+------------------+
| Type   | Length    | Payload          |
| 1 byte | 2 bytes BE| Length bytes     |
+--------+-----------+------------------+
```

| Type | Name | Receiver action |
|------|------|-----------------|
| 0x00 | DATA | append Payload to the application byte stream |
| 0x01 | PAD  | discard Payload (cover / size shaping) |

- `Length` is the payload length (0..65535). A frame with `Length == 0` is legal
  (a header-only marker) and is skipped.
- After Reality TLS encryption, DATA and PAD frames are indistinguishable on the
  wire. There are **no magic bytes, no version field, no handshake** of Shadow
  Stream's own — the connection is already authenticated by Reality.

## Record shaping (write side)

For each outbound TLS record the sender:

1. samples a **target record size** from the active traffic profile
   (per-connection; the first records follow the profile's initial sequence);
2. fills the record with one or more DATA frames drawn from pending app data;
3. if app data runs out before the target size is reached, appends a single PAD
   frame of random bytes so the record still hits its target size;
4. performs exactly **one** `Conn.Write(record)` so the record maps to one TLS
   record.

This lets the sender reproduce a real browser's record-size distribution
*exactly*, including padding small writes up to plausible sizes — the capability
that eliminates the small-record ("19-byte") and TLS-in-TLS size fingerprints.

## Read side

Parse frames from the decrypted byte stream (frames may span TLS records):
read the 3-byte header, then `Length` bytes; deliver DATA payloads to the
application in order, silently drop PAD payloads. Byte delivery is exact — no
byte of application data is ever added or lost.

## Compatibility

- Single stream per connection (mux is a future, backward-compatible extension
  using an added StreamID field — NOT part of v1).
- Both ends must agree on the traffic profile family, but the exact per-record
  sizes are sampled independently on each side; only the frame parsing must
  match. A receiver never needs to know how the sender chose sizes.

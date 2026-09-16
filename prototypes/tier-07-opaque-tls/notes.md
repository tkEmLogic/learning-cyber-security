# Spike: one mutually authenticated handshake from an opaque PSA key

**Question:** [GitHub issue #157](https://github.com/tkEmLogic/learning-cyber-security/issues/157), part of map [#132](https://github.com/tkEmLogic/learning-cyber-security/issues/132)

**Run date:** 16 September 2026, on the nanoESP32-C6, board `beacon-remfg-404cca5ea9fc`

**Status:** Prototype. Throwaway code, kept on this branch as the primary source
for the answer. Nothing here is meant to be merged; what Tier 7 takes from it is
the decision, not the files.

## Answer

Yes. The board completed a mutually authenticated TLS 1.2 handshake presenting a
certificate whose private key is a PSA key that cannot be exported, and the key
was still there and still non-exportable afterwards.

Read off the board's own console:

```
spike.begin one mutually authenticated handshake, issue #157
spike.identity presenting beacon-remfg-404cca5ea9fc
spike.socket protocol 260 dispatched to the course implementation, fd=0
spike.tls wrapped PSA key 0x00000601, no private material exported
spike.result HANDSHAKE COMPLETED TLSv1.2 TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
spike.result peer verification flags 0x00000000
spike.data the service answered: HTTP/1.1 200 OK
spike.key 0x00000601 still present after the handshake and the free
spike.key usage flags 0x00001400, exportable=no
spike.end
```

and from the other end of the same connection:

```
client certificate subject "CN=beacon-remfg-404cca5ea9fc,O=Learning Cyber Security course\, synthetic"
                    issuer "CN=Learning Cyber Security Manufacturer Device CA,O=Learning Cyber Security course\, synthetic"
client certificate public key *ecdsa.PublicKey, chains verified 1
request GET /spike from beacon-remfg-404cca5ea9fc, version 0x0303 suite 0xc02b
```

The server ran `tls.RequireAndVerifyClientCert` against the manufacturer device
authority, so "chains verified 1" is Go's verifier saying the certificate chained
to that authority, not the spike saying so about itself. 39 handshakes completed
across the run and none was refused.

Full console in `evidence/board-console.txt`, full server log in
`evidence/spike-server.txt`.

## What this settles, and what it does not

Settled, on the board:

- `NET_SOCKET_REGISTER` on a course-specific protocol number works from the
  application. `zsock_socket(AF_INET, SOCK_STREAM, 260)` reached the spike's
  implementation and handed back an ordinary descriptor. Zephyr's
  `protocol_check()` claims 256 to 259 and 272 to 273 and refuses everything
  else, so 260 collides with nothing and the implementation does not have to win
  on priority. No Zephyr source was changed and no module was forked.
- `mbedtls_pk_wrap_psa()` plus `mbedtls_ssl_conf_own_cert()` carries a key
  identifier all the way through a TLS 1.2 CertificateVerify. The key was never
  exported, because it cannot be: its usage flags are `0x00001400` and
  `PSA_KEY_USAGE_EXPORT` is not among them.
- `mbedtls_pk_free()` does not take the key with it. This was the dangerous
  failure mode, because losing key `0x601` would strand the device's identity,
  and the spike checks for it explicitly after every connection rather than
  trusting the doc comment. The key survived all three connections in the
  captured log.
- The three build-time properties #138 asked for hold, and now fail the build
  rather than the handshake if they stop holding: exactly one SHA-256
  ciphersuite is enabled, `PSA_WANT_ALG_DETERMINISTIC_ECDSA` is off, and
  TLS 1.3 is off.
- The certificate that was presented is the genuine Tier 6 Factory certificate
  already on the device, issued by the manufacturer device authority against a
  certification request that same key signed. Nothing was minted for the spike.

Not settled, and deliberately not attempted:

- **Poll.** The spike implements `connect`, `read`, `write`, `sendto`,
  `recvfrom` and `close`, and its `ioctl` returns `EOPNOTSUPP`.
  `http_client_req()` polls the descriptor, so it cannot run on this socket as
  written. The spike sent its GET with `zsock_send()` and read the reply with
  `zsock_recv()`. Whether `http_client` can be carried is the next question and
  it belongs to #148, not here. It is the one part of the #138 recommendation
  that remains unproven, and it is the part that decides how much of
  `ota_client.c` Tier 7 can reuse.
- **Concurrency.** One static context, one connection at a time, blocking
  throughout. Real firmware needs at least the allocation Zephyr's own
  `tls_alloc()` does.
- **Session handling, renegotiation, close_notify on the error path,
  timeouts.** None of it. The spike returns `ECONNABORTED` for every handshake
  failure and reports the mbedTLS code beside it.
- **Stack.** The handshake ran on `main`, whose stack this build already sizes
  for the Tier 6 work. #138 warned that the key load and sign overran 2 KiB on
  the shell thread. Nothing here measured the margin, so #148 should.

## What it cost

About 400 lines of firmware, of which `src/opaque_tls.c` is the load-bearing
part, plus a 90-line throwaway server. The socket implementation is the piece
Tier 7 would keep and grow; everything else here is scaffolding.

That is at the low end of what #138 estimated for option A, but the estimate did
not include poll, which is the part still missing.

## Two things the run itself taught

**A spike image must not poll for updates.** The first spike image booted, ran
the spike, then entered Tier 6's normal OTA poll loop, found a release waiting,
installed it and rebooted into it. It replaced itself with Tier 5 before anyone
had read the console, and the evidence of the first run is simply gone. The
image now ends in its own loop and never reaches the poll. Any later
board-side spike in this map should do the same.

**The console has to be captured before the reset, not after.** The board's
USB-JTAG serial device re-enumerates across an esptool reset, and a reader
attached afterwards misses the boot. Repeating the spike every 30 seconds makes
this a non-problem, which is the cheaper fix than getting the timing right.

## How to run it again

```
./prototypes/tier-07-opaque-tls/run.sh build     # container: sysbuild, then imgtool sign
SPIKE_ESPTOOL=<path to esptool 5.4.0> \
  ./prototypes/tier-07-opaque-tls/run.sh flash   # host: primary slot only
./prototypes/tier-07-opaque-tls/run.sh server    # host: the listener that demands a client cert
./prototypes/tier-07-opaque-tls/run.sh console   # host: watch it
```

Two things the runbook cannot do for you. The spike server listens on 8444, and
firewalld on this host opens only 8080 and 8443, so the port has to be opened
before the board can reach it; the first run failed with `errno=116` for exactly
this reason and nothing else. And the board keeps running the spike image until
something else is flashed over it, because the spike image does not update
itself.

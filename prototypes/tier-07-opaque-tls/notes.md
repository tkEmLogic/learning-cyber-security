# Spike: an opaque-key TLS socket, and whether http_client can run on it

**Questions:** [GitHub issue #157](https://github.com/tkEmLogic/learning-cyber-security/issues/157)
and [GitHub issue #158](https://github.com/tkEmLogic/learning-cyber-security/issues/158),
part of map [#132](https://github.com/tkEmLogic/learning-cyber-security/issues/132)

**Run dates:** 16 September 2026 (#157) and 18 September 2026 (#158), on the
nanoESP32-C6, board `beacon-remfg-404cca5ea9fc`

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

Not settled by #157, and taken up by #158 below: poll, stack margin and
concurrency.

Still not settled by either, and deliberately not attempted:

- **Session handling, renegotiation, close_notify on the error path,
  timeouts.** None of it. The spike returns `ECONNABORTED` for every handshake
  failure and reports the mbedTLS code beside it.
- **`getsockopt`.** `http_client`'s `http_wait_data()` calls
  `zsock_getsockopt(SO_ERROR)`, but only on the `ZSOCK_POLLERR` branch, which no
  run here reached. Tier 7 should implement it rather than discover it from a
  connection that fails in the field.
- **Server sockets.** Client only. Nothing here listens or accepts.

## Issue #158: poll, stack and concurrency

Run on 18 September 2026, same board, same Factory certificate, same key
`0x00000601`. Full console in `evidence/board-console-158.txt`, server log in
`evidence/spike-server-158.txt`.

### Poll: yes, and Tier 7 keeps `ota_client.c`

`http_client_req()` runs on the opaque socket, unchanged, with the same
`struct http_request` shape `ota_client.c` already builds. Off the board:

```
spike.http asking http_client_req() to run on the opaque socket, GET /spike
spike.http http_client_req returned 49 after 19 ms
spike.http HTTP OVER THE OPAQUE SOCKET WORKED url=/spike status=200 body=60 complete=yes reads=1
spike.poll /spike prepare: 1 forwarded, 0 already-had-plaintext
spike.poll /spike update: 1 decrypted-now, 0 from-mbedtls-buffer, 0 partial-record
```

**That first result proves less than it looks like it does**, and the counters
are there to say so: a 60 byte reply arrives in one record and is consumed in
one read, so it takes the easy branch once and never asks the poll
implementation the question the ticket was about. A 64 KiB body against the
512 byte `recv_buf` does:

```
spike.http http_client_req returned 55 after 850 ms
spike.http HTTP OVER THE OPAQUE SOCKET WORKED url=/spike/large status=200 body=65536 complete=yes reads=135
spike.poll /spike/large prepare: 11 forwarded, 124 already-had-plaintext
spike.poll /spike/large update: 11 decrypted-now, 124 from-mbedtls-buffer, 128 partial-record
```

All 65536 bytes, 135 response callbacks, `complete=yes`, and the two hard
branches carried nearly all of it. Identical counts on the next iteration
30 seconds later, and on the one after that.

Read those counters as the argument for why forwarding alone is not enough:

- **124 polls were answered from mbedTLS's own buffer.** One record decrypts up
  to 16 KiB and `http_client` takes 512 bytes at a time, so for 31 reads out of
  every 32 the plaintext is already in the SSL context and the TCP descriptor
  has nothing left to signal. A poll that only forwards would block on every one
  of those, forever, on data the socket is already holding. This is the failure
  that hangs.
- **128 polls saw a readable TCP descriptor and no completed record.** A poll
  that only forwards reports `ZSOCK_POLLIN` there and sends `http_client` into a
  `zsock_recv()` that blocks until the rest of the record arrives, which quietly
  turns the request timeout into no timeout at all.

Both are handled the way Zephyr's own `sockets_tls.c` handles them, mirrored
rather than reinvented: `ZFD_IOCTL_POLL_PREPARE` forwards to the underlying TCP
descriptor and then returns `-EALREADY` when `mbedtls_ssl_get_bytes_avail()` is
non-zero, and `ZFD_IOCTL_POLL_UPDATE` forwards, then reports `POLLIN` from the
buffer, then runs a non-blocking `mbedtls_ssl_read(ssl, NULL, 0)` data check and
hands `-EAGAIN` back to `zvfs_poll_internal()` with the event reset to
`K_POLL_STATE_NOT_READY`. The data check is why `bio_recv()` grew a
`recv_flags` field: it has to pass `ZSOCK_MSG_DONTWAIT` down, or the check that
exists to avoid blocking blocks.

**Cost: 150 lines**, all in `opaque_tls.c`, the whole of it in and under
`opaque_ioctl()`. That is the answer to what #158 was weighing. Option C from
`research/tier-07-client-certificates.md`, writing Tier 7's own request building
and response parsing for the restricted endpoints, is not needed and should not
be taken.

### Stack: 3224 bytes of 8192, and the handshake is the peak

`CONFIG_INIT_STACKS` plus `k_thread_stack_space_get()` on `main`, which is the
thread the handshake runs on:

```
spike.stack after the raw handshake main has 5132 bytes of 8192 never touched, high water 3060
spike.stack after http_client_req main has 5124 bytes of 8192 never touched, high water 3068
spike.stack after the 64 KiB download main has 4968 bytes of 8192 never touched, high water 3224
```

The handshake sets the mark and neither `http_client_req()` nor a 64 KiB
download moves it much: 3060 for the handshake alone, 3224 after everything.
`main` at 8192 has around 5 KiB of headroom, so #138's warning holds for the
2048 byte default and does not threaten this build. What #138 measured was the
*shell* thread, which Tier 6 raised to 8192 for exactly this reason; nothing
changes there.

`thread_analyzer_print()` over every thread found no other thread near its
limit. `sysworkq` at 608 of 1024 and `wifi` at 1880 of 3584 are the closest, and
both are Tier 6 numbers rather than anything this spike introduced. It reports
`ISR0` at 2048 of 2048; that is the interrupt stack rather than a thread, the
reading did not move across runs, and it was not chased.

Note that `CONFIG_INIT_STACKS`, `CONFIG_THREAD_MONITOR` and the analyzer are in
this spike's `prj.conf` and must not follow it into Tier 7. Tier 6 turned that
introspection off on purpose with `CONFIG_SHELL_MINIMAL`; these are instruments
for a throwaway image.

### Concurrency: one at a time, and that is the decision

```
spike.concurrency a second socket is refused with errno=12, one at a time
```

`errno=12` is `ENOMEM`, from the single static context. **Tier 7 does not need
more, and this is written down as a decision rather than left as a limitation.**
`ota_client.c:473`'s `run_request()` opens a socket, connects, calls
`http_client_req()` and closes it, once per exchange, on `main`; the Tier 7
endpoints (assignment, image download, status event, and the claim) are the same
shape and the same thread. Nothing in Tier 7 has two exchanges in flight.

What Tier 7 should do instead of adding contexts is make the refusal legible:
one context, and a second `socket()` returning `ENOMEM` with a comment saying
which design decision that enforces. Zephyr's own `tls_alloc()` over
`CONFIG_NET_SOCKETS_TLS_MAX_CONTEXTS` is the pattern to copy if that ever stops
being true.

## What it cost

About 550 lines of firmware, of which `src/opaque_tls.c` is the load-bearing
part, plus a 100-line throwaway server. The socket implementation is the piece
Tier 7 would keep and grow; everything else here is scaffolding.

#138 estimated option A without poll. Poll turned out to be 150 of those lines,
so the estimate holds with it included.

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

There is no esptool 5.4.0 venv on this host any more. `uvx --from
esptool==5.4.0 esptool` is 5.4.0 and works; `run.sh` execs `$SPIKE_ESPTOOL` as a
single word, so point it at a one-line wrapper around that rather than at a
command with arguments.

Two things the runbook cannot do for you. The spike server listens on 8444, and
firewalld on this host opens only 8080 and 8443, so the port has to be opened
before the board can reach it; the first run failed with `errno=116` for exactly
this reason and nothing else. And the board keeps running the spike image until
something else is flashed over it, because the spike image does not update
itself.

**The board is still holding the #158 spike image.** Reflash it with a real tier
image before anything else needs this board.

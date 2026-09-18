/*
 * The opaque-key TLS socket. See opaque_tls.h for why it exists.
 *
 * This is the #157 and #158 prototype promoted, with the spike's own entry
 * point and its running commentary removed and two things added that a spike
 * did not need: a choice of which identity to present, and getsockopt().
 *
 * It is a client only. It handles one connection at a time, which #158 turned
 * from a limitation into a decision: every Tier 7 exchange is one
 * run_request() on main, a socket opened and closed around one
 * http_client_req(), and nothing in the tier has two exchanges in flight. The
 * refusal below is ENOMEM and it names the decision it enforces.
 */

#include "opaque_tls.h"
#include "identity.h"

#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <zephyr/sys/fdtable.h>
#include <errno.h>
#include <string.h>

#include <psa/crypto.h>
#include <mbedtls/ssl.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/net_sockets.h>

/* The Course certificate authority, compiled into this image.
 *
 * It lives here rather than in ota_client.c because this is now the only file
 * that opens a connection: Tier 6 registered it with tls_credential_add() for
 * Zephyr's TLS layer, and Tier 7 does not use that layer at all. One copy, and
 * course_opaque_tls_trust_anchor() hands it to whoever needs to describe it.
 *
 * The trailing zero keeps the array from being zero length when the anchor is
 * empty, so the length is one less than the array.
 */
static const unsigned char course_ca_der[] = {
#include "course_ca_der.inc"
	0x00
};

#define COURSE_CA_DER_LEN (sizeof(course_ca_der) - 1)

/*
 * Three build-time assertions, carried over from #138 through #157. Each one is
 * a property the firmware has to state rather than discover on the wire, and
 * each stops the build rather than the handshake.
 */

/*
 * 1. The ciphersuite pin is a control, not a config detail.
 *
 * TLS 1.2 signs CertificateVerify with the negotiated ciphersuite's own hash,
 * not one the key agreed to, so a SHA-384 suite would ask a key whose policy
 * says SHA-256 for a signature PSA refuses, and TLS 1.2 has no fallback. The
 * build enables exactly one suite and it is a SHA-256 one. If that ever stops
 * being true, this stops the build rather than the handshake.
 */
BUILD_ASSERT(IS_ENABLED(CONFIG_MBEDTLS_CIPHERSUITE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
	     "the SHA-256 ciphersuite this key's policy can sign for is not enabled");

/*
 * 2. Deterministic ECDSA changes what the key policy has to say.
 *
 * MBEDTLS_PK_ALG_ECDSA(hash) resolves to PSA_ALG_DETERMINISTIC_ECDSA when
 * PSA_WANT_ALG_DETERMINISTIC_ECDSA is set, and is_alg_compatible_with_key()
 * demands an exact match. The Tier 6 key policy is PSA_ALG_ECDSA(SHA_256), so
 * turning determinism on silently makes mbedtls_pk_can_do_psa() false. Harmless
 * on this TLS 1.2 path, which never asks, and fatal on TLS 1.3, which does.
 */
BUILD_ASSERT(!IS_ENABLED(CONFIG_PSA_WANT_ALG_DETERMINISTIC_ECDSA),
	     "deterministic ECDSA is on; the Tier 6 key policy no longer matches "
	     "MBEDTLS_PK_ALG_ECDSA and TLS 1.3 would refuse this key");

/*
 * 3. TLS 1.3 signs CertificateVerify through a different path.
 *
 * #138 walked the TLS 1.2 client path end to end and nothing else. TLS 1.3
 * negotiates signature algorithms and would ask mbedtls_pk_can_do_psa() the
 * question assertion 2 is about, so turning it on is a change to be reasoned
 * about rather than a Kconfig value to flip.
 */
BUILD_ASSERT(!IS_ENABLED(CONFIG_MBEDTLS_SSL_PROTO_TLS1_3),
	     "Tier 7 reasoned about the TLS 1.2 client path only");

/*
 * One context, because Tier 7 needs one.
 *
 * The mbedTLS state is here rather than on the stack because the handshake runs
 * on whichever thread calls connect(), and #138 warned about exactly that: Tier 6
 * had to raise SHELL_STACK_SIZE to 8192 when loading this key and signing with it
 * overran 2 KiB, and the symptom read as a fault inside the crypto library.
 * #158 measured main's high water at 3224 of 8192 with the handshake, not HTTP,
 * setting the mark.
 *
 * If a later tier needs two connections at once, Zephyr's own tls_alloc() over
 * CONFIG_NET_SOCKETS_TLS_MAX_CONTEXTS is the pattern to copy. Do not reach for
 * it before then.
 */
struct opaque_ctx {
	bool in_use;
	int sock;
	bool handshake_done;
	bool peer_closed;
	/* What bio_recv() passes to zsock_recv(). Zero everywhere except inside
	 * the poll data check, which must not block on the underlying socket.
	 * Zephyr's tls_data_check() does exactly this with ctx->flags.
	 */
	int recv_flags;
	/*
	 * What getsockopt(SOL_SOCKET, SO_ERROR) answers.
	 *
	 * http_wait_data() reads it on the ZSOCK_POLLERR branch, which no run
	 * in #158 reached, so the spike never discovered that its ioctl refused
	 * the call. A connection that fails in the field is a bad time to find
	 * out that the diagnostic path is the one that is missing.
	 */
	int last_error;
	enum course_tls_identity identity;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt ca;
	mbedtls_x509_crt own_cert;
	mbedtls_pk_context pk;
	char hostname[64];
};

static struct opaque_ctx the_context;

static const struct socket_op_vtable opaque_fd_op_vtable;

/* What the last handshake did, so a refusal can be read out loud. */
static struct course_opaque_tls_result last_result;

/*
 * Which poll branch fired how often, so the evidence for the two hard cases is
 * a count off the board rather than an argument about record sizes.
 */
static struct course_opaque_tls_poll_stats poll_stats;

const struct course_opaque_tls_poll_stats *course_opaque_tls_poll_stats(void)
{
	return &poll_stats;
}

void course_opaque_tls_reset_poll_stats(void)
{
	memset(&poll_stats, 0, sizeof(poll_stats));
}

const struct course_opaque_tls_result *course_opaque_tls_last_result(void)
{
	return &last_result;
}

void course_opaque_tls_set_hostname(const char *name)
{
	strncpy(the_context.hostname, name, sizeof(the_context.hostname) - 1);
	the_context.hostname[sizeof(the_context.hostname) - 1] = '\0';
}

/* Set before the socket is created, like the hostname, and for the same
 * reason: by connect() time the configuration has to be complete.
 */
static enum course_tls_identity next_identity = COURSE_TLS_IDENTITY_OPERATIONAL;

void course_opaque_tls_set_identity(enum course_tls_identity identity)
{
	next_identity = identity;
}

bool course_opaque_tls_has_trust_anchor(void)
{
	return COURSE_CA_DER_LEN > 0;
}

int course_opaque_tls_trust_anchor(const unsigned char **der, size_t *len)
{
	if (COURSE_CA_DER_LEN == 0) {
		return -ENOENT;
	}
	*der = course_ca_der;
	*len = COURSE_CA_DER_LEN;
	return 0;
}

/* mbedTLS talks to the network through these two. They are the only place the
 * underlying TCP socket is read or written.
 */
static int bio_send(void *arg, const unsigned char *buf, size_t len)
{
	struct opaque_ctx *ctx = arg;
	ssize_t sent = zsock_send(ctx->sock, buf, len, 0);

	if (sent < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return MBEDTLS_ERR_SSL_WANT_WRITE;
		}
		return MBEDTLS_ERR_NET_SEND_FAILED;
	}
	return (int)sent;
}

static int bio_recv(void *arg, unsigned char *buf, size_t len)
{
	struct opaque_ctx *ctx = arg;
	ssize_t got = zsock_recv(ctx->sock, buf, len, ctx->recv_flags);

	if (got < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return MBEDTLS_ERR_SSL_WANT_READ;
		}
		return MBEDTLS_ERR_NET_RECV_FAILED;
	}
	return (int)got;
}

static void context_free(struct opaque_ctx *ctx)
{
	mbedtls_ssl_free(&ctx->ssl);
	mbedtls_ssl_config_free(&ctx->conf);
	mbedtls_x509_crt_free(&ctx->ca);
	mbedtls_x509_crt_free(&ctx->own_cert);

	/*
	 * This is the call the whole question turns on. For a context populated
	 * by mbedtls_pk_wrap_psa() this frees the wrapper and leaves the PSA key
	 * alone: pk.h says so and extras/pk.c guards psa_destroy_key() on
	 * pk_info->type != MBEDTLS_PK_OPAQUE. If that were wrong, freeing this
	 * context would destroy the device's Factory key, which is why #157 read
	 * the key back after every one of its handshakes rather than trusting
	 * the doc comment. It survived all of them.
	 */
	mbedtls_pk_free(&ctx->pk);

	if (ctx->sock >= 0) {
		(void)zsock_close(ctx->sock);
		ctx->sock = -1;
	}
	ctx->handshake_done = false;
	ctx->in_use = false;
}

/*
 * Everything Zephyr's tls_mbedtls_set_credentials() would have done, except
 * that the private key arrives as a key identifier instead of a byte buffer.
 */
static int configure(struct opaque_ctx *ctx)
{
	const unsigned char *cert_der;
	size_t cert_len;
	uint32_t key_id;
	int err;

	mbedtls_ssl_init(&ctx->ssl);
	mbedtls_ssl_config_init(&ctx->conf);
	mbedtls_x509_crt_init(&ctx->ca);
	mbedtls_x509_crt_init(&ctx->own_cert);
	mbedtls_pk_init(&ctx->pk);

	err = mbedtls_ssl_config_defaults(&ctx->conf, MBEDTLS_SSL_IS_CLIENT,
					  MBEDTLS_SSL_TRANSPORT_STREAM,
					  MBEDTLS_SSL_PRESET_DEFAULT);
	if (err != 0) {
		printk("tls.setup config defaults err=-0x%04x\n", (unsigned int)-err);
		return err;
	}

	/* The service is verified exactly as the Tier 2 connection verifies it.
	 * Nothing about presenting a client certificate relaxes this.
	 */
	if (COURSE_CA_DER_LEN == 0) {
		printk("tls.setup no trust anchor is compiled into this image\n");
		return -ENOENT;
	}
	err = mbedtls_x509_crt_parse_der(&ctx->ca, course_ca_der, COURSE_CA_DER_LEN);
	if (err != 0) {
		printk("tls.setup trust anchor will not parse err=-0x%04x\n", (unsigned int)-err);
		return err;
	}
	mbedtls_ssl_conf_ca_chain(&ctx->conf, &ctx->ca, NULL);
	mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_REQUIRED);

	/*
	 * Which certificate this connection presents, and which key signs for
	 * it. Both come out of identity.h and neither is a byte of private key
	 * material.
	 *
	 * The unclaimed case is the tier's sharpest line rather than an error
	 * path. A device that has never been issued an Operational certificate
	 * does not fall back to its Factory identity for the restricted
	 * endpoints; it stays unable to download, and it says so.
	 */
	if (ctx->identity == COURSE_TLS_IDENTITY_OPERATIONAL) {
		err = course_identity_operational_credentials(&key_id, &cert_der, &cert_len);
		if (err != 0) {
			printk("tls.identity this device holds no Operational certificate, so it\n");
			printk("tls.identity will not open this connection. It does not present its\n");
			printk("tls.identity Factory identity instead: that identity claims and\n");
			printk("tls.identity recovers, and it does not authorize updates.\n");
			return err;
		}
	} else {
		err = course_identity_certificate(&cert_der, &cert_len);
		if (err != 0) {
			printk("tls.identity this device holds no Factory certificate to present\n");
			return err;
		}
		key_id = course_identity_key_id();
	}

	err = mbedtls_x509_crt_parse_der(&ctx->own_cert, cert_der, cert_len);
	if (err != 0) {
		printk("tls.identity the certificate to present will not parse err=-0x%04x\n",
		       (unsigned int)-err);
		return err;
	}

	/*
	 * The line Zephyr's credential store cannot express.
	 *
	 * The key identifier goes in, no key material comes out, and the context
	 * signs through psa_sign_hash() when the server asks for CertificateVerify.
	 * mbedtls_pk_free() on the way out leaves this key alive and still
	 * non-exportable, which #157 verified on the board after every connection
	 * rather than trusting the doc comment.
	 */
	err = mbedtls_pk_wrap_psa(&ctx->pk, (mbedtls_svc_key_id_t)key_id);
	if (err != 0) {
		printk("tls.identity mbedtls_pk_wrap_psa err=-0x%04x\n", (unsigned int)-err);
		return err;
	}
	printk("tls.identity presenting the %s certificate, signed by PSA key 0x%08x\n",
	       ctx->identity == COURSE_TLS_IDENTITY_OPERATIONAL ? "Operational" : "Factory",
	       (unsigned int)key_id);

	err = mbedtls_ssl_conf_own_cert(&ctx->conf, &ctx->own_cert, &ctx->pk);
	if (err != 0) {
		printk("tls.setup conf_own_cert err=-0x%04x\n", (unsigned int)-err);
		return err;
	}

	err = mbedtls_ssl_setup(&ctx->ssl, &ctx->conf);
	if (err != 0) {
		printk("tls.setup ssl_setup err=-0x%04x\n", (unsigned int)-err);
		return err;
	}
	err = mbedtls_ssl_set_hostname(&ctx->ssl, ctx->hostname);
	if (err != 0) {
		printk("tls.setup set_hostname err=-0x%04x\n", (unsigned int)-err);
		return err;
	}
	mbedtls_ssl_set_bio(&ctx->ssl, ctx, bio_send, bio_recv, NULL);
	return 0;
}

static int opaque_connect(void *obj, const struct net_sockaddr *addr,
			  net_socklen_t addrlen)
{
	struct opaque_ctx *ctx = obj;
	int err;

	if (zsock_connect(ctx->sock, addr, addrlen) < 0) {
		ctx->last_error = errno;
		printk("tls.setup the TCP connection was refused errno=%d\n", errno);
		return -1;
	}

	err = configure(ctx);
	if (err != 0) {
		ctx->last_error = EINVAL;
		errno = EINVAL;
		return -1;
	}

	memset(&last_result, 0, sizeof(last_result));

	while ((err = mbedtls_ssl_handshake(&ctx->ssl)) != 0) {
		if (err == MBEDTLS_ERR_SSL_WANT_READ || err == MBEDTLS_ERR_SSL_WANT_WRITE) {
			continue;
		}
		printk("tls.setup handshake failed err=-0x%04x\n", (unsigned int)-err);
		last_result.mbedtls_error = err;
		last_result.verify_flags = mbedtls_ssl_get_verify_result(&ctx->ssl);
		ctx->last_error = ECONNABORTED;
		errno = ECONNABORTED;
		return -1;
	}

	ctx->handshake_done = true;
	last_result.completed = true;
	last_result.verify_flags = mbedtls_ssl_get_verify_result(&ctx->ssl);
	strncpy(last_result.ciphersuite, mbedtls_ssl_get_ciphersuite(&ctx->ssl),
		sizeof(last_result.ciphersuite) - 1);
	strncpy(last_result.version, mbedtls_ssl_get_version(&ctx->ssl),
		sizeof(last_result.version) - 1);
	return 0;
}

static ssize_t opaque_sendto(void *obj, const void *buf, size_t len, int flags,
			     const struct net_sockaddr *dest_addr, net_socklen_t addrlen)
{
	struct opaque_ctx *ctx = obj;
	int sent;

	ARG_UNUSED(flags);
	ARG_UNUSED(dest_addr);
	ARG_UNUSED(addrlen);

	if (!ctx->handshake_done) {
		errno = ENOTCONN;
		return -1;
	}
	do {
		sent = mbedtls_ssl_write(&ctx->ssl, buf, len);
	} while (sent == MBEDTLS_ERR_SSL_WANT_READ || sent == MBEDTLS_ERR_SSL_WANT_WRITE);

	if (sent < 0) {
		ctx->last_error = EIO;
		errno = EIO;
		return -1;
	}
	return sent;
}

static ssize_t opaque_recvfrom(void *obj, void *buf, size_t max_len, int flags,
			       struct net_sockaddr *src_addr, net_socklen_t *addrlen)
{
	struct opaque_ctx *ctx = obj;
	int got;

	ARG_UNUSED(flags);
	ARG_UNUSED(src_addr);
	ARG_UNUSED(addrlen);

	if (!ctx->handshake_done) {
		errno = ENOTCONN;
		return -1;
	}
	do {
		got = mbedtls_ssl_read(&ctx->ssl, buf, max_len);
	} while (got == MBEDTLS_ERR_SSL_WANT_READ || got == MBEDTLS_ERR_SSL_WANT_WRITE);

	if (got == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
		ctx->peer_closed = true;
		return 0;
	}
	if (got < 0) {
		ctx->last_error = EIO;
		errno = EIO;
		return -1;
	}
	return got;
}

static ssize_t opaque_read(void *obj, void *buf, size_t len)
{
	return opaque_recvfrom(obj, buf, len, 0, NULL, NULL);
}

static ssize_t opaque_write(void *obj, const void *buf, size_t len)
{
	return opaque_sendto(obj, buf, len, 0, NULL, 0);
}

static int opaque_close(void *obj, int fd)
{
	struct opaque_ctx *ctx = obj;

	ARG_UNUSED(fd);

	if (ctx->handshake_done) {
		(void)mbedtls_ssl_close_notify(&ctx->ssl);
	}
	context_free(ctx);
	return 0;
}

/*
 * Poll.
 *
 * This is the whole of issue #158. http_client_req() does not read and write a
 * descriptor; it polls it, in sendall() for ZSOCK_POLLOUT and in
 * http_wait_data() for ZSOCK_POLLIN, and calls zsock_recv() only once poll has
 * said data is there. A descriptor whose ioctl refuses ZFD_IOCTL_POLL_PREPARE
 * makes zsock_poll() fail outright, so #157's socket could not carry it.
 *
 * Forwarding the two ioctls to the underlying TCP descriptor is most of the
 * answer, and the part it gets wrong is the part that matters:
 *
 *   - TLS arrives in records. The TCP descriptor can be readable while the
 *     record is incomplete, so nothing decrypts out of it. Reporting POLLIN
 *     there sends http_client into a zsock_recv() that blocks until the rest of
 *     the record arrives, and with it the request timeout stops being a timeout.
 *   - mbedTLS buffers. A read can decrypt a whole record and return less than
 *     it holds, leaving bytes sitting in the SSL context with nothing left for
 *     the TCP descriptor to signal. Poll would then block forever on data the
 *     socket already has. This is the one that hangs rather than stalls.
 *
 * Zephyr's own sockets_tls.c answers both, and this mirrors it deliberately
 * rather than inventing a second answer: ztls_poll_prepare_pollin() returns
 * -EALREADY when mbedtls_ssl_get_bytes_avail() is non-zero, and
 * tls_update_pollin() runs a non-blocking data check and hands -EAGAIN back to
 * zvfs_poll_internal(), which retries with the event set back to NOT_READY.
 */

/*
 * Decrypt whatever has arrived, without blocking, and say how many bytes are
 * now readable. mbedtls_ssl_read() with a NULL buffer and zero length processes
 * records into the context and copies nothing out.
 *
 * Zephyr's tls_data_check() resets the mbedTLS session on an unexpected error.
 * This socket has nothing to reset to, because every exchange is a fresh
 * connection, so it records the error and lets the caller see POLLERR and then
 * read it back through getsockopt(SO_ERROR).
 */
static int data_check(struct opaque_ctx *ctx)
{
	int ret;

	if (!ctx->handshake_done) {
		return -ENOTCONN;
	}
	if (ctx->peer_closed) {
		return -ENOTCONN;
	}

	ctx->recv_flags = ZSOCK_MSG_DONTWAIT;
	ret = mbedtls_ssl_read(&ctx->ssl, NULL, 0);
	ctx->recv_flags = 0;

	if (ret < 0) {
		if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			ctx->peer_closed = true;
			return -ENOTCONN;
		}
		if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
			return 0;
		}
		printk("tls.poll data check err=-0x%04x\n", (unsigned int)-ret);
		ctx->last_error = ECONNABORTED;
		return -ECONNABORTED;
	}

	return (int)mbedtls_ssl_get_bytes_avail(&ctx->ssl);
}

/* The underlying TCP descriptor, with its lock held for the call, exactly as
 * ztls_poll_prepare_ctx() takes it.
 */
static int forward_ioctl(struct opaque_ctx *ctx, unsigned int request,
			 struct zsock_pollfd *pfd, struct k_poll_event **pev,
			 struct k_poll_event *pev_end)
{
	const struct fd_op_vtable *vtable;
	struct k_mutex *lock;
	void *obj;
	int ret;

	obj = zvfs_get_fd_obj_and_vtable(ctx->sock, &vtable, &lock);
	if (obj == NULL) {
		return -EBADF;
	}

	(void)k_mutex_lock(lock, K_FOREVER);
	if (request == ZFD_IOCTL_POLL_PREPARE) {
		ret = zvfs_fdtable_call_ioctl(vtable, obj, request, pfd, pev, pev_end);
	} else {
		ret = zvfs_fdtable_call_ioctl(vtable, obj, request, pfd, pev);
	}
	k_mutex_unlock(lock);

	return ret;
}

static int poll_prepare(struct opaque_ctx *ctx, struct zsock_pollfd *pfd,
			struct k_poll_event **pev, struct k_poll_event *pev_end)
{
	int ret;

	/* Forward first, unconditionally. The k_poll_event slots have to be
	 * filled the same way on every call, because POLL_UPDATE walks the same
	 * array; returning -EALREADY before forwarding would leave *pev short by
	 * one and desynchronise the update pass.
	 */
	ret = forward_ioctl(ctx, ZFD_IOCTL_POLL_PREPARE, pfd, pev, pev_end);
	if (ret != 0) {
		return ret;
	}

	if ((pfd->events & ZSOCK_POLLIN) && mbedtls_ssl_get_bytes_avail(&ctx->ssl) > 0) {
		/* Decrypted bytes are already here. -EALREADY tells
		 * zvfs_poll_internal() to collect events without waiting.
		 */
		poll_stats.prepare_already++;
		return -EALREADY;
	}

	poll_stats.prepare_forwarded++;
	return 0;
}

static int poll_update(struct opaque_ctx *ctx, struct zsock_pollfd *pfd,
		       struct k_poll_event **pev)
{
	int ret;

	ret = forward_ioctl(ctx, ZFD_IOCTL_POLL_UPDATE, pfd, pev, NULL);
	if (ret != 0) {
		return ret;
	}

	if ((pfd->events & ZSOCK_POLLIN) == 0) {
		return 0;
	}

	/* Buffered in mbedTLS, so the TCP descriptor has nothing to say. */
	if (mbedtls_ssl_get_bytes_avail(&ctx->ssl) > 0) {
		poll_stats.update_buffered++;
		pfd->revents |= ZSOCK_POLLIN;
		return 0;
	}

	if ((pfd->revents & ZSOCK_POLLIN) == 0) {
		return 0;
	}

	ret = data_check(ctx);
	if (ret == -ENOTCONN || (pfd->revents & ZSOCK_POLLHUP)) {
		pfd->revents |= ZSOCK_POLLHUP;
		return 0;
	}
	if (ret < 0) {
		pfd->revents |= ZSOCK_POLLERR;
		return 0;
	}
	if (ret > 0) {
		poll_stats.update_decrypted++;
		return 0;
	}

	/* Ciphertext arrived, no plaintext came of it. Withdraw the readiness
	 * the TCP descriptor reported and ask for another iteration.
	 */
	poll_stats.update_partial_record++;
	pfd->revents &= ~ZSOCK_POLLIN;
	if (pfd->revents == 0) {
		(*pev - 1)->state = K_POLL_STATE_NOT_READY;
		return -EAGAIN;
	}

	return 0;
}

static int opaque_ioctl(void *obj, unsigned int request, va_list args)
{
	struct opaque_ctx *ctx = obj;

	switch (request) {
	case ZFD_IOCTL_POLL_PREPARE: {
		struct zsock_pollfd *pfd = va_arg(args, struct zsock_pollfd *);
		struct k_poll_event **pev = va_arg(args, struct k_poll_event **);
		struct k_poll_event *pev_end = va_arg(args, struct k_poll_event *);

		return poll_prepare(ctx, pfd, pev, pev_end);
	}

	case ZFD_IOCTL_POLL_UPDATE: {
		struct zsock_pollfd *pfd = va_arg(args, struct zsock_pollfd *);
		struct k_poll_event **pev = va_arg(args, struct k_poll_event **);

		return poll_update(ctx, pfd, pev);
	}

	default:
		errno = EOPNOTSUPP;
		return -1;
	}
}

/*
 * getsockopt(SOL_SOCKET, SO_ERROR), and only that.
 *
 * #158 left this unimplemented and said why it mattered: http_wait_data()
 * reads SO_ERROR on the ZSOCK_POLLERR branch, and none of the spike's runs
 * reached it. An ioctl that refuses the call turns a diagnosable failure into
 * "http_client_req returned something", at the moment the connection is
 * already going wrong.
 *
 * The value is the errno of the last operation that failed on this context,
 * read and cleared the way a socket error is. Everything else is refused
 * rather than forwarded to the TCP descriptor: forwarding would answer
 * questions about the wrong socket, and a wrong answer is worse here than no
 * answer.
 */
static int opaque_getsockopt(void *obj, int level, int optname, void *optval,
			     net_socklen_t *optlen)
{
	struct opaque_ctx *ctx = obj;

	if (level == SOL_SOCKET && optname == SO_ERROR) {
		if (optval == NULL || optlen == NULL || *optlen < sizeof(int)) {
			errno = EINVAL;
			return -1;
		}
		*(int *)optval = ctx->last_error;
		*optlen = sizeof(int);
		ctx->last_error = 0;
		return 0;
	}

	errno = ENOPROTOOPT;
	return -1;
}

static const struct socket_op_vtable opaque_fd_op_vtable = {
	.fd_vtable = {
		.read = opaque_read,
		.write = opaque_write,
		.close2 = opaque_close,
		.ioctl = opaque_ioctl,
	},
	.connect = opaque_connect,
	.sendto = opaque_sendto,
	.recvfrom = opaque_recvfrom,
	.getsockopt = opaque_getsockopt,
};

/*
 * Zephyr's protocol_check() claims 256 to 259 and 272 to 273 and returns
 * -EPROTONOSUPPORT for everything else, so 260 collides with nothing and this
 * implementation does not have to win on priority to be reached.
 */
static bool opaque_is_supported(int family, int type, int proto)
{
	return (family == NET_AF_INET || family == NET_AF_INET6) &&
	       type == NET_SOCK_STREAM && proto == IPPROTO_COURSE_OPAQUE_TLS;
}

static int opaque_socket(int family, int type, int proto)
{
	struct opaque_ctx *ctx = &the_context;
	int fd;

	ARG_UNUSED(type);
	ARG_UNUSED(proto);

	if (ctx->in_use) {
		/*
		 * One connection at a time, and this is the decision #158 made
		 * rather than a shortage. Every Tier 7 exchange is one
		 * run_request() on main: a socket opened, one http_client_req(),
		 * and the socket closed. Two in flight would mean two contexts
		 * and a reason to have them, and Tier 7 has neither.
		 */
		errno = ENOMEM;
		return -1;
	}

	fd = zvfs_reserve_fd();
	if (fd < 0) {
		return -1;
	}

	/* The hostname and the identity are set before the socket is created, so
	 * they have to survive the reset that clears everything else.
	 */
	char hostname[sizeof(ctx->hostname)];

	strncpy(hostname, ctx->hostname, sizeof(hostname));
	memset(ctx, 0, sizeof(*ctx));
	strncpy(ctx->hostname, hostname, sizeof(ctx->hostname) - 1);
	ctx->identity = next_identity;
	ctx->in_use = true;
	ctx->sock = zsock_socket(family, NET_SOCK_STREAM, NET_IPPROTO_TCP);
	if (ctx->sock < 0) {
		ctx->in_use = false;
		zvfs_free_fd(fd);
		return -1;
	}

	zvfs_finalize_typed_fd(fd, ctx, (const struct fd_op_vtable *)&opaque_fd_op_vtable,
			       ZVFS_MODE_IFSOCK);
	return fd;
}

/* Priority 40, ahead of Zephyr's TLS layer at 45, though on protocol 260 the
 * order does not decide anything. It is stated so the dispatch is readable.
 */
NET_SOCKET_REGISTER(course_opaque_tls, 40, NET_AF_UNSPEC, opaque_is_supported, opaque_socket);

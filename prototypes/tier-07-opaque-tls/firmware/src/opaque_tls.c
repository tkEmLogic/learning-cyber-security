/*
 * PROTOTYPE. Throwaway spike code for issue #157. Not production firmware.
 *
 * One question: can a mutually authenticated TLS 1.2 handshake be completed on
 * this board from a PSA key that cannot be exported?
 *
 * Research issue #138 said yes in principle and nothing in it was compiled.
 * Zephyr's own socket TLS layer cannot do it, because tls_set_private_key()
 * feeds TLS_CREDENTIAL_PRIVATE_KEY straight to mbedtls_pk_parse_key() and a PSA
 * key identifier is not a key. The route it recommended is this file: an
 * application-owned socket implementation registered through NET_SOCKET_REGISTER
 * on a protocol number Zephyr does not claim, owning its own mbedtls_ssl_context
 * and reaching the key through mbedtls_pk_wrap_psa().
 *
 * This is the smallest thing that answers that question. It is a client only, it
 * handles one connection at a time, it is blocking, and it implements just
 * enough of socket_op_vtable to connect, send, receive and close. It does not
 * implement poll, so Zephyr's http_client cannot run on it as written; whether
 * the descriptor is good enough for http_client_req() is a separate question
 * this spike deliberately does not answer.
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

/* The Course certificate authority, compiled in exactly as ota_client.c
 * compiles it in. The trailing zero keeps the array from being zero length when
 * the anchor is empty, so the length is one less than the array.
 */
static const unsigned char course_ca_der[] = {
#include "course_ca_der.inc"
	0x00
};

#define COURSE_CA_DER_LEN (sizeof(course_ca_der) - 1)

/*
 * Three build-time assertions, carried over from #138. Each one is a property
 * the firmware has to state rather than discover on the wire.
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

/* 3. TLS 1.3 would sign through a different path. See section 4 of the note. */
BUILD_ASSERT(!IS_ENABLED(CONFIG_MBEDTLS_SSL_PROTO_TLS1_3),
	     "this spike reasoned about the TLS 1.2 client path only");

/*
 * One context. A spike opens one connection.
 *
 * The mbedTLS state is here rather than on the stack because the handshake runs
 * on whichever thread calls connect(), and #138 warned about exactly that: Tier 6
 * had to raise SHELL_STACK_SIZE to 8192 when loading this key and signing with it
 * overran 2 KiB, and the symptom read as a fault inside the crypto library.
 */
struct opaque_ctx {
	bool in_use;
	int sock;
	bool handshake_done;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt ca;
	mbedtls_x509_crt own_cert;
	mbedtls_pk_context pk;
	char hostname[64];
};

static struct opaque_ctx the_context;

static const struct socket_op_vtable opaque_fd_op_vtable;

/* What the last handshake did, for the spike to report. */
static struct course_opaque_tls_result last_result;

const struct course_opaque_tls_result *course_opaque_tls_last_result(void)
{
	return &last_result;
}

void course_opaque_tls_set_hostname(const char *name)
{
	strncpy(the_context.hostname, name, sizeof(the_context.hostname) - 1);
	the_context.hostname[sizeof(the_context.hostname) - 1] = '\0';
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
	ssize_t got = zsock_recv(ctx->sock, buf, len, 0);

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
	 * context would destroy the device's Factory key, which is why the spike
	 * reads the key back after the handshake and says whether it is still
	 * there.
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
		printk("spike.tls config defaults err=-0x%04x\n", (unsigned int)-err);
		return err;
	}

	/* The service is verified exactly as the Tier 2 connection verifies it.
	 * Nothing about presenting a client certificate relaxes this.
	 */
	if (COURSE_CA_DER_LEN == 0) {
		printk("spike.tls no trust anchor is compiled into this image\n");
		return -ENOENT;
	}
	err = mbedtls_x509_crt_parse_der(&ctx->ca, course_ca_der, COURSE_CA_DER_LEN);
	if (err != 0) {
		printk("spike.tls trust anchor will not parse err=-0x%04x\n", (unsigned int)-err);
		return err;
	}
	mbedtls_ssl_conf_ca_chain(&ctx->conf, &ctx->ca, NULL);
	mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_REQUIRED);

	/* The certificate the device presents is the Factory certificate it is
	 * already holding, issued by the manufacturer device authority against
	 * the certification request Tier 6 signed with this same key. Nothing is
	 * issued for the spike.
	 */
	err = course_identity_certificate(&cert_der, &cert_len);
	if (err != 0) {
		printk("spike.tls this device holds no Factory certificate to present\n");
		return err;
	}
	err = mbedtls_x509_crt_parse_der(&ctx->own_cert, cert_der, cert_len);
	if (err != 0) {
		printk("spike.tls Factory certificate will not parse err=-0x%04x\n",
		       (unsigned int)-err);
		return err;
	}

	/*
	 * The line Zephyr's credential store cannot express.
	 *
	 * The key identifier goes in, no key material comes out, and the context
	 * signs through psa_sign_hash() when the server asks for CertificateVerify.
	 */
	err = mbedtls_pk_wrap_psa(&ctx->pk, (mbedtls_svc_key_id_t)course_identity_key_id());
	if (err != 0) {
		printk("spike.tls mbedtls_pk_wrap_psa err=-0x%04x\n", (unsigned int)-err);
		return err;
	}
	printk("spike.tls wrapped PSA key 0x%08x, no private material exported\n",
	       (unsigned int)course_identity_key_id());

	err = mbedtls_ssl_conf_own_cert(&ctx->conf, &ctx->own_cert, &ctx->pk);
	if (err != 0) {
		printk("spike.tls conf_own_cert err=-0x%04x\n", (unsigned int)-err);
		return err;
	}

	err = mbedtls_ssl_setup(&ctx->ssl, &ctx->conf);
	if (err != 0) {
		printk("spike.tls ssl_setup err=-0x%04x\n", (unsigned int)-err);
		return err;
	}
	err = mbedtls_ssl_set_hostname(&ctx->ssl, ctx->hostname);
	if (err != 0) {
		printk("spike.tls set_hostname err=-0x%04x\n", (unsigned int)-err);
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
		printk("spike.tcp connect failed errno=%d\n", errno);
		return -1;
	}

	err = configure(ctx);
	if (err != 0) {
		errno = EINVAL;
		return -1;
	}

	memset(&last_result, 0, sizeof(last_result));

	while ((err = mbedtls_ssl_handshake(&ctx->ssl)) != 0) {
		if (err == MBEDTLS_ERR_SSL_WANT_READ || err == MBEDTLS_ERR_SSL_WANT_WRITE) {
			continue;
		}
		printk("spike.tls handshake failed err=-0x%04x\n", (unsigned int)-err);
		last_result.mbedtls_error = err;
		last_result.verify_flags = mbedtls_ssl_get_verify_result(&ctx->ssl);
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
		return 0;
	}
	if (got < 0) {
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

/* Poll is not implemented, which is the one thing a caller is most likely to
 * want next. http_client_req() polls the descriptor, so this spike cannot carry
 * it and does not claim to.
 */
static int opaque_ioctl(void *obj, unsigned int request, va_list args)
{
	ARG_UNUSED(obj);
	ARG_UNUSED(request);
	ARG_UNUSED(args);

	errno = EOPNOTSUPP;
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
		errno = ENOMEM;
		return -1;
	}

	fd = zvfs_reserve_fd();
	if (fd < 0) {
		return -1;
	}

	/* The hostname is set before the socket is created, so it has to survive
	 * the reset that clears everything else.
	 */
	char hostname[sizeof(ctx->hostname)];

	strncpy(hostname, ctx->hostname, sizeof(hostname));
	memset(ctx, 0, sizeof(*ctx));
	strncpy(ctx->hostname, hostname, sizeof(ctx->hostname) - 1);
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

package openssl

/*
#cgo CFLAGS: -g
#cgo LDFLAGS: -lssl -lcrypto

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

#define COOKIE_SECRET_LENGTH 16
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];

int init_cookie_secret()
{
	if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH)) {
		return -1;
	}
	return 0;
}

int CalculateCookicBasedOnPeerInfo(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
	unsigned int length = 0, resultlength = 0;
	unsigned char* buffer = NULL, result[EVP_MAX_MD_SIZE] = {0};
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} peer;

	// Get peer info
	BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	// Create buffer with peer's address and port
	switch (peer.ss.ss_family) {
		case AF_INET:
			length += sizeof(struct in_addr);
			break;
		case AF_INET6:
			length += sizeof(struct in6_addr);
			break;
		default:
			printf("Unknown ss_family type.\n");
			return -1;
	}

	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);
	if (buffer == NULL) {
		printf("Failed to OPENSSL_malloc.\n");
		return -1;
	}

	switch (peer.ss.ss_family) {
	case AF_INET:
		memcpy(buffer, &peer.s4.sin_port, sizeof(in_port_t));
		memcpy(buffer + sizeof(peer.s4.sin_port), &peer.s4.sin_addr, sizeof(struct in_addr));
		break;
	case AF_INET6:
		memcpy(buffer, &peer.s6.sin6_port, sizeof(in_port_t));
		memcpy(buffer + sizeof(in_port_t), &peer.s6.sin6_addr, sizeof(struct in6_addr));
		break;
	default:
		printf("Unknown ss_family type.\n");
		return -1;
	}

	// Calculate HMAC of buffer using the secret
	HMAC(EVP_sha256(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH, (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	memcpy(cookie, result, resultlength);
	*cookie_len = resultlength;
	return 0;
}

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
	unsigned int resultlength = 0;
	unsigned char result[EVP_MAX_MD_SIZE] = {0};
	int ret = CalculateCookicBasedOnPeerInfo(ssl, result, &resultlength);
	if (ret < 0) {
		return 0;
	}

	memcpy(cookie, result, resultlength);
	*cookie_len = resultlength;
	return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
	unsigned int resultlength = 0;
	unsigned char result[EVP_MAX_MD_SIZE] = {0};
	int ret = CalculateCookicBasedOnPeerInfo(ssl, result, &resultlength);
	if (ret < 0) {
		return 0;
	}
	return cookie_len==resultlength && memcmp(result, cookie, resultlength)==0;
}

int new_socket(unsigned int port)
{
	int sock;
	const int on = 1, off = 0;

	struct sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(server_addr));

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(port);

	if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		return -1;
	}

	if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*) &on, (socklen_t) sizeof(on)) < 0) {
		close(sock);
		perror("set reuse address");
		return -2;
	}

	//if(setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char*) &on, (socklen_t) sizeof(on)) < 0) {
	//    close(sock);
	//    perror("set reuse port");
	//    return -3;
	//}

	if(bind(sock, (const struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
		close(sock);
		perror("bind");
		return -4;
	}
	return sock;
}

int new_dgram_socket(int domain, int port)
{
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} local_addr;
	memset(&local_addr, 0, sizeof(struct sockaddr_storage));

	// local addr
	if (domain == AF_INET) {
		local_addr.s4.sin_family = AF_INET;
		local_addr.s4.sin_port = htons(port);
		inet_pton(AF_INET, "0.0.0.0", &local_addr.s4.sin_addr);
	} else if (domain == AF_INET6) {
		local_addr.s6.sin6_family = AF_INET6;
		local_addr.s6.sin6_port = htons(port);
		inet_pton(AF_INET6, "0:0:0:0:0:0:0:0", &local_addr.s6.sin6_addr);
	} else {
		return -1;
	}

	int sock = BIO_socket(domain, SOCK_DGRAM, 0, 0);
	if (sock < 0) {
		return sock;
	}

	if (!BIO_listen(sock, (BIO_ADDR *) &local_addr, BIO_SOCK_REUSEADDR)) {
		BIO_closesocket(sock);
	}
	return sock;
}

int read_msg(int fd, void *buf, size_t len)
{
	int n = recv(fd, buf, len, 0);
	if(n < 0) {
		if(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
			return 0;
		} else {
			return -1;
		}
	}
    return n;
}

int UpdateUdpDtlsCtxBaseCfg(SSL_CTX *ctx)
{
	SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb(ctx, &verify_cookie);
}

int UdpDtlsListen(SSL *ssl, int fd, char *raddr)
{
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} client_addr;
	memset(&client_addr, 0, sizeof(struct sockaddr_storage));

	while (DTLSv1_listen(ssl, (BIO_ADDR *) &client_addr) <= 0);

	//Get Peer addr: ip:port
	char addrbuf[INET6_ADDRSTRLEN];
	sprintf(raddr, "%s:%d", inet_ntop(AF_INET, &client_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN), ntohs(client_addr.s4.sin_port));

	// DEBUG
	if (1) {
		printf ("accepted connection from %s\n", raddr);
	}

	if (!BIO_connect(fd, (BIO_ADDR *) &client_addr, 0)) {
		return -1;
	}
	BIO_ctrl_set_connected(SSL_get_rbio(ssl), &client_addr.ss);
	return 0;
}

int associate_peer_info(SSL *ssl, int fd, char *raddr, unsigned int rport)
{
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in s4;
		struct sockaddr_in6 s6;
	} remote_addr;

	if (inet_pton(AF_INET, raddr, &remote_addr.s4.sin_addr) == 1) {
		remote_addr.s4.sin_family = AF_INET;
		remote_addr.s4.sin_port = htons(rport);
	} else if (inet_pton(AF_INET6, raddr, &remote_addr.s6.sin6_addr) == 1) {
		remote_addr.s6.sin6_family = AF_INET6;
		remote_addr.s6.sin6_port = htons(rport);
	} else {
		return -1;
	}

	//bind peer ip:port
	if (!BIO_connect(fd, (BIO_ADDR *) &remote_addr, 0)) {
		return -1;
	}
	BIO_ctrl_set_connected(SSL_get_rbio(ssl), &remote_addr.ss);
	return 0;
}
 */
import "C"
import (
	"errors"
	"fmt"
	"github.com/spacemonkeygo/openssl/utils"
	"io"
	"log"
	"strings"
	"sync"
	"unsafe"
)

func InitUdpDtlsLib() (err error) {
	// Init openssl lib
	Init()

	// Init Cookie Secret
	if (C.init_cookie_secret() < 0) {
		err = errors.New("error setting random cookie secret")
		return
	}
	return
}

type SocketConn struct {
	fd   int
}

func (c *SocketConn) Close() (err error) {
	if (C.BIO_closesocket(C.int(c.fd)) == 0) {
		err = errors.New(fmt.Sprintf("failed to BIO_closesocket(%d)", c.fd))
	}
	return
}

func (c *SocketConn) Read(p []byte) (n int, err error) {
	rv := C.read_msg(C.int(c.fd), C.CBytes(p), C.ulong(len(p)))
	if rv == 0 {
		n = -1
		//err = errors.New("resource temporarily unavailable")
	} else if rv < 0 {
		n = -2
		err = errors.New(fmt.Sprintf("failed ot C.recv, fd=%d, ret=%d", c.fd, n))
	} else {
		n = int(rv)
	}
	/*n = int(C.recv(C.int(c.fd), C.CBytes(p), C.ulong(len(p)), 0))
	if n < 0 {
		err = errors.New(fmt.Sprintf("Failed ot C.recv, fd=%d, ret=%d", c.fd, n)
	}*/
	return
}

func (c *SocketConn) Write(p []byte) (n int, err error) {
	n = int(C.send(C.int(c.fd), C.CBytes(p), C.ulong(len(p)), 0))
	if n < 0 {
		err = errors.New(fmt.Sprintf("Failed ot C.send, fd=%d, ret=%d", c.fd, n))
		return
	}
	return
}

// UdpDtlsConn .
type UdpDtlsConn struct {
	*SSL
	Fd               int
	Raddr            string
	bio              *Bio
	conn             *SocketConn
	ctx              *Ctx // for gc
	into_ssl         *readBio
	from_ssl         *writeBio
	is_shutdown      bool
	mtx              sync.Mutex
	want_read_future *utils.Future
}

func (c *UdpDtlsConn) fillInputBuffer() (err error) {
	for {
		n, err := c.into_ssl.ReadFromOnce(c.conn)
		if n == 0 && err == nil {
			continue
		}
		if err == io.EOF {
			c.into_ssl.MarkEOF()
			return c.Close()
		}
		return err
	}
	return
}

func (c *UdpDtlsConn) flushOutputBuffer() (err error) {
	_, err = c.from_ssl.WriteTo(c.conn)
	return err
}

func (c *UdpDtlsConn) getError(rv C.int) (err error) {
	switch (C.SSL_get_error(c.ssl, rv)) {
	case C.SSL_ERROR_ZERO_RETURN:
		return errors.New("SSL_connect failed with SSL_ERROR_ZERO_RETURN\n")
	case C.SSL_ERROR_WANT_READ:
		return errors.New("SSL_connect failed with SSL_ERROR_WANT_READ\n")
	case C.SSL_ERROR_WANT_WRITE:
		return errors.New("SSL_connect failed with SSL_ERROR_WANT_WRITE\n")
	case C.SSL_ERROR_WANT_CONNECT:
		return errors.New("SSL_connect failed with SSL_ERROR_WANT_CONNECT\n")
	case C.SSL_ERROR_WANT_ACCEPT:
		return errors.New("SSL_connect failed with SSL_ERROR_WANT_ACCEPT\n")
	case C.SSL_ERROR_WANT_X509_LOOKUP:
		return errors.New("SSL_connect failed with SSL_ERROR_WANT_X509_LOOKUP\n")
	case C.SSL_ERROR_SYSCALL:
		return errors.New("SSL_connect failed with SSL_ERROR_SYSCALL\n")
	case C.SSL_ERROR_SSL:
		return errors.New("SSL_connect failed with SSL_ERROR_SSL\n")
	default:
		return errors.New("SSL_connect failed with unknown error\n")
	}
}

func (c *UdpDtlsConn) getErrorHandler(rv C.int, errno error) func() error {
	errcode := C.SSL_get_error(c.ssl, rv)
	log.Printf("SSL_get_error = %d, err = %v\n", errcode, errno)
	switch errcode {
	case C.SSL_ERROR_ZERO_RETURN:
		return func() error {
			c.Close()
			return io.ErrUnexpectedEOF
		}
	case C.SSL_ERROR_WANT_READ:
		go c.flushOutputBuffer()
		if c.want_read_future != nil {
			want_read_future := c.want_read_future
			return func() error {
				_, err := want_read_future.Get()
				return err
			}
		}
		c.want_read_future = utils.NewFuture()
		want_read_future := c.want_read_future
		return func() (err error) {
			defer func() {
				c.mtx.Lock()
				c.want_read_future = nil
				c.mtx.Unlock()
				want_read_future.Set(nil, err)
			}()
			err = c.fillInputBuffer()
			if err != nil {
				return err
			}
			return tryAgain
		}
	case C.SSL_ERROR_WANT_WRITE:
		return func() error {
			err := c.flushOutputBuffer()
			if err != nil {
				return err
			}
			return tryAgain
		}
	case C.SSL_ERROR_SYSCALL:
		var err error
		if C.ERR_peek_error() == 0 {
			switch rv {
			case 0:
				err = errors.New("protocol-violating EOF")
			case -1:
				err = errno
			default:
				err = errorFromErrorQueue()
			}
		} else {
			err = errorFromErrorQueue()
		}
		return func() error { return err }
	default:
		err := errorFromErrorQueue()
		return func() error { return err }
	}
}

func (c *UdpDtlsConn) handleError(errcb func() error) error {
	if errcb != nil {
		return errcb()
	}
	return nil
}

func (c *UdpDtlsConn) shutdownLoop() error {
	err := tryAgain
	shutdown_tries := 0
	for err == tryAgain {
		shutdown_tries = shutdown_tries + 1
		rv, errno := C.SSL_shutdown(c.ssl)

		if rv < 0 {
			err = c.handleError(c.getErrorHandler(rv, errno))
		} else {
			err = nil
		}

		if err == nil {
			return c.flushOutputBuffer()
		}
		if err == tryAgain && shutdown_tries >= 2 {
			return errors.New("shutdown requested a third time?")
		}
	}
	if err == io.ErrUnexpectedEOF {
		err = nil
	}
	return err
}

func (c *UdpDtlsConn) DoSslShutdown() {
	C.SSL_shutdown(c.ssl)
}

// Close dtls conn
func (c *UdpDtlsConn) Close() error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	var errs utils.ErrorGroup
	if(!c.is_shutdown) {
		c.is_shutdown = true
		errs.Add(c.shutdownLoop())
		C.SSL_set_shutdown(c.ssl, C.SSL_SENT_SHUTDOWN | C.SSL_RECEIVED_SHUTDOWN)
		C.SSL_free(c.ssl)
		errs.Add(c.conn.Close())
	}
	return errs.Finalize()
}

func (c *UdpDtlsConn) Read(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	err = tryAgain
	for err == tryAgain {
		n, errcb := c.read(b)
		err = c.handleError(errcb)
		if err == nil {
			go c.flushOutputBuffer()
			return n, nil
		}
		if err == io.ErrUnexpectedEOF {
			err = io.EOF
		}
	}
	return 0, err
}

func (c *UdpDtlsConn) read(b []byte) (int, func() error) {

	if c.is_shutdown {
		return 0, func() error { return io.EOF }
	}
	//BioCtrlGetSCTPRcvInfo(c.bio, rcvInfo)

	rv, errno := C.SSL_read(c.ssl, unsafe.Pointer(&b[0]), C.int(len(b)))
	if rv > 0 {
		return int(rv), nil
	}

	return 0, c.getErrorHandler(rv, errno)
}

func (c *UdpDtlsConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	err = tryAgain
	for err == tryAgain {
		n, errcb := c.write(b)
		err = c.handleError(errcb)
		if err == nil {
			return n, c.flushOutputBuffer()
		}
	}
	return 0, err
}

func (c *UdpDtlsConn) write(b []byte) (int, func() error) {

	if c.is_shutdown {
		err := errors.New("connection closed")
		return 0, func() error { return err }
	}
	//BioCtrlSetSCTPSndInfo(c.bio, sndInfo)
	rv, errno := C.SSL_write(c.ssl, unsafe.Pointer(&b[0]), C.int(len(b)))
	if rv > 0 {
		return int(rv), nil
	}

	return 0, c.getErrorHandler(rv, errno)
}

func UpdateSetUdpDtlsCtxBaseCfg(ctx *Ctx) {
	C.UpdateUdpDtlsCtxBaseCfg(ctx.ctx)
}

func UdpDtlsAccept(ctx *Ctx, domain, port int) (conn *UdpDtlsConn, err error) {
	fd := C.new_dgram_socket(C.int(domain), C.int(port))
	if (fd <= 0) {
		return nil, errors.New("Failed to new_dgram_socket")
	}
	ssl := &SSL{}
	//ssl.ssl = C.SSL_new(ctx.ctx)
	ssl.ssl, err = newSSL(ctx.ctx)
	if err != nil || C.SSL_clear(ssl.ssl) == 0 {
		C.BIO_closesocket(fd)
		if err == nil {
			err = errors.New("Failed to clearing SSL connection.")
		}
		return nil, err
	}

	//BIO_NOCLOSE == 0; BIO_CLOSE == 1;
	bio := NewBioDgramUdp(ssl, int(fd), 0)
	C.SSL_set_accept_state(ssl.ssl)

	// Set recv/send timeout.
	//BIOCtrlDgramSetRecvTimeout(bio, 5)
	//BIOCtrlDgramSetSendTimeout(bio, 5)

	// Turn on cookie exchange.
	ssl.SetOptions(CookieExchange)

	raddr := make([]byte, 128)
	ret := C.UdpDtlsListen(ssl.ssl, fd, (*C.char)(unsafe.Pointer(&raddr[0])))
	if ret < 0 {
		C.SSL_set_shutdown(ssl.ssl, C.SSL_SENT_SHUTDOWN | C.SSL_RECEIVED_SHUTDOWN)
		C.SSL_free(ssl.ssl)
		C.BIO_closesocket(fd)
		return nil, errors.New("Failed to UdpDtlsListen.");
	}
	raddrLen := strings.IndexByte(string(raddr[:]), byte(0))

	conn = &UdpDtlsConn{
		SSL: ssl,
		Fd: int(fd),
		bio: bio,
		ctx: ctx,
		conn: &SocketConn{fd: int(fd)},
		Raddr: string(raddr[:raddrLen]),
		into_ssl: &readBio{},
		from_ssl: &writeBio{},
	}

	ret = C.SSL_accept(conn.ssl)
	if ret < 0 {
		C.SSL_set_shutdown(ssl.ssl, C.SSL_SENT_SHUTDOWN | C.SSL_RECEIVED_SHUTDOWN)
		C.SSL_free(ssl.ssl)
		C.BIO_closesocket(fd)
		return nil, conn.getError(ret)
	}
	return conn, nil
}

func NewUdpDtlsClient(ctx *Ctx, domain, lport int, raddr string, rport int) (conn *UdpDtlsConn, err error) {
	fd := C.new_dgram_socket(C.int(domain), C.int(lport))
	if (fd <= 0) {
		return nil, errors.New("Failed to new_dgram_socket.")
	}

	ssl := &SSL{}
	ssl.ssl = C.SSL_new(ctx.ctx)
	//BIO_NOCLOSE == 0; BIO_CLOSE == 1;
	bio := NewBioDgramUdp(ssl, int(fd), 1)
	C.SSL_set_connect_state(ssl.ssl)

	ret := C.associate_peer_info(ssl.ssl, fd, C.CString(raddr), C.uint(rport))
	if ret < 0 {
		C.SSL_set_shutdown(ssl.ssl, C.SSL_SENT_SHUTDOWN | C.SSL_RECEIVED_SHUTDOWN)
		C.SSL_free(ssl.ssl)
		C.BIO_closesocket(fd)
		return nil, errors.New("Failed to associatePeerInfo.")
	}

	// Set recv/send timeout.
	//BIOCtrlDgramSetRecvTimeout(bio, 5)
	//BIOCtrlDgramSetSendTimeout(bio, 5)

	conn = &UdpDtlsConn{
		SSL: ssl,
		Fd: int(fd),
		bio: bio,
		ctx: ctx,
		conn: &SocketConn{fd: int(fd)},
		Raddr: fmt.Sprintf("%s:%d", raddr, rport),
		into_ssl: &readBio{},
		from_ssl: &writeBio{},
	}

	ret = C.SSL_connect(conn.ssl)
	if ret < 0 {
		C.SSL_set_shutdown(ssl.ssl, C.SSL_SENT_SHUTDOWN | C.SSL_RECEIVED_SHUTDOWN)
		C.SSL_free(ssl.ssl)
		C.BIO_closesocket(fd)
		return nil, conn.getError(ret)
	}

	return conn, nil
}

package openssl

/*
#cgo CFLAGS: -g
#cgo LDFLAGS: -lssl -lcrypto

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

char cookie_str[] = "BISCUIT!";

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    memmove(cookie, cookie_str, sizeof(cookie_str)-1);
    *cookie_len = sizeof(cookie_str)-1;

    return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
    return sizeof(cookie_str)-1==cookie_len && memcmp(cookie, cookie_str, sizeof(cookie_str)-1)==0;
}

int new_socket(unsigned int port) {
    int sock;
    const int on = 1, off = 0;

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);

    if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*) &on, (socklen_t) sizeof(on)) < 0) {
        perror("set reuse address");
        exit(EXIT_FAILURE);
    }

    //if(setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char*) &on, (socklen_t) sizeof(on)) < 0) {
    //    perror("set reuse port");
    //    exit(EXIT_FAILURE);
    //}

    if(bind(sock, (const struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }
    return sock;
}

int ConnRead(SSL *ssl) {
	int n = 0;
	char buf[2000];
	n = SSL_read(ssl, buf, sizeof(buf));
	if(n > 0) {
		printf("SSL_read -> %d\n", n);
	}
    return n;
}

//Clinet
SSL* client_connect(SSL_CTX *ctx, char *raddr, unsigned int rport, unsigned int lport) {
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in s4;
		struct sockaddr_in6 s6;
	} remote_addr;

	if (inet_pton(AF_INET, raddr, &remote_addr.s4.sin_addr) == 1) {
		remote_addr.s4.sin_family = AF_INET;
		//remote_addr.s4.sin_len = sizeof(struct sockaddr_in);
		remote_addr.s4.sin_port = htons(rport);
	} else if (inet_pton(AF_INET6, raddr, &remote_addr.s6.sin6_addr) == 1) {
		remote_addr.s6.sin6_family = AF_INET6;
		//remote_addr.s6.sin6_len = sizeof(struct sockaddr_in6);
		remote_addr.s6.sin6_port = htons(rport);
	} else {
		return NULL;
	}

    int fd = new_socket(lport);
    if (fd <= 0) {
        return NULL;
    }

    SSL *ssl = SSL_new(ctx);

    // Create BIO, connect and set to already connected
	BIO *bio = BIO_new_dgram(fd, BIO_CLOSE);
	if (remote_addr.ss.ss_family == AF_INET) {
		if (connect(fd, (struct sockaddr *) &remote_addr, sizeof(struct sockaddr_in))) {
             return NULL;
		}
	} else {
		if (connect(fd, (struct sockaddr *) &remote_addr, sizeof(struct sockaddr_in6))) {
             return NULL;
		}
	}
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &remote_addr.ss);
    SSL_set_bio(ssl, bio, bio);

    int retval = SSL_connect(ssl);
	if (retval <= 0) {
		switch (SSL_get_error(ssl, retval)) {
			case SSL_ERROR_ZERO_RETURN:
				printf("SSL_connect failed with SSL_ERROR_ZERO_RETURN\n");
				break;
			case SSL_ERROR_WANT_READ:
				printf("SSL_connect failed with SSL_ERROR_WANT_READ\n");
				break;
			case SSL_ERROR_WANT_WRITE:
				printf("SSL_connect failed with SSL_ERROR_WANT_WRITE\n");
				break;
			case SSL_ERROR_WANT_CONNECT:
				printf("SSL_connect failed with SSL_ERROR_WANT_CONNECT\n");
				break;
			case SSL_ERROR_WANT_ACCEPT:
				printf("SSL_connect failed with SSL_ERROR_WANT_ACCEPT\n");
				break;
			case SSL_ERROR_WANT_X509_LOOKUP:
				printf("SSL_connect failed with SSL_ERROR_WANT_X509_LOOKUP\n");
				break;
			case SSL_ERROR_SYSCALL:
				printf("SSL_connect failed with SSL_ERROR_SYSCALL\n");
				break;
			case SSL_ERROR_SSL:
				printf("SSL_connect failed with SSL_ERROR_SSL\n");
				break;
			default:
				printf("SSL_connect failed with unknown error\n");
				break;
		}
		return NULL;
    }

    // Set and activate timeouts
    struct timeval timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    // Debug
	if (1) {
	    char addrbuf[INET6_ADDRSTRLEN];
		if (remote_addr.ss.ss_family == AF_INET) {
			printf ("Connected to %s\n",
					 inet_ntop(AF_INET, &remote_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN));
		} else {
			printf ("Connected to %s\n",
					 inet_ntop(AF_INET6, &remote_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN));
		}
	}

	char buf[64] = "Hello, World!";
	SSL_write(ssl, buf, sizeof(buf));
    return ssl;
}

int client(SSL_CTX *ctx) {
    SSL *ssl = client_connect(ctx, "127.0.0.1", 4444, 12345);
    if (ssl == NULL) {
         return -1;
    }
    return 0;
}

int UpdateUdpDtlsCtxBaseCfg(SSL_CTX *ctx) {
    SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, &verify_cookie);
}

void BioCtrlForUdpDtls(BIO *bio, int recv_timeout) {
    struct timeval timeout;
    timeout.tv_sec = recv_timeout;
    timeout.tv_usec = 0;
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
}

char* UdpDtlsListen(SSL *ssl, int fd) {
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} client_addr;
    memset(&client_addr, 0, sizeof(struct sockaddr_storage));

    while (DTLSv1_listen(ssl, (BIO_ADDR *) &client_addr) <= 0);

    //Get Peer addr: ip:port
    char addrbuf[INET6_ADDRSTRLEN];
    sprintf(peer_addr, "%s:%d", inet_ntop(AF_INET, &client_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN), ntohs(client_addr.s4.sin_port));
    // DEBUG
    if (1) {
        printf ("accepted connection from %s\n", peer_addr);
    }

	if (connect(fd, (struct sockaddr *) &client_addr, sizeof(struct sockaddr_in))) {
		printf("Failed to connect.");
		return NULL;
	}
    //BIO_set_fd(SSL_get_rbio(ssl), info.fd, BIO_NOCLOSE);
    BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &client_addr.ss);

    return peer_addr;
}
 */
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

// UdpDtlsConn .
type UdpDtlsConn struct {
	*SSL
	Fd      int
	bio     *Bio
	Raddr   string
}

func UdpDtlsAccept(ctx *Ctx, port uint16) (conn *UdpDtlsConn) {
	ssl := &SSL{}

	accept := C.DtlsUdpAccept(ctx.ctx, port)

	raddr := make([]byte, 128)
	ssl.ssl = C.peer_connect_handle(accept, unsafe.Pointer(&raddr[0]))
	if ssl.ssl == nil {
		return
	}
	conn = &UdpDtlsConn{
		SSL: ssl,
	}
	return
}

func (c *UdpDtlsConn) Read(b []byte) (n int, err error) {
	rv, _ := C.SSL_read(c.ssl, unsafe.Pointer(&b[0]), C.int(len(b)))
	if rv <=  0 {
		return rv, errors.New("Failed to SSL_read")
	}
	return int(rv), nil
}

func (c *UdpDtlsConn) Write(b []byte) (n int, err error) {
	rv, _ := C.SSL_write(c.ssl, unsafe.Pointer(&b[0]), C.int(len(b)))
	if rv <=  0 {
		return rv, errors.New("Failed to SSL_write")
	}
	return int(rv), nil
}

func UdpDtlstest(cert, key string) (err error) {
	ctx, err := NewCtxFromFiles(cert, key, DTLSv1_2)
	if err != nil || ctx == nil {
		err = fmt.Errorf("cannot create context from cert files %s and %s; err: %v", cert, key, err)
		return
	}

	C.UpdateUdpDtlsCtxBaseCfg(ctx.ctx)
	ctx.SetVerify(VerifyPeer|VerifyFailIfNoPeerCert, nil)
	ctx.SetReadAhead(1)

	//Todo: tbd
	//ctx.SetCipherList()

	for {
		fd := C.new_socket(4444);
		if (fd <= 0) {
			return errors.New("Failed to new_socket.");
		}
		ssl := &SSL{}
		ssl.ssl = C.SSL_new(ctx.ctx)
		ssl.SetOptions(CookieExchange)

		//BIO_NOCLOSE == 0; BIO_CLOSE == 1;
		bio := NewBioDgramUdp(ssl, int(fd), 0)
		C.BioCtrlForUdpDtls(bio.bio, 5)

		raddr := C.UdpDtlsListen(ssl.ssl)

		conn := &UdpDtlsConn{
			SSL: ssl,
			Fd: int(fd),
			bio: bio,
			Raddr: C.GoString(raddr),
		}

		go func() {
			var res int = 0
			for(res <= 0) {
				// TODO: optimize
				res = C.SSL_accept(conn.ssl)
			}
			C.BioCtrlForUdpDtls(bio.bio, 5)

			for {
				buf := make([]byte, 1000)
				n, err := conn.Read(buf)
				if err != nil {
					fmt.Printf("Failed to conn.Read, Err: %v\n", err)
				} else {
					fmt.Printf("Receive msg from %s, msg[%d]:%v\n", conn.Raddr, n, buf)
					_, err = conn.Write([]byte("OK"))
					if err != nil {
						fmt.Printf("Failed to conn.Write, Err: %v\n", err)
					}
				}
			}
		}()
	}
}


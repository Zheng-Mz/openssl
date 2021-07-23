package openssl

// #include "shim.h"
/*
extern void StartGoFunc();
void handleFn(void *bio, void *context, void *buf) {
	printf(" handleFn called");
}
*/
import "C"

import (
	"errors"
	"fmt"
	"github.com/spacemonkeygo/openssl/utils"
	"gitlab.casa-systems.com/opensource/sctp"
	"io"
	"sync"
	"unsafe"
)

// DtlsConn .
type DtlsConn struct {
	*SSL
	Fd               int
	bio              *Bio
	conn             *sctp.SCTPConn
	ctx              *Ctx // for gc
	into_ssl         *readBio
	from_ssl         *writeBio
	is_shutdown      bool
	mtx              sync.Mutex
	want_read_future *utils.Future
}

// DtlsSCTPListener .
type DtlsSCTPListener struct {
	ln *sctp.SCTPListener
}

// DtlsSctpListen .
func DtlsSctpListen(sctpSocket *sctp.SocketConfig, laddr *sctp.SCTPAddr) (*DtlsSCTPListener, error) {
	ln, err := sctpSocket.Listen("sctp", laddr)
	if err != nil {
		return nil, err
	}
	return &DtlsSCTPListener{
		ln: ln,
	}, nil
}

// GetSctpConn .
func (c *DtlsConn) GetSctpConn() *sctp.SCTPConn {
	return c.conn
}

func test([]byte) error {
	fmt.Println("AcceptSCTPExt callback ")
	return nil
}

// AcceptDtlsSCTP .
func (ln *DtlsSCTPListener) AcceptDtlsSCTP(ctx *Ctx, initMsg sctp.InitMsg) (*DtlsConn, error) {

	ssl := &SSL{}

	ssl.ssl = C.SSL_new(ctx.ctx)

	sctpConn, err := ln.ln.AcceptSCTP()
	if err != nil {
		fmt.Println("AcceptSCTP failed", err)
		return nil, err
	}

	/*
	 * We are interested in association change events and we want
	 * to get sctp_sndrcvinfo in each receive.
	 */
	var flags int
	flags |= sctp.SCTP_EVENT_DATA_IO
	flags |= sctp.SCTP_EVENT_ASSOCIATION
	flags |= sctp.SCTP_EVENT_SEND_FAILURE
	flags |= sctp.SCTP_EVENT_SHUTDOWN
	flags |= sctp.SCTP_EVENT_AUTHENTICATION

	sctpConn.SubscribeEvents(flags)

	bio := NewBioDgramSctp(ssl, sctpConn.GetSocketFd(), 0)

	c := &DtlsConn{
		SSL:      ssl,
		Fd:       sctpConn.GetSocketFd(),
		conn:     sctpConn,
		bio:      bio,
		ctx:      ctx,
		into_ssl: &readBio{},
		from_ssl: &writeBio{},
	}

	sctpConn.SetInitMsg(int(initMsg.NumOstreams), int(initMsg.MaxInstreams), int(initMsg.MaxAttempts), int(initMsg.MaxInitTimeout))
	// TODO check to make sure this call is blocking (if bio is set to block)
	// ensure that the dtls handshake is completed before this function returns
	C.SSL_set_accept_state(c.ssl)
	_ = C.SSL_accept(c.ssl)

	return c, err
}

func (ln *DtlsSCTPListener) Close() error {
	return ln.ln.Close()
}

func (c *DtlsConn) shutdownLoop() error {
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

// Close dtls conn
func (c *DtlsConn) Close() error {

	c.conn.Close()
	c.is_shutdown = true
	var errs utils.ErrorGroup
	errs.Add(c.shutdownLoop())
	errs.Add(c.conn.Close())
	return errs.Finalize()
}

//Read
func (c *DtlsConn) Read(b []byte, rcvInfo *BioDgramSctpRcvinfo) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	err = tryAgain
	for err == tryAgain {
		n, errcb := c.read(b, rcvInfo)
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

//read
func (c *DtlsConn) read(b []byte, rcvInfo *BioDgramSctpRcvinfo) (int, func() error) {

	if c.is_shutdown {
		return 0, func() error { return io.EOF }
	}
	BioCtrlGetSCTPRcvInfo(c.bio, rcvInfo)

	rv, errno := C.SSL_read(c.ssl, unsafe.Pointer(&b[0]), C.int(len(b)))
	if rv > 0 {
		return int(rv), nil
	}

	return 0, c.getErrorHandler(rv, errno)
}

//Write
func (c *DtlsConn) Write(b []byte, sndInfo *BioDgramSctpSndinfo) (written int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	err = tryAgain
	for err == tryAgain {
		n, errcb := c.write(b, sndInfo)
		err = c.handleError(errcb)
		if err == nil {
			return n, c.flushOutputBuffer()
		}
	}
	return 0, err
}

//write
func (c *DtlsConn) write(b []byte, sndInfo *BioDgramSctpSndinfo) (int, func() error) {

	if c.is_shutdown {
		err := errors.New("connection closed")
		return 0, func() error { return err }
	}
	BioCtrlSetSCTPSndInfo(c.bio, sndInfo)
	rv, errno := C.SSL_write(c.ssl, unsafe.Pointer(&b[0]), C.int(len(b)))
	if rv > 0 {
		return int(rv), nil
	}

	return 0, c.getErrorHandler(rv, errno)
}

func (c *DtlsConn) fillInputBuffer() error {
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
}

func (c *DtlsConn) flushOutputBuffer() error {
	_, err := c.from_ssl.WriteTo(c.conn)
	return err
}

func (c *DtlsConn) getErrorHandler(rv C.int, errno error) func() error {
	errcode := C.SSL_get_error(c.ssl, rv)
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
func (c *DtlsConn) handleError(errcb func() error) error {
	if errcb != nil {
		return errcb()
	}
	return nil
}
func (c *DtlsConn) SctpNotificationCb() int {
	//C.BIO_dgram_sctp_notification_cb(c.bio, C.BIO_dgram_sctp_notification_handler_FN(C.handleFn), unsafe.Pointer(c.SSL))
	BIODgramSctpNotificationCB(c.bio, c.SSL)
	fmt.Println("BIO_dgram_sctp_notification_cb")
	return 0
}

func SctpNotificationHandleCb(bio *C.BIO, context unsafe.Pointer, buf unsafe.Pointer) {
	fmt.Println("SctpNotificationHandleCb")
}

func BIODgramSctpNotificationCB(b *Bio, sslContext *SSL) (rspcode int) {
	C.BIO_dgram_sctp_notification_cb(b.bio, C.BIO_dgram_sctp_notification_handler_FN(C.handleFn), unsafe.Pointer(sslContext))
	//return int(i)
	return rspcode
}

package proxy

import (
	"io"
	"net"
)

// bridge copies data between two connections concurrently until both sides
// are done. It attempts a half-close after each direction finishes so the
// peer gets a clean EOF without killing the other direction prematurely.
func bridge(a, b net.Conn) {
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(a, b)
		closeWrite(a)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(b, a)
		closeWrite(b)
		done <- struct{}{}
	}()

	<-done
	<-done
}

type halfCloser interface {
	CloseWrite() error
}

func closeWrite(c net.Conn) {
	if hc, ok := c.(halfCloser); ok {
		hc.CloseWrite()
	} else {
		c.Close()
	}
}

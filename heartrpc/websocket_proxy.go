/*
Copyright (C) 2015-2018 Lightning Labs and The Lightning Network Developers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package heartrpc

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
	"golang.org/x/net/context"
)

const (
	MethodOverrideParam        = "method"
	HeaderWebSocketProtocol    = "Sec-Websocket-Protocol"
	WebSocketProtocolDelimiter = "+"
)

var (
	BitswarmdClientStreamingURIs = []*regexp.Regexp{}
	defaultHeadersToForward      = map[string]bool{
		"Origin":                 true,
		"Referer":                true,
		"Grpc-Metadata-Macaroon": true,
	}
	defaultProtocolsToAllow = map[string]bool{
		"Grpc-Metadata-Macaroon": true,
	}
)

type WebsocketProxy struct {
	backend             http.Handler
	logger              *zerolog.Logger
	upgrader            *websocket.Upgrader
	clientStreamingURIs []*regexp.Regexp
	pingInterval        time.Duration
	pongWait            time.Duration
}

type requestForwardingReader struct {
	io.Reader
	io.Writer

	pipeR *io.PipeReader
	pipeW *io.PipeWriter
}

type responseForwardingWriter struct {
	io.Writer
	*bufio.Scanner

	pipeR *io.PipeReader
	pipeW *io.PipeWriter

	header http.Header
	code   int
	closed chan bool
}

// NewWebSocketProxy attempts to expose the underlying handler as a response-
// streaming WebSocket stream with newline-delimited JSON as the content
// encoding. If pingInterval is a non-zero duration, a ping message will be
// sent out periodically and a pong response message is expected from the
// client. The clientStreamingURIs parameter can hold a list of all patterns
// for URIs that are mapped to client-streaming RPC methods. We need to keep
// track of those to make sure we initialize the request body correctly for the
// underlying grpc-gateway library.
func NewWebSocketProxy(h http.Handler, logger *zerolog.Logger, pingInterval, pongWait time.Duration) http.Handler {
	p := &WebsocketProxy{
		backend: h,
		logger:  logger,
		upgrader: &websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		clientStreamingURIs: BitswarmdClientStreamingURIs,
	}
	if pingInterval > 0 && pongWait > 0 {
		p.pingInterval = pingInterval
		p.pongWait = pongWait
	}
	return p
}

// pingPongEnabled returns true if a ping interval is set to enable sending and
// expecting regular ping/pong messages.
func (p *WebsocketProxy) pingPongEnabled() bool {
	return p.pingInterval > 0 && p.pongWait > 0
}

// ServeHTTP handles the incoming HTTP request. If the request is an
// "upgradeable" WebSocket request (identified by header fields), then the
// WS proxy handles the request. Otherwise the request is passed directly to the
// underlying REST proxy.
func (p *WebsocketProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !websocket.IsWebSocketUpgrade(r) {
		p.backend.ServeHTTP(w, r)
		return
	}
	p.upgradeToWebSocketProxy(w, r)
}

// upgradeToWebSocketProxy upgrades the incoming request to a WebSocket, reads
// one incoming message then streams all responses until either the client or
// server quit the connection.
func (p *WebsocketProxy) upgradeToWebSocketProxy(w http.ResponseWriter,
	r *http.Request) {

	conn, err := p.upgrader.Upgrade(w, r, nil)
	if err != nil {
		p.logger.Error().Msg(fmt.Sprintf("error upgrading websocket: %v", err))
		return
	}
	defer func() {
		err := conn.Close()
		if err != nil && !IsClosedConnError(err) {
			p.logger.Error().Msg(fmt.Sprintf("WS: error closing upgraded conn: %v", err))
		}
	}()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	requestForwarder := newRequestForwardingReader()
	request, err := http.NewRequestWithContext(
		r.Context(), r.Method, r.URL.String(), requestForwarder,
	)
	if err != nil {
		p.logger.Error().Msg(fmt.Sprintf("WS: error preparing request: %v", err))
		return
	}

	// Allow certain headers to be forwarded, either from source headers
	// or the special Sec-Websocket-Protocol header field.
	forwardHeaders(r.Header, request.Header)

	// Also allow the target request method to be overwritten, as all
	// WebSocket establishment calls MUST be GET requests.
	if m := r.URL.Query().Get(MethodOverrideParam); m != "" {
		request.Method = m
	}

	// Is this a call to a client-streaming RPC method?
	clientStreaming := false
	for _, pattern := range p.clientStreamingURIs {
		if pattern.MatchString(r.URL.Path) {
			clientStreaming = true
		}
	}

	responseForwarder := newResponseForwardingWriter()
	go func() {
		<-ctx.Done()
		responseForwarder.Close()
	}()

	go func() {
		defer cancelFn()
		p.backend.ServeHTTP(responseForwarder, request)
	}()

	// Read loop: Take messages from websocket and write to http request.
	go func() {
		defer cancelFn()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			_, payload, err := conn.ReadMessage()
			if err != nil {
				if IsClosedConnError(err) {
					p.logger.Trace().Msg(fmt.Sprintf("WS: socket "+
						"closed: %v", err))
					return
				}
				p.logger.Error().Msg(fmt.Sprintf("error reading message: %v", err))
				return
			}
			_, err = requestForwarder.Write(payload)
			if err != nil {
				p.logger.Error().Msg(fmt.Sprintf("WS: error writing message to upstream http server: %v", err))
				return
			}
			_, _ = requestForwarder.Write([]byte{'\n'})

			// The grpc-gateway library uses a different request
			// reader depending on whether it is a client streaming
			// RPC or not. For a non-streaming request we need to
			// close with EOF to signal the request was completed.
			if !clientStreaming {
				requestForwarder.CloseWriter()
			}
		}
	}()

	// Ping write loop: Send a ping message regularly if ping/pong is
	// enabled.
	if p.pingPongEnabled() {
		// We'll send out our first ping in pingInterval. So the initial
		// deadline is that interval plus the time we allow for a
		// response to be sent.
		initialDeadline := time.Now().Add(p.pingInterval + p.pongWait)
		_ = conn.SetReadDeadline(initialDeadline)

		// Whenever a pong message comes in, we extend the deadline
		// until the next read is expected by the interval plus pong
		// wait time.
		conn.SetPongHandler(func(appData string) error {
			nextDeadline := time.Now().Add(
				p.pingInterval + p.pongWait,
			)
			_ = conn.SetReadDeadline(nextDeadline)
			return nil
		})
		go func() {
			ticker := time.NewTicker(p.pingInterval)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					p.logger.Debug().Msg("WS: ping loop done")
					return

				case <-ticker.C:
					// Writing the ping shouldn't take any
					// longer than we'll wait for a response
					// in the first place.
					writeDeadline := time.Now().Add(
						p.pongWait,
					)
					_ = conn.SetWriteDeadline(writeDeadline)

					err := conn.WriteMessage(
						websocket.PingMessage, nil,
					)
					if err != nil {
						p.logger.Warn().Msg(fmt.Sprintf("WS: could not "+
							"send ping message: %v",
							err))
						return
					}
				}
			}
		}()
	}

	// Write loop: Take messages from the response forwarder and write them
	// to the WebSocket.
	for responseForwarder.Scan() {
		if len(responseForwarder.Bytes()) == 0 {
			p.logger.Error().Msg(fmt.Sprintf("WS: empty scan: %v",
				responseForwarder.Err()))

			continue
		}

		err = conn.WriteMessage(
			websocket.TextMessage, responseForwarder.Bytes(),
		)
		if err != nil {
			p.logger.Error().Msg(fmt.Sprintf("WS: error writing message: %v", err))
			return
		}
	}
	if err := responseForwarder.Err(); err != nil && !IsClosedConnError(err) {
		p.logger.Error().Msg(fmt.Sprintf("WS: scanner err: %v", err))
	}
}

// forwardHeaders forwards certain allowed header fields from the source request
// to the target request. Because browsers are limited in what header fields
// they can send on the WebSocket setup call, we also allow additional fields to
// be transported in the special Sec-Websocket-Protocol field.
func forwardHeaders(source, target http.Header) {
	// Forward allowed header fields directly.
	for header := range source {
		headerName := textproto.CanonicalMIMEHeaderKey(header)
		if forward, ok := defaultHeadersToForward[headerName]; ok && forward {
			target.Set(headerName, source.Get(header))
		}
	}

	// Browser aren't allowed to set custom header fields on WebSocket
	// requests. We need to allow them to submit the macaroon as a WS
	// protocol, which is the only allowed header. Set any "protocols" we
	// declare valid as header fields on the forwarded request.
	protocol := source.Get(HeaderWebSocketProtocol)
	for key := range defaultProtocolsToAllow {
		if strings.HasPrefix(protocol, key) {
			// The format is "<protocol name>+<value>". We know the
			// protocol string starts with the name so we only need
			// to set the value.
			values := strings.Split(
				protocol, WebSocketProtocolDelimiter,
			)
			target.Set(key, values[1])
		}
	}
}

// IsClosedConnError is a helper function that returns true if the given error
// is an error indicating we are using a closed connection.
func IsClosedConnError(err error) bool {
	if err == nil {
		return false
	}
	if err == http.ErrServerClosed {
		return true
	}

	str := err.Error()
	if strings.Contains(str, "use of closed network connection") {
		return true
	}
	if strings.Contains(str, "closed pipe") {
		return true
	}
	if strings.Contains(str, "broken pipe") {
		return true
	}
	if strings.Contains(str, "connection reset by peer") {
		return true
	}
	return websocket.IsCloseError(
		err, websocket.CloseNormalClosure, websocket.CloseGoingAway,
	)
}

// newResponseForwardingWriter creates a new http.ResponseWriter that intercepts
// what's written to it and presents it through a bufio.Scanner interface.
func newResponseForwardingWriter() *responseForwardingWriter {
	r, w := io.Pipe()
	return &responseForwardingWriter{
		Writer:  w,
		Scanner: bufio.NewScanner(r),
		pipeR:   r,
		pipeW:   w,
		header:  http.Header{},
		closed:  make(chan bool, 1),
	}
}

// newRequestForwardingReader creates a new request forwarding pipe.
func newRequestForwardingReader() *requestForwardingReader {
	r, w := io.Pipe()
	return &requestForwardingReader{
		Reader: r,
		Writer: w,
		pipeR:  r,
		pipeW:  w,
	}
}

// CloseWriter closes the underlying pipe writer.
func (r *requestForwardingReader) CloseWriter() {
	_ = r.pipeW.CloseWithError(io.EOF)
}

// Write writes the given bytes to the internal pipe.
//
// NOTE: This is part of the http.ResponseWriter interface.
func (w *responseForwardingWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

// Header returns the HTTP header fields intercepted so far.
//
// NOTE: This is part of the http.ResponseWriter interface.
func (w *responseForwardingWriter) Header() http.Header {
	return w.header
}

// WriteHeader indicates that the header part of the response is now finished
// and sets the response code.
//
// NOTE: This is part of the http.ResponseWriter interface.
func (w *responseForwardingWriter) WriteHeader(code int) {
	w.code = code
}

// CloseNotify returns a channel that indicates if a connection was closed.
//
// NOTE: This is part of the http.CloseNotifier interface.
func (w *responseForwardingWriter) CloseNotify() <-chan bool {
	return w.closed
}

// Flush empties all buffers. We implement this to indicate to our backend that
// we support flushing our content. There is no actual implementation because
// all writes happen immediately, there is no internal buffering.
//
// NOTE: This is part of the http.Flusher interface.
func (w *responseForwardingWriter) Flush() {}

func (w *responseForwardingWriter) Close() {
	_ = w.pipeR.CloseWithError(io.EOF)
	_ = w.pipeW.CloseWithError(io.EOF)
	w.closed <- true
}

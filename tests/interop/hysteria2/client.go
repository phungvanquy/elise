// Interoperability fixture using the exact Hysteria core pinned by V2bX.
package main

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/extras/v2/obfs"
)

type obfsFactory struct{}

func (obfsFactory) New(_ net.Addr) (net.PacketConn, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	wrapped, err := obfs.WrapPacketConnSalamander(conn, []byte("fixture-obfs"))
	if err != nil {
		conn.Close()
	}
	return wrapped, err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	server, err := net.ResolveUDPAddr("udp", os.Args[1])
	if err != nil {
		return err
	}
	cert, err := os.ReadFile(os.Args[2])
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		return fmt.Errorf("invalid fixture certificate")
	}
	rx, _ := strconv.ParseUint(os.Args[6], 10, 64)
	tx, _ := strconv.ParseUint(os.Args[7], 10, 64)
	expectedTx, _ := strconv.ParseUint(os.Args[8], 10, 64)
	expectedRx, _ := strconv.ParseUint(os.Args[10], 10, 64)
	config := &client.Config{
		ServerAddr: server, Auth: "fixture", FastOpen: os.Args[9] == "true",
		TLSConfig:       client.TLSConfig{ServerName: "localhost", RootCAs: roots},
		BandwidthConfig: client.BandwidthConfig{MaxRx: rx, MaxTx: tx},
	}
	if os.Args[5] == "salamander" {
		config.ConnFactory = obfsFactory{}
	}
	proxy, handshake, err := client.NewClient(config)
	if err != nil {
		return fmt.Errorf("authenticate: %w", err)
	}
	defer proxy.Close()
	if !handshake.UDPEnabled || handshake.Tx != expectedTx {
		return fmt.Errorf("negotiated UDP=%v TX=%d, want true/%d", handshake.UDPEnabled, handshake.Tx, expectedTx)
	}

	// Exercise concurrent TCP streams, including clients that wait for the
	// TCPResponse before writing the application bytes required by sniffing.
	started := time.Now()
	var wg sync.WaitGroup
	errors := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, err := proxy.TCP(os.Args[3])
			if err != nil {
				errors <- err
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			payload := append([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"), bytes.Repeat([]byte{byte(i + 1)}, 256*1024)...)
			if _, err = conn.Write(payload); err != nil {
				errors <- err
				return
			}
			reply := make([]byte, len(payload))
			if _, err = io.ReadFull(conn, reply); err != nil {
				errors <- err
				return
			}
			if !bytes.Equal(payload, reply) {
				errors <- fmt.Errorf("TCP stream %d corrupted", i)
			}
		}(i)
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			return err
		}
	}
	if expectedRx > 0 {
		elapsed := time.Since(started)
		budget := time.Duration(float64(4*256*1024) / float64(expectedRx) * float64(time.Second))
		// Allow scheduling/QUIC overhead while catching an ignored rate limit or
		// a tiny congestion window that stalls on delayed ACKs at loopback RTT.
		if elapsed < budget/2 || elapsed > 3*budget+time.Second {
			return fmt.Errorf("TCP throughput outside negotiated rate budget: elapsed=%s, nominal=%s", elapsed, budget)
		}
	}
	// Sniffed names must still reach the audit rules with fast open disabled.
	// Before the server sends an early TCPResponse, sniffing times out without
	// seeing these bytes and the request incorrectly reaches the echo server.
	blocked, err := proxy.TCP(os.Args[3])
	if err != nil {
		return err
	}
	blocked.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = blocked.Write([]byte("GET / HTTP/1.1\r\nHost: blocked.test\r\n\r\n"))
	if err != nil {
		blocked.Close()
		return err
	}
	var byteReply [1]byte
	n, err := blocked.Read(byteReply[:])
	blocked.Close()
	if n != 0 || err == nil {
		return fmt.Errorf("sniffed block rule was bypassed or a second TCPResponse leaked into the stream")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		return fmt.Errorf("blocked TCP stream was left open")
	}

	udp, err := proxy.UDP()
	if err != nil {
		return err
	}
	defer udp.Close()
	// The default Go client omits max_datagram_frame_size to imitate Chrome.
	// Responses must still work, including multi-fragment packets and reuse.
	// The Go client limits the serialized message (including its header) to
	// 4096 bytes. 4000 bytes exercises four fragments within that limit.
	for _, size := range []int{64, 1500, 4000, 64} {
		payload := bytes.Repeat([]byte{byte(size / 64)}, size)
		if err := udp.Send(payload, os.Args[4]); err != nil {
			return err
		}
		type result struct {
			data []byte
			addr string
			err  error
		}
		received := make(chan result, 1)
		go func() { data, addr, err := udp.Receive(); received <- result{data, addr, err} }()
		select {
		case reply := <-received:
			if reply.err != nil {
				return reply.err
			}
			if !bytes.Equal(payload, reply.data) || reply.addr != os.Args[4] {
				return fmt.Errorf("UDP %d-byte response corrupted: %d bytes from %s", size, len(reply.data), reply.addr)
			}
		case <-time.After(5 * time.Second):
			return fmt.Errorf("UDP %d-byte response timed out", size)
		}
	}
	fmt.Printf("TCP concurrent 1 MiB + UDP roundtrips: %s\n", time.Since(started))
	return nil
}

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
	_ "github.com/metacubex/mihomo/dns"
)

func main() {
	host, portText, err := net.SplitHostPort(os.Args[1])
	if err != nil {
		panic(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		panic(err)
	}
	mode := os.Args[2]
	options := map[string]any{"host": "localhost", "path": "/api/v1/sync", "mode": mode}
	if mode == "packet-header" || mode == "packet-body" {
		options["mode"] = "packet-up"
		options["sc-max-each-post-bytes"] = "2048"
		options["sc-min-posts-interval-ms"] = "1"
	}
	if mode == "packet-header" {
		for key, value := range map[string]any{
			"uplink-http-method": "GET", "uplink-data-placement": "header", "uplink-data-key": "X-Data",
			"uplink-chunk-size": "2048", "x-padding-bytes": "100-1000", "x-padding-obfs-mode": true,
			"x-padding-placement": "queryInHeader", "x-padding-header": "X-Padding",
			"x-padding-key": "x_padding", "x-padding-method": "repeat-x",
		} {
			options[key] = value
		}
	}
	proxy, err := adapter.ParseProxy(map[string]any{
		"name": "local-interop", "type": "vless", "server": host, "port": port,
		"uuid": "6a9ecf20-44b2-4fc2-a3a0-4dcda7b2c3eb", "network": "xhttp", "tls": true,
		"servername": "localhost", "skip-cert-verify": true, "alpn": []string{os.Args[3]}, "xhttp-opts": options,
	})
	if err != nil {
		panic(err)
	}
	defer proxy.Close()
	var wait sync.WaitGroup
	errors := make(chan error, 4)
	for range 4 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errors <- transfer(proxy)
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			panic(err)
		}
	}
	fmt.Println("4 concurrent VLESS sessions echoed 64 KiB each")
}

func transfer(proxy C.Proxy) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Type: C.INNER, Host: "echo.invalid", DstPort: 80})
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	payload := make([]byte, 64*1024)
	if _, err := rand.Read(payload); err != nil {
		return err
	}
	written := make(chan error, 1)
	go func() { _, err := io.Copy(conn, bytes.NewReader(payload)); written <- err }()
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if err := <-written; err != nil {
		return err
	}
	if !bytes.Equal(payload, response) {
		return fmt.Errorf("echo payload mismatch")
	}
	return nil
}

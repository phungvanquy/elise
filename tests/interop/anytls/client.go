// Exercise the AnyTLS wire protocol over a REALITY handshake made by uTLS.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
)

const (
	cmdSYN      = 1
	cmdPSH      = 2
	cmdFIN      = 3
	cmdSettings = 4
	cmdAlert    = 5
	cmdSYNACK   = 7
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 8 {
		return errors.New("usage: client server public-key short-id password target expected-alpn proxy")
	}
	conn, err := net.DialTimeout("tcp", os.Args[1], 3*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		return err
	}
	if err := proxyHeader(conn, os.Args[7]); err != nil {
		return err
	}
	publicBytes, err := base64.RawURLEncoding.DecodeString(os.Args[2])
	if err != nil {
		return err
	}
	public, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		return err
	}
	shortID, err := hex.DecodeString(os.Args[3])
	if err != nil || len(shortID) > 8 {
		return errors.New("invalid short ID")
	}
	var authKey []byte
	client := utls.UClient(conn, &utls.Config{
		ServerName: "localhost", InsecureSkipVerify: true, SessionTicketsDisabled: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("missing REALITY certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			key, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return errors.New("REALITY certificate must use Ed25519")
			}
			mac := hmac.New(sha512.New, authKey)
			mac.Write(key)
			if !hmac.Equal(mac.Sum(nil), cert.Signature) {
				return errors.New("REALITY certificate authentication failed")
			}
			return nil
		},
	}, utls.HelloChrome_120)
	if err := client.BuildHandshakeState(); err != nil {
		return err
	}
	hello := client.HandshakeState.Hello
	if len(hello.SessionId) != 32 || client.HandshakeState.State13.KeyShareKeys == nil || client.HandshakeState.State13.KeyShareKeys.Ecdhe == nil {
		return errors.New("uTLS did not produce the required X25519 ClientHello")
	}
	shared, err := client.HandshakeState.State13.KeyShareKeys.Ecdhe.ECDH(public)
	if err != nil {
		return err
	}
	authKey = make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, hello.Random[:20], []byte("REALITY")), authKey); err != nil {
		return err
	}
	clear(hello.Raw[39:71])
	var plaintext [16]byte
	copy(plaintext[:3], []byte{1, 8, 0})
	binary.BigEndian.PutUint32(plaintext[4:8], uint32(time.Now().Unix()))
	copy(plaintext[8:], shortID)
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	hello.SessionId = aead.Seal(hello.SessionId[:0], hello.Random[20:], plaintext[:], hello.Raw)
	copy(hello.Raw[39:71], hello.SessionId)
	if err := client.Handshake(); err != nil {
		return fmt.Errorf("REALITY handshake: %w", err)
	}
	if client.ConnectionState().NegotiatedProtocol != os.Args[6] {
		return fmt.Errorf("ALPN = %q, expected %q", client.ConnectionState().NegotiatedProtocol, os.Args[6])
	}
	fmt.Println("REALITY certificate verified")
	password := sha256.Sum256([]byte(os.Args[4]))
	if _, err := client.Write(append(password[:], 0, 5, 'p', 'a', 'd', '!', '!')); err != nil {
		return err
	}
	if err := writeFrame(client, cmdSettings, 0, []byte("v=2\n")); err != nil {
		return err
	}
	target, err := net.ResolveTCPAddr("tcp", os.Args[5])
	if err != nil {
		return err
	}
	payloads := [][]byte{[]byte("first-stream"), []byte("second-stream")}
	for i, payload := range payloads {
		id := uint32(i + 1)
		if err := writeFrame(client, cmdSYN, id, nil); err != nil {
			return err
		}
		request := append([]byte{1}, target.IP.To4()...)
		request = binary.BigEndian.AppendUint16(request, uint16(target.Port))
		request = append(request, payload...)
		if err := writeFrame(client, cmdPSH, id, request); err != nil {
			return err
		}
	}
	var received [2][]byte
	var acked [2]bool
	for len(received[0]) < len(payloads[0]) || len(received[1]) < len(payloads[1]) {
		var header [7]byte
		if _, err := io.ReadFull(client, header[:]); err != nil {
			return fmt.Errorf("AnyTLS frame: %w", err)
		}
		id := binary.BigEndian.Uint32(header[1:5])
		payload := make([]byte, binary.BigEndian.Uint16(header[5:7]))
		if _, err := io.ReadFull(client, payload); err != nil {
			return err
		}
		if header[0] == cmdAlert {
			return fmt.Errorf("AnyTLS alert: %s", payload)
		}
		if header[0] == cmdPSH || header[0] == cmdSYNACK {
			if id < 1 || id > 2 {
				return fmt.Errorf("unexpected stream %d", id)
			}
			if header[0] == cmdSYNACK {
				if len(payload) != 0 {
					return fmt.Errorf("stream error: %s", payload)
				}
				acked[id-1] = true
			} else {
				received[id-1] = append(received[id-1], payload...)
			}
		}
	}
	for i, payload := range payloads {
		if !acked[i] || string(received[i]) != string(payload) {
			return fmt.Errorf("stream %d failed: %q", i+1, received[i])
		}
		if err := writeFrame(client, cmdFIN, uint32(i+1), nil); err != nil {
			return err
		}
	}
	fmt.Println("REALITY certificate verified; two AnyTLS streams roundtripped")
	return client.Close()
}

func writeFrame(w io.Writer, command byte, id uint32, payload []byte) error {
	frame := binary.BigEndian.AppendUint32([]byte{command}, id)
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(payload)))
	_, err := w.Write(append(frame, payload...))
	return err
}

func proxyHeader(w io.Writer, version string) error {
	var header []byte
	switch version {
	case "off":
		return nil
	case "v1":
		header = []byte("PROXY TCP4 192.0.2.7 127.0.0.1 12345 443\r\n")
	case "v2":
		header = append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x21, 0x11, 0, 12)
		header = append(header, 192, 0, 2, 7, 127, 0, 0, 1, 0x30, 0x39, 0x01, 0xbb)
	default:
		return errors.New("invalid PROXY protocol version")
	}
	_, err := w.Write(header)
	return err
}

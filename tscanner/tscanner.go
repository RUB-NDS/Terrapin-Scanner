// Package tscanner provides a scanner to validate if an ssh client or server is vulnerable to the Terrapin Attack.
// See more details at https://terrapin-attack.com.
package tscanner

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/exp/slices"
)

// ScanMode describes a scan mode for the scanner.
type ScanMode int32

const (
	// ServerScan indicates that the scanner should connect to the provided address and perform a server-side scan.
	ServerScan ScanMode = iota
	// ClientScan indicates that the scanner should listen on the provided address and perform a client-side scan.
	ClientScan
)

const chaCha20Poly1305 = "chacha20-poly1305@openssh.com"
const etmSuffix = "-etm@openssh.com"
const cbcSuffix = "-cbc"
const kexStrictIndicatorClient = "kex-strict-c-v00@openssh.com"
const kexStrictIndicatorServer = "kex-strict-s-v00@openssh.com"

// Report contains the results of a vulnerability scan.
type Report struct {
	// Contains the IP address and port of the scanned peer.
	RemoteAddr string
	// Indicates whether the scanned host was acting as client or server.
	IsServer bool
	// Banner contains the SSH banner of the remote peer.
	Banner string
	// SupportsChaCha20 indicates whether the remote peer supports the ChaCha20-Poly1305 cipher.
	SupportsChaCha20 bool
	// SupportsCbcEtm indicates whether the remote peer supports CBC ciphers with ETM.
	SupportsCbcEtm bool
	// SupportsStrictKex indicates whether the remote peer supports strict key exchange.
	SupportsStrictKex bool
}

// IsVulnerable evaluates whether the report indicates vulnerability to prefix truncation.
func (report *Report) IsVulnerable() bool {
	return (report.SupportsChaCha20 || report.SupportsCbcEtm) && !report.SupportsStrictKex
}

// MarshalJSON marshals the report to JSON.
func (report *Report) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Report
		Vulnerable bool
	}{
		*report,
		report.IsVulnerable(),
	})
}

// Scan performs a vulnerability scan to check whether the remote peer is likely to be vulnerable against prefix truncation.
func Scan(address string, scanMode ScanMode, verbose bool) (*Report, error) {
	return ScanWithTimeout(address, scanMode, verbose, 0)
}

// ScanWithTimeout performs a vulnerability scan with configurable timeout to check whether the remote peer
// is likely to be vulnerable against prefix truncation.
func ScanWithTimeout(address string, scanMode ScanMode, verbose bool, timeout int) (*Report, error) {
	var conn net.Conn
	if scanMode == ServerScan {
		var err error
		dialer := net.Dialer{Timeout: time.Duration(timeout) * time.Second}
		if conn, err = dialer.Dial("tcp", address); err != nil {
			return nil, err
		}
	} else if scanMode == ClientScan {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return nil, err
		}
		defer listener.Close()

		if verbose {
			fmt.Fprintln(os.Stderr, "Listening for incoming client connection on", address)
		}

		if conn, err = listener.Accept(); err != nil {
			return nil, err
		}
	}
	defer conn.Close()
	connrw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	remoteBanner, err := exchangeBanners(connrw)
	if err != nil {
		return nil, err
	}
	remoteKexInit, err := receiveRemoteKexInit(connrw)
	if err != nil {
		return nil, err
	}
	hasSuffix := func(suffix string) func(string) bool {
		return func(s string) bool {
			return strings.HasSuffix(s, suffix)
		}
	}
	report := new(Report)
	report.RemoteAddr = conn.RemoteAddr().String()
	report.IsServer = scanMode == ServerScan
	report.Banner = remoteBanner
	report.SupportsChaCha20 = slices.Contains(remoteKexInit.EncryptionAlgorithmsClientToServer, chaCha20Poly1305) ||
		slices.Contains(remoteKexInit.EncryptionAlgorithmsServerToClient, chaCha20Poly1305)
	report.SupportsCbcEtm =
		(slices.ContainsFunc(remoteKexInit.EncryptionAlgorithmsClientToServer, hasSuffix(cbcSuffix)) &&
			slices.ContainsFunc(remoteKexInit.MacAlgorithmsClientToServer, hasSuffix(etmSuffix))) ||
			(slices.ContainsFunc(remoteKexInit.EncryptionAlgorithmsServerToClient, hasSuffix(cbcSuffix)) &&
				slices.ContainsFunc(remoteKexInit.MacAlgorithmsServerToClient, hasSuffix(etmSuffix)))
	report.SupportsStrictKex = slices.Contains(remoteKexInit.KexAlgorithms, kexStrictIndicatorServer)
	if scanMode == ClientScan {
		report.SupportsStrictKex = slices.Contains(remoteKexInit.KexAlgorithms, kexStrictIndicatorClient)
	}
	return report, nil
}

type binaryPacket struct {
	PacketLength  uint32
	PaddingLength byte
	Payload       []byte
	Padding       []byte
	Mac           []byte
}

type sshMsgKexInit struct {
	MsgType                             byte
	Cookie                              []byte
	KexAlgorithms                       []string
	ServerHostKeyAlgorithms             []string
	EncryptionAlgorithmsClientToServer  []string
	EncryptionAlgorithmsServerToClient  []string
	MacAlgorithmsClientToServer         []string
	MacAlgorithmsServerToClient         []string
	CompressionAlgorithmsClientToServer []string
	CompressionAlgorithmsServerToClient []string
	LanguagesClientToServer             []string
	LanguagesServerToClient             []string
	FirstKexPacketFollows               bool
	Flags                               uint32
}

// Reads a single incoming, unencrypted binary packet from the provided connection.
// Does not support reading encrypted binary packets.
func readSinglePacket(connrw *bufio.ReadWriter) (*binaryPacket, error) {
	pkt := new(binaryPacket)
	// Read packet length
	pktLengthBytes := make([]byte, 4)
	if _, err := io.ReadFull(connrw, pktLengthBytes); err != nil {
		return nil, fmt.Errorf("error while reading packet length of binary packet: %w", err)
	}
	pkt.PacketLength = binary.BigEndian.Uint32(pktLengthBytes)
	// Any packet length > 35000 bytes can be considered invalid (see RFC4253 Sec. 6.1)
	if pkt.PacketLength > 35000 {
		return nil, fmt.Errorf("packet length is larger than 35000 bytes")
	}
	// Read remaining packet
	pktBytes := make([]byte, pkt.PacketLength)
	if _, err := io.ReadFull(connrw, pktBytes); err != nil {
		return nil, fmt.Errorf("error while reading binary packet: %w", err)
	}
	pkt.PaddingLength = pktBytes[0]
	pkt.Payload = pktBytes[1 : pkt.PacketLength-uint32(pkt.PaddingLength)]
	pkt.Padding = pktBytes[pkt.PacketLength-uint32(pkt.PaddingLength):]
	// Empty MAC
	pkt.Mac = make([]byte, 0)
	return pkt, nil
}

// Performs the SSH banner exchange by sending our banner and receiving the remote peer's banner.
// Ignores leading ASCII lines not starting with SSH- (as per RFC4253 Sec. 4.2).
func exchangeBanners(connrw *bufio.ReadWriter) (string, error) {
	// Send own banner first
	if _, err := connrw.Write([]byte("SSH-2.0-TerrapinVulnerabilityScanner\r\n")); err != nil {
		return "", fmt.Errorf("error while sending SSH banner: %w", err)
	}
	if err := connrw.Flush(); err != nil {
		return "", fmt.Errorf("error while flushing outgoing connection buffer: %w", err)
	}
	// Receive banner from the remote peer
	for {
		line, err := connrw.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("error while reading from connection during banner exchange: %w", err)
		}
		// RFC 4253 allows SSH servers to send additional lines before the banner
		if strings.HasPrefix(line, "SSH-1.99") || strings.HasPrefix(line, "SSH-2.0") {
			line = strings.TrimSpace(line)
			return line, nil
		}
	}
}

// Parses a field of type name-list from the binary packet's payload at position offset.
// Returns either the separated name-list, and the total length of the name-list in bytes
// (including the length), or an error.
func parseNameList(pkt *binaryPacket, offset uint32) ([]string, uint32, error) {
	if uint32(len(pkt.Payload)) < offset+4 {
		return nil, 0, fmt.Errorf("not enough bytes to read name list length")
	}
	lengthBytes := pkt.Payload[offset : offset+4]
	length := binary.BigEndian.Uint32(lengthBytes)
	if uint32(len(pkt.Payload)) < offset+4+length {
		return nil, 0, fmt.Errorf("not enough bytes to read name list")
	}
	nameListBytes := pkt.Payload[offset+4 : offset+4+length]
	nameList := strings.Split(string(nameListBytes), ",")
	return nameList, 4 + length, nil
}

// Parses a message of type SSH_MSG_KEXINIT into the corresponding struct.
func parseKexInit(pkt *binaryPacket) (*sshMsgKexInit, error) {
	msg := new(sshMsgKexInit)
	offset := uint32(0)
	msg.MsgType = pkt.Payload[offset]
	offset += 1
	msg.Cookie = pkt.Payload[offset : offset+16]
	offset += 16
	for i := 0; i < 10; i++ {
		list, length, err := parseNameList(pkt, offset)
		if err != nil {
			return nil, err
		}
		switch i {
		case 0:
			msg.KexAlgorithms = list
		case 1:
			msg.ServerHostKeyAlgorithms = list
		case 2:
			msg.EncryptionAlgorithmsClientToServer = list
		case 3:
			msg.EncryptionAlgorithmsServerToClient = list
		case 4:
			msg.MacAlgorithmsClientToServer = list
		case 5:
			msg.MacAlgorithmsServerToClient = list
		case 6:
			msg.CompressionAlgorithmsClientToServer = list
		case 7:
			msg.CompressionAlgorithmsServerToClient = list
		case 8:
			msg.LanguagesClientToServer = list
		case 9:
			msg.LanguagesServerToClient = list
		}
		offset += length
	}
	msg.FirstKexPacketFollows = binary.BigEndian.Uint32(pkt.Payload[offset:offset+4]) > 0
	offset += 4
	msg.Flags = binary.BigEndian.Uint32(pkt.Payload[offset : offset+4])
	return msg, nil
}

// Receives binary packets until the remote's KEXINIT has been received and returns the parsed message.
func receiveRemoteKexInit(connrw *bufio.ReadWriter) (*sshMsgKexInit, error) {
	for {
		pkt, err := readSinglePacket(connrw)
		if err != nil {
			return nil, err
		}
		if pkt.Payload[0] == 20 {
			return parseKexInit(pkt)
		}
	}
}

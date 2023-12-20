package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/fatih/color"
	"io"
	"net"
	"os"
	"slices"
	"strings"
)

const ChaCha20Poly1305 = "chacha20-poly1305@openssh.com"
const EtmSuffix = "-etm@openssh.com"
const CbcSuffix = "-cbc"
const KexStrictIndicatorClient = "kex-strict-c-v00@openssh.com"
const KexStrictIndicatorServer = "kex-strict-s-v00@openssh.com"

type ScanMode int32

const (
	ServerScan ScanMode = iota
	ClientScan
)

type BinaryPacket struct {
	PacketLength  uint32
	PaddingLength byte
	Payload       []byte
	Padding       []byte
	Mac           []byte
}

type SshMsgKexInit struct {
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

type TerrapinVulnerabilityReport struct {
	Banner            string
	SupportsChaCha20  bool
	SupportsCbcEtm    bool
	SupportsStrictKex bool
}

// IsVulnerable evaluates whether the report indicates vulnerability to prefix truncation.
func (report *TerrapinVulnerabilityReport) IsVulnerable() bool {
	return (report.SupportsChaCha20 || report.SupportsCbcEtm) && !report.SupportsStrictKex
}

func (report *TerrapinVulnerabilityReport) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		TerrapinVulnerabilityReport
		Vulnerable bool
	}{
		*report,
		report.IsVulnerable(),
	})
}

// Reads a single incoming, unencrypted binary packet from the provided connection.
// Does not support reading encrypted binary packets.
func readSinglePacket(connrw *bufio.ReadWriter) (*BinaryPacket, error) {
	pkt := new(BinaryPacket)
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
func parseNameList(pkt *BinaryPacket, offset uint32) ([]string, uint32, error) {
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
func parseKexInit(pkt *BinaryPacket) (*SshMsgKexInit, error) {
	msg := new(SshMsgKexInit)
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
func receiveRemoteKexInit(connrw *bufio.ReadWriter) (*SshMsgKexInit, error) {
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

// Performs a vulnerability scan to check whether the remote peer is likely to be vulnerable against prefix truncation.
func performVulnerabilityScan(address string, scanMode ScanMode) (*TerrapinVulnerabilityReport, error) {
	var conn net.Conn
	if scanMode == ServerScan {
		var err error
		if conn, err = net.Dial("tcp", address); err != nil {
			return nil, err
		}
	} else if scanMode == ClientScan {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return nil, err
		}
		defer listener.Close()
		fmt.Fprintln(os.Stderr, "Listening for incoming client connection on", address)

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
	report := new(TerrapinVulnerabilityReport)
	report.Banner = remoteBanner
	report.SupportsChaCha20 = slices.Contains(remoteKexInit.EncryptionAlgorithmsClientToServer, ChaCha20Poly1305) ||
		slices.Contains(remoteKexInit.EncryptionAlgorithmsServerToClient, ChaCha20Poly1305)
	report.SupportsCbcEtm =
		(slices.ContainsFunc(remoteKexInit.EncryptionAlgorithmsClientToServer, hasSuffix(CbcSuffix)) &&
			slices.ContainsFunc(remoteKexInit.MacAlgorithmsClientToServer, hasSuffix(EtmSuffix))) ||
			(slices.ContainsFunc(remoteKexInit.EncryptionAlgorithmsServerToClient, hasSuffix(CbcSuffix)) &&
				slices.ContainsFunc(remoteKexInit.MacAlgorithmsServerToClient, hasSuffix(EtmSuffix)))
	report.SupportsStrictKex = slices.Contains(remoteKexInit.KexAlgorithms, KexStrictIndicatorServer)
	if scanMode == ClientScan {
		report.SupportsStrictKex = slices.Contains(remoteKexInit.KexAlgorithms, KexStrictIndicatorClient)
	}
	return report, nil
}

// Formats a socket address given the scan mode
func formatAddress(address string, mode ScanMode) string {
	formatted := strings.TrimSpace(address)
	switch mode {
	case ServerScan:
		if (strings.HasPrefix(formatted, "[") && strings.HasSuffix(formatted, "]")) ||
			!strings.Contains(formatted, ":") {
			// Literal IPv6 / IPv4 address or hostname without explicit port, default to port 22
			formatted += ":22"
		}
	case ClientScan:
		if formatted == "" {
			// No bind address and port given, default to binding 127.0.0.1 port 2222
			formatted = "127.0.0.1:2222"
		} else if !strings.Contains(formatted, ":") {
			// Port only, default to binding 127.0.0.1 only
			formatted = "127.0.0.1:" + formatted
		}
	}
	return formatted
}

func printColoredBoolean(value bool, ifTrue color.Attribute, ifFalse color.Attribute) {
	if value {
		color.Set(ifTrue)
	} else {
		color.Set(ifFalse)
	}
	fmt.Printf("%t\n", value)
	color.Unset()
}

// Prints the report to stdout
func printReport(report *TerrapinVulnerabilityReport, outputJson bool) error {
	if !outputJson {
		color.Set(color.FgBlue)
		fmt.Println("================================================================================")
		fmt.Println("==================================== Report ====================================")
		fmt.Println("================================================================================")
		color.Unset()
		fmt.Println()
		fmt.Printf("Remote Banner: %s\n", report.Banner)
		fmt.Println()
		fmt.Print("ChaCha20-Poly1305 support:   ")
		printColoredBoolean(report.SupportsChaCha20, color.FgYellow, color.FgGreen)
		fmt.Print("CBC-EtM support:             ")
		printColoredBoolean(report.SupportsCbcEtm, color.FgYellow, color.FgGreen)
		fmt.Println()
		fmt.Print("Strict key exchange support: ")
		printColoredBoolean(report.SupportsStrictKex, color.FgGreen, color.FgRed)
		fmt.Println()
		if report.IsVulnerable() {
			color.Set(color.FgRed)
			fmt.Println("The scanned peer is VULNERABLE to Terrapin.")
			color.Unset()
		} else {
			color.Set(color.FgGreen)
			fmt.Println("The scanned peer supports Terrapin mitigations and can establish")
			fmt.Println("connections that are NOT VULNERABLE to Terrapin. Glad to see this.")
			fmt.Println("For strict key exchange to take effect, both peers must support it.")
			color.Unset()
		}
	} else {
		marshalledReport, err := json.MarshalIndent(report, "", "    ")
		if err != nil {
			return err
		}
		fmt.Println(string(marshalledReport))
	}
	return nil
}

// Prints a short disclaimer to stdout
func printDisclaimer() {
	fmt.Println()
	fmt.Println("Note: This tool is provided as is, with no warranty whatsoever. It determines")
	fmt.Println("      the vulnerability of a peer by checking the supported algorithms and")
	fmt.Println("      support for strict key exchange. It may falsely claim a peer to be")
	fmt.Println("      vulnerable if the vendor supports countermeasures other than strict key")
	fmt.Println("      exchange.")
	fmt.Println()
	fmt.Println("For more details visit our website available at https://terrapin-attack.com")
}

func main() {
	connectPtr := flag.String(
		"connect",
		"",
		"Address to connect to for server-side scans. Format: <host>[:port]")
	listenPtr := flag.String(
		"listen",
		"",
		"Address to bind to for client-side scans. Format: [host:]<port>")
	jsonPtr := flag.Bool(
		"json",
		false,
		"Outputs the scan result as json. Can be useful when calling the scanner from a script.")
	noColor := flag.Bool(
		"no-color",
		false,
		"Disables colored output.")
	helpPtr := flag.Bool(
		"help",
		false,
		"Prints this usage help to the user.")
	flag.Parse()
	color.NoColor = *noColor
	if (*connectPtr == "" && *listenPtr == "") || *helpPtr {
		flag.Usage()
		printDisclaimer()
		os.Exit(0)
	}
	if *connectPtr != "" && *listenPtr != "" {
		panic(fmt.Errorf("unable to determine scan mode. make sure to provide either -connect or -listen"))
	}
	var report *TerrapinVulnerabilityReport
	if *connectPtr != "" {
		address := formatAddress(*connectPtr, ServerScan)
		var err error
		if report, err = performVulnerabilityScan(address, ServerScan); err != nil {
			panic(err)
		}
	} else if *listenPtr != "" {
		address := formatAddress(*listenPtr, ClientScan)
		var err error
		if report, err = performVulnerabilityScan(address, ClientScan); err != nil {
			panic(err)
		}
	}
	if err := printReport(report, *jsonPtr); err != nil {
		panic(err)
	}
	if !*jsonPtr {
		printDisclaimer()
	}
}

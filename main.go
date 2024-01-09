package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/RUB-NDS/Terrapin-Scanner/tscanner"
	"github.com/fatih/color"
)

const Version = "v1.1.2"

// Formats a socket address given the scan mode
func formatAddress(address string, mode tscanner.ScanMode) string {
	formatted := strings.TrimSpace(address)
	switch mode {
	case tscanner.ServerScan:
		if (strings.HasPrefix(formatted, "[") && strings.HasSuffix(formatted, "]")) ||
			!strings.Contains(formatted, ":") {
			// Literal IPv6 / IPv4 address or hostname without explicit port, default to port 22
			formatted += ":22"
		}
	case tscanner.ClientScan:
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
func printReport(report *tscanner.Report, outputJson bool) error {
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

// Prints the version of this tool to stdout
func printVersion() {
	fmt.Println("Terrapin Vulnerability Scanner " + Version)
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
	versionPtr := flag.Bool(
		"version",
		false,
		"Prints the version of this tool.")
	helpPtr := flag.Bool(
		"help",
		false,
		"Prints this usage help to the user.")
	timeoutPtr := flag.Int(
		"timeout",
		5,
		"Timeout in seconds for the connection to the server.")
	flag.Parse()
	color.NoColor = *noColor
	if (*connectPtr == "" && *listenPtr == "" && !*versionPtr) || *helpPtr {
		printVersion()
		flag.Usage()
		printDisclaimer()
		os.Exit(0)
	}
	if *versionPtr {
		printVersion()
		os.Exit(0)
	}
	if *connectPtr != "" && *listenPtr != "" {
		panic(fmt.Errorf("unable to determine scan mode. make sure to provide either -connect or -listen"))
	}
	var report *tscanner.Report
	if *connectPtr != "" {
		address := formatAddress(*connectPtr, tscanner.ServerScan)
		var err error
		if report, err = tscanner.ScanWithTimeout(address, tscanner.ServerScan, true, *timeoutPtr); err != nil {
			panic(err)
		}
	} else if *listenPtr != "" {
		address := formatAddress(*listenPtr, tscanner.ClientScan)
		var err error
		if report, err = tscanner.ScanWithTimeout(address, tscanner.ClientScan, true, *timeoutPtr); err != nil {
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

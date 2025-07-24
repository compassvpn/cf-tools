package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
)

const (
	asnToFilter = 13335                           // The CloudFlare ASN
	url         = "https://bgp.tools/table.jsonl" // URL for the JSONL table dump
	userAgent   = "compassvpn-cf-tools bgp.tools"          // Custom User-Agent header

	ConcurrentPrefixes = 128 // Number of Concurrencies
	RetryCount         = 4   // Number of retries if one checker fails

	RetryDelay     = 500 * time.Millisecond // Delay between each retry
	RequestTimeout = 500 * time.Millisecond // Timeout delay

	TestIPIncrement1 = 13 // First IP to check in a /24 prefix
	TestIPIncrement2 = 69 // Second IP to check in a /24 prefix

	defaultInputFile      = "all_cf_v4.txt"   // Default output file name: All CloudFlare IPv4 ranges converted to /24 prefixes
	defaultCDNOutputFile  = "all_cdn_v4.txt"  // Default output file name: All CloudFlare CDN IPv4 with /24 prefixes
	defaultWARPOutputFile = "all_warp_v4.txt" // Default output file name: All CloudFlare WARP IPv4 with /24 prefixes

	// WARP Wireguard configurations
	privateKeyB64   = "0ALZyBx68KO4by/oQR+3kmPpYbrOuq605aBYv5GKU0Y="
	publicKeyB64    = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	presharedKeyB64 = ""
)

var (
	httpClient = &http.Client{Timeout: RequestTimeout}
	scanPorts  = []int{2408} // List of ports to scan WARP. Example: {2408, 7559, 2371, 894, ...}
)

// Prefix structure for JSON parsing
type Prefix struct {
	CIDR netip.Prefix `json:"CIDR"`
	ASN  int          `json:"ASN"`
}

// Holds the result of prefix processing
type PrefixResult struct {
	Prefix  netip.Prefix
	IsValid bool
}

// Helper function to show usage
func showHelp() {
	fmt.Println("Usage:")
	fmt.Println("  -h, --help    Show help")
	fmt.Println("  -f, --fetch   Fetch and convert to /24 only")
	fmt.Println("  -c, --cdn     Run the CDN checker")
	fmt.Println("  -w, --warp    Run the WARP checker")
	fmt.Println("  -o, --output  Specify the output file name")
}

// Fetches the prefixes from the URL and filters them by the given ASN
func fetchAndFilterPrefixes(url string, asn int) ([]netip.Prefix, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Set the custom User-Agent header
	req.Header.Set("User-Agent", userAgent)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	// Check for non-200 status codes
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-200 status code %d", resp.StatusCode)
	}

	var v4Prefixes []netip.Prefix
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		var prefix Prefix
		line := scanner.Text()

		// Decode each JSON object
		if err := json.Unmarshal([]byte(line), &prefix); err != nil {
			fmt.Printf("Error decoding JSON line: %v\n", err)
			continue
		}

		// Filter for the specified ASN and store IPv4 prefixes
		if prefix.ASN == asn && !prefix.CIDR.Addr().Is6() {
			v4Prefixes = append(v4Prefixes, prefix.CIDR)
		}
	}

	// Check for errors during scanning
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning response: %w", err)
	}

	return v4Prefixes, nil
}

// Converts the prefixes to /24 blocks and writes them to the output file
func convertTo24AndWrite(prefixes []netip.Prefix, outputFile string) error {
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer outFile.Close()

	writer := bufio.NewWriter(outFile)
	defer writer.Flush()

	unique24s := make(map[string]struct{})
	var wg sync.WaitGroup
	prefixChan := make(chan string, len(prefixes))

	// Process each prefix in a separate goroutine
	for _, prefix := range prefixes {
		wg.Add(1)
		go func(p netip.Prefix) {
			defer wg.Done()
			processPrefix(p, prefixChan)
		}(prefix)
	}

	// Close the channel once all processing is done
	go func() {
		wg.Wait()
		close(prefixChan)
	}()

	// Collect processed prefixes
	var sortedPrefixes []string
	for line := range prefixChan {
		if _, exists := unique24s[line]; !exists {
			unique24s[line] = struct{}{}
			sortedPrefixes = append(sortedPrefixes, line)
		}
	}

	// Sort prefixes
	sort.Slice(sortedPrefixes, func(i, j int) bool {
		return compareIPs(sortedPrefixes[i], sortedPrefixes[j])
	})

	for _, prefix := range sortedPrefixes {
		if _, err := writer.WriteString(prefix + "\n"); err != nil {
			return fmt.Errorf("writing to output file: %w", err)
		}
	}

	return nil
}

// Compares two IP addresses based on the first three octets
func compareIPs(ip1, ip2 string) bool {
	parts1 := strings.Split(ip1, ".")
	parts2 := strings.Split(ip2, ".")

	for i := 0; i < 3; i++ {
		num1, _ := strconv.Atoi(parts1[i])
		num2, _ := strconv.Atoi(parts2[i])
		if num1 != num2 {
			return num1 < num2
		}
	}

	return false
}

// Processes a single prefix and sends /24 blocks to the channel
func processPrefix(prefix netip.Prefix, prefixChan chan<- string) {
	ip := prefix.Addr()
	prefixLen := prefix.Bits()

	// Directly send /24 prefixes
	if prefixLen == 24 {
		prefixChan <- prefix.String()
		return
	}

	ipInt := ipToInt(ip)
	numBlocks := 1 << (24 - prefixLen)
	for i := 0; i < numBlocks; i++ {
		ip := intToIP(ipInt)
		net24 := netip.PrefixFrom(ip, 24).String()
		prefixChan <- net24
		incrementIPBy24(ipInt)
	}
}

// Converts an IP address to a big integer
func ipToInt(ip netip.Addr) *big.Int {
	ipInt := big.NewInt(0)
	ipInt.SetBytes(ip.AsSlice())
	return ipInt
}

// Increments an IP address by one /24 block using bit shift operations
func incrementIPBy24(ipInt *big.Int) {
	increment := big.NewInt(1 << 8) // 256 for /24
	ipInt.Add(ipInt, increment)
}

// Converts a big integer back to an IP address
func intToIP(ipInt *big.Int) netip.Addr {
	ipBytes := make([]byte, 4)
	ipInt.FillBytes(ipBytes)
	ip, _ := netip.AddrFromSlice(ipBytes)
	return ip
}

// Checks if an IP address responds with StatusOK for the CDN trace URL.
func isValidCDNIP(ip netip.Addr) bool {
	url := fmt.Sprintf("http://%s/cdn-cgi/trace", ip)

	for i := 0; i < RetryCount; i++ {
		resp, err := httpClient.Head(url)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
		time.Sleep(RetryDelay)
	}
	return false
}

// Increments the given IP address by a specified value.
func incrementIP(ip netip.Addr, increment int) netip.Addr {
	ipBytes := ip.As4()
	ipUint := uint32(ipBytes[0])<<24 | uint32(ipBytes[1])<<16 | uint32(ipBytes[2])<<8 | uint32(ipBytes[3])
	ipUint += uint32(increment)
	newIP := netip.AddrFrom4([4]byte{byte(ipUint >> 24), byte(ipUint >> 16), byte(ipUint >> 8), byte(ipUint)})
	return newIP
}

// Checks if any IP within the prefix is a CDN IP.
func processPrefixCDN(prefix netip.Prefix) bool {
	baseIP := prefix.Addr()
	testIP1 := incrementIP(baseIP, TestIPIncrement1)
	testIP2 := incrementIP(baseIP, TestIPIncrement2)
	return isValidCDNIP(testIP1) || isValidCDNIP(testIP2)
}

// Processes each prefix and sends the result to the channel.
func parallelFunctionCDN(ipChannel chan PrefixResult, prefix netip.Prefix) {
	isValid := processPrefixCDN(prefix)
	ipChannel <- PrefixResult{
		Prefix:  prefix,
		IsValid: isValid,
	}
}

// Generates a static keypair from a base64-encoded private key
func staticKeypair(privateKeyBase64 string) (noise.DHKey, error) {
	privateKey, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return noise.DHKey{}, err
	}

	var pubkey, privkey [32]byte
	copy(privkey[:], privateKey)
	curve25519.ScalarBaseMult(&pubkey, &privkey)

	return noise.DHKey{
		Private: privateKey,
		Public:  pubkey[:],
	}, nil
}

// Generates an ephemeral keypair
func ephemeralKeypair() (noise.DHKey, error) {
	ephemeralPrivateKey := make([]byte, 32)
	if _, err := rand.Read(ephemeralPrivateKey); err != nil {
		return noise.DHKey{}, err
	}

	ephemeralPublicKey, err := curve25519.X25519(ephemeralPrivateKey, curve25519.Basepoint)
	if err != nil {
		return noise.DHKey{}, err
	}

	return noise.DHKey{
		Private: ephemeralPrivateKey,
		Public:  ephemeralPublicKey,
	}, nil
}

// Converts a uint32 to a byte slice
func uint32ToBytes(n uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return b
}

// Initiates a handshake with the server and returns the round-trip time (RTT)
func initiateHandshake(serverAddr netip.AddrPort, privateKeyBase64, peerPublicKeyBase64, presharedKeyBase64 string) (time.Duration, error) {
	staticKeyPair, err := staticKeypair(privateKeyBase64)
	if err != nil {
		return 0, err
	}

	peerPublicKey, err := base64.StdEncoding.DecodeString(peerPublicKeyBase64)
	if err != nil {
		return 0, err
	}

	presharedKey, err := base64.StdEncoding.DecodeString(presharedKeyBase64)
	if err != nil {
		return 0, err
	}

	if presharedKeyBase64 == "" {
		presharedKey = make([]byte, 32)
	}

	ephemeral, err := ephemeralKeypair()
	if err != nil {
		return 0, err
	}

	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           cs,
		Pattern:               noise.HandshakeIK,
		Initiator:             true,
		StaticKeypair:         staticKeyPair,
		PeerStatic:            peerPublicKey,
		Prologue:              []byte("WireGuard v1 zx2c4 Jason@zx2c4.com"),
		PresharedKey:          presharedKey,
		PresharedKeyPlacement: 2,
		EphemeralKeypair:      ephemeral,
		Random:                rand.Reader,
	})
	if err != nil {
		return 0, err
	}

	now := time.Now().UTC()
	epochOffset := int64(4611686018427387914) // TAI offset from Unix epoch

	tai64nTimestampBuf := make([]byte, 0, 16)
	tai64nTimestampBuf = binary.BigEndian.AppendUint64(tai64nTimestampBuf, uint64(epochOffset+now.Unix()))
	tai64nTimestampBuf = binary.BigEndian.AppendUint32(tai64nTimestampBuf, uint32(now.Nanosecond()))
	msg, _, _, err := hs.WriteMessage(nil, tai64nTimestampBuf)
	if err != nil {
		return 0, err
	}

	initiationPacket := new(bytes.Buffer)
	binary.Write(initiationPacket, binary.BigEndian, []byte{0x01, 0x00, 0x00, 0x00})
	binary.Write(initiationPacket, binary.BigEndian, uint32ToBytes(28))
	binary.Write(initiationPacket, binary.BigEndian, msg)

	macKey := blake2s.Sum256(append([]byte("mac1----"), peerPublicKey...))
	hasher, err := blake2s.New128(macKey[:])
	if err != nil {
		return 0, err
	}
	_, err = hasher.Write(initiationPacket.Bytes())
	if err != nil {
		return 0, err
	}
	initiationPacketMAC := hasher.Sum(nil)

	binary.Write(initiationPacket, binary.BigEndian, initiationPacketMAC[:16])
	binary.Write(initiationPacket, binary.BigEndian, [16]byte{})

	conn, err := net.Dial("udp", serverAddr.String())
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	_, err = initiationPacket.WriteTo(conn)
	if err != nil {
		return 0, err
	}
	t0 := time.Now()

	response := make([]byte, 92)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	i, err := conn.Read(response)
	if err != nil {
		return 0, err
	}
	rtt := time.Since(t0)

	if i < 60 {
		return 0, fmt.Errorf("invalid handshake response length %d bytes", i)
	}

	if response[0] != 2 {
		return 0, errors.New("invalid response type")
	}

	ourIndex := binary.LittleEndian.Uint32(response[8:12])
	if ourIndex != 28 {
		return 0, errors.New("invalid sender index in response")
	}

	payload, _, _, err := hs.ReadMessage(nil, response[12:60])
	if err != nil {
		return 0, err
	}

	if len(payload) != 0 {
		return 0, errors.New("unexpected payload in response")
	}

	return rtt, nil
}

// Checks if an IP address responds with StatusOK for the WARP trace URL on any of the given ports
func isValidWarpIP(ip netip.Addr) bool {
	for _, port := range scanPorts {
		ip2 := netip.AddrPortFrom(ip, uint16(port))

		for i := 0; i < RetryCount; i++ {
			_, err := initiateHandshake(ip2, privateKeyB64, publicKeyB64, presharedKeyB64)
			if err == nil {
				return true
			}
			time.Sleep(RetryDelay)
		}
	}
	return false
}

// Checks if any IP within the prefix is a WARP IP
func processPrefixWARP(prefix netip.Prefix) bool {
	baseIP := prefix.Addr()
	testIP1 := incrementIP(baseIP, TestIPIncrement1)
	testIP2 := incrementIP(baseIP, TestIPIncrement2)
	return isValidWarpIP(testIP1) || isValidWarpIP(testIP2)
}

// Processes each prefix and sends the result to the channel
func parallelFunctionWARP(ipChannel chan PrefixResult, prefix netip.Prefix) {
	isValid := processPrefixWARP(prefix)
	ipChannel <- PrefixResult{
		Prefix:  prefix,
		IsValid: isValid,
	}
}

func main() {
	// Define flags
	helpFlag := flag.Bool("h", false, "Show help")
	helpFlagLong := flag.Bool("help", false, "Show help")
	cdnFlag := flag.Bool("c", false, "Run the CDN checker")
	cdnFlagLong := flag.Bool("cdn", false, "Run the CDN checker")
	warpFlag := flag.Bool("w", false, "Run the WARP checker")
	warpFlagLong := flag.Bool("warp", false, "Run the WARP checker")
	fetchFlag := flag.Bool("f", false, "Fetch and convert to /24 only")
	fetchFlagLong := flag.Bool("fetch", false, "Fetch and convert to /24 only")
	outputFile := flag.String("o", "", "Specify the output file name")
	outputFileLong := flag.String("output", "", "Specify the output file name")

	flag.Parse()

	// If no flag is provided, show help
	if !*helpFlag && !*helpFlagLong && !*cdnFlag && !*cdnFlagLong && !*warpFlag && !*warpFlagLong && !*fetchFlag && !*fetchFlagLong {
		showHelp()
		return
	}

	if *helpFlag || *helpFlagLong {
		showHelp()
		return
	}

	// Fetch and filter the prefixes
	v4Prefixes, err := fetchAndFilterPrefixes(url, asnToFilter)
	if err != nil {
		fmt.Printf("Error fetching and filtering prefixes: %v\n", err)
		return
	}

	// Determine the output file
	output := defaultInputFile
	if *outputFile != "" {
		output = *outputFile
	}
	if *outputFileLong != "" {
		output = *outputFileLong
	}

	// Convert the prefixes to /24 and write to the intermediate file
	err = convertTo24AndWrite(v4Prefixes, output)
	if err != nil {
		fmt.Printf("Error converting to /24 and writing to file: %v\n", err)
		return
	}

	// If fetch-only flag is set, exit after converting and writing the prefixes
	if *fetchFlag || *fetchFlagLong {
		fmt.Println("Prefixes fetched and converted to /24. Output written to", output)
		return
	}

	// Open intermediate file containing IP prefixes
	file, err := os.Open(output)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	// Read all prefixes and store them in a map to avoid duplicates
	prefixSet := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		prefixString := scanner.Text()
		prefixSet[prefixString] = struct{}{}
	}

	// Convert the map keys back to a slice
	var prefixes []netip.Prefix
	for prefixString := range prefixSet {
		prefix, err := netip.ParsePrefix(prefixString)
		if err == nil {
			prefixes = append(prefixes, prefix)
		}
	}

	if *cdnFlag || *cdnFlagLong {
		output := defaultCDNOutputFile
		if *outputFile != "" {
			output = *outputFile
		}
		if *outputFileLong != "" {
			output = *outputFileLong
		}

		// Create output file for valid CDN IP prefixes
		outputFile, err := os.Create(output)
		if err != nil {
			fmt.Printf("Error creating output file: %v\n", err)
			return
		}
		defer outputFile.Close()

		ipChannel := make(chan PrefixResult)
		sem := make(chan struct{}, ConcurrentPrefixes)

		// Process prefixes concurrently with limited concurrency
		go func() {
			for _, prefix := range prefixes {
				sem <- struct{}{}
				go func(prefix netip.Prefix) {
					defer func() { <-sem }()
					parallelFunctionCDN(ipChannel, prefix)
				}(prefix)
			}
		}()

		var validPrefixes []string
		// Collect results and store valid prefixes
		for i := 0; i < len(prefixes); i++ {
			result := <-ipChannel
			if result.IsValid {
				fmt.Printf("Valid CDN Prefix: %v\n", result.Prefix)
				validPrefixes = append(validPrefixes, result.Prefix.String())
			}
		}
		close(ipChannel)

		// Sort and write valid prefixes to the output file
		sort.Slice(validPrefixes, func(i, j int) bool {
			return compareIPs(validPrefixes[i], validPrefixes[j])
		})
		for _, prefix := range validPrefixes {
			outputFile.WriteString(prefix + "\n")
		}

		fmt.Println("Processing complete. Valid /24 prefixes have been written to", output)
	}

	if *warpFlag || *warpFlagLong {
		output := defaultWARPOutputFile
		if *outputFile != "" {
			output = *outputFile
		}
		if *outputFileLong != "" {
			output = *outputFileLong
		}

		// Create output file for valid WARP IP prefixes
		outputFile, err := os.Create(output)
		if err != nil {
			fmt.Printf("Error creating output file: %v\n", err)
			return
		}
		defer outputFile.Close()

		ipChannel := make(chan PrefixResult)
		sem := make(chan struct{}, ConcurrentPrefixes)

		// Process prefixes concurrently with limited concurrency
		go func() {
			for _, prefix := range prefixes {
				sem <- struct{}{}
				go func(prefix netip.Prefix) {
					defer func() { <-sem }()
					parallelFunctionWARP(ipChannel, prefix)
				}(prefix)
			}
		}()

		var validPrefixes []string
		// Collect results and store valid prefixes
		for i := 0; i < len(prefixes); i++ {
			result := <-ipChannel
			if result.IsValid {
				fmt.Printf("Valid WARP Prefix: %v\n", result.Prefix)
				validPrefixes = append(validPrefixes, result.Prefix.String())
			}
		}
		close(ipChannel)

		// Sort and write valid prefixes to the output file
		sort.Slice(validPrefixes, func(i, j int) bool {
			return compareIPs(validPrefixes[i], validPrefixes[j])
		})
		for _, prefix := range validPrefixes {
			outputFile.WriteString(prefix + "\n")
		}

		fmt.Println("Processing complete. Valid /24 prefixes have been written to", output)
	}
}

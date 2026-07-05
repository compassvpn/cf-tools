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
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
)

// ASNs whose prefixes we keep from the BGP table.
var asnsToFilter = []int{
	13335,
	209242,
	14789,
	202623,
	203898,
	394536,
	395747,
	139242,
	132892,
}

// Host offsets probed inside each /24 prefix.
var testIPOffsets = []int{8, 13, 69, 144, 234}

const (
	bgpTableURL = "https://bgp.tools/table.jsonl" // JSONL BGP table dump
	userAgent   = "compassvpn-cf-tools bgp.tools" // custom User-Agent header

	ConcurrentPrefixes = 55              // max prefixes scanned in parallel
	RetryCount         = 4               // attempts per probe before giving up
	RetryDelay         = 1 * time.Second // delay between attempts
	RequestTimeout     = 4 * time.Second // per-probe timeout
	FetchTimeout       = 2 * time.Minute // timeout for the full table download

	defaultInputFile      = "all_cf_v4.txt"   // all Cloudflare IPv4 ranges as /24 prefixes
	defaultCDNOutputFile  = "all_cdn_v4.txt"  // Cloudflare CDN /24 prefixes
	defaultWARPOutputFile = "all_warp_v4.txt" // Cloudflare WARP /24 prefixes

	// WARP WireGuard configuration (public, default WARP keys — not secrets).
	privateKeyB64   = "0ALZyBx68KO4by/oQR+3kmPpYbrOuq605aBYv5GKU0Y="
	publicKeyB64    = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	presharedKeyB64 = ""
)

var (
	httpClient = &http.Client{
		Timeout: RequestTimeout,
		// The CDN probe only cares about the first-hop response, never a redirect target.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	scanPorts = []int{2408} // WARP ports to scan, e.g. {2408, 7559, 2371, 894, ...}
)

// Prefix mirrors one JSON record from the bgp.tools table dump.
type Prefix struct {
	CIDR netip.Prefix `json:"CIDR"`
	ASN  int          `json:"ASN"`
}

// PrefixResult pairs a prefix with whether it passed a checker.
type PrefixResult struct {
	Prefix  netip.Prefix
	IsValid bool
}

func showHelp() {
	fmt.Println("Usage:")
	fmt.Println("  -h, --help    Show help")
	fmt.Println("  -f, --fetch   Fetch and convert to /24 only")
	fmt.Println("  -c, --cdn     Run the CDN checker")
	fmt.Println("  -w, --warp    Run the WARP checker")
	fmt.Println("  -o, --output  Specify the output file name")
}

// fetchAndFilterPrefixes downloads the BGP table and returns the IPv4 prefixes
// belonging to any of the given ASNs.
func fetchAndFilterPrefixes(url string, asns []int) ([]netip.Prefix, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	client := &http.Client{Timeout: FetchTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-200 status code %d", resp.StatusCode)
	}

	wanted := make(map[int]struct{}, len(asns))
	for _, asn := range asns {
		wanted[asn] = struct{}{}
	}

	var v4Prefixes []netip.Prefix
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		var prefix Prefix
		if err := json.Unmarshal(scanner.Bytes(), &prefix); err != nil {
			fmt.Printf("Error decoding JSON line: %v\n", err)
			continue
		}
		if _, ok := wanted[prefix.ASN]; ok && !prefix.CIDR.Addr().Is6() {
			v4Prefixes = append(v4Prefixes, prefix.CIDR)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning response: %w", err)
	}
	return v4Prefixes, nil
}

// convertTo24AndWrite expands prefixes into unique, sorted /24 blocks, writes
// them to outputFile, and returns them for reuse.
func convertTo24AndWrite(prefixes []netip.Prefix, outputFile string) ([]netip.Prefix, error) {
	prefixChan := make(chan netip.Prefix, ConcurrentPrefixes)
	var wg sync.WaitGroup
	for _, prefix := range prefixes {
		wg.Add(1)
		go func(p netip.Prefix) {
			defer wg.Done()
			processPrefix(p, prefixChan)
		}(prefix)
	}
	go func() {
		wg.Wait()
		close(prefixChan)
	}()

	seen := make(map[netip.Prefix]struct{})
	var unique []netip.Prefix
	for p := range prefixChan {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			unique = append(unique, p)
		}
	}
	sort.Slice(unique, func(i, j int) bool {
		return unique[i].Addr().Less(unique[j].Addr())
	})

	out, err := os.Create(outputFile)
	if err != nil {
		return nil, fmt.Errorf("creating output file: %w", err)
	}
	defer out.Close()

	writer := bufio.NewWriter(out)
	for _, p := range unique {
		if _, err := writer.WriteString(p.String() + "\n"); err != nil {
			return nil, fmt.Errorf("writing to output file: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		return nil, fmt.Errorf("flushing output file: %w", err)
	}
	return unique, nil
}

// processPrefix sends every /24 block covered by prefix to out. A prefix that is
// already /24 or longer collapses to its single covering /24.
func processPrefix(prefix netip.Prefix, out chan<- netip.Prefix) {
	bits := prefix.Bits()
	if bits >= 24 {
		out <- netip.PrefixFrom(prefix.Addr(), 24).Masked()
		return
	}
	ip := prefix.Addr()
	for i := 0; i < 1<<(24-bits); i++ {
		out <- netip.PrefixFrom(ip, 24).Masked()
		ip = incrementIP(ip, 256)
	}
}

// incrementIP returns ip advanced by increment (IPv4 arithmetic).
func incrementIP(ip netip.Addr, increment int) netip.Addr {
	b := ip.As4()
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	n += uint32(increment)
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}

// isValidCDNIP reports whether ip serves a Cloudflare /cdn-cgi/trace response.
func isValidCDNIP(ip netip.Addr) bool {
	url := fmt.Sprintf("http://%s/cdn-cgi/trace", ip)
	for i := 0; i < RetryCount; i++ {
		if servesCloudflareTrace(url) {
			return true
		}
		if i < RetryCount-1 {
			time.Sleep(RetryDelay)
		}
	}
	return false
}

// servesCloudflareTrace reports whether url returns a genuine Cloudflare trace
// body (guarding against unrelated servers that merely answer 200).
func servesCloudflareTrace(url string) bool {
	resp, err := httpClient.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return false
	}
	// The trace endpoint always reports the Cloudflare colo that served it.
	return bytes.Contains(body, []byte("colo="))
}

// prefixHasValidIP reports whether any probed IP in the /24 passes check. Probes
// run concurrently and it returns as soon as one succeeds.
func prefixHasValidIP(prefix netip.Prefix, check func(netip.Addr) bool) bool {
	base := prefix.Addr()
	found := make(chan struct{}, len(testIPOffsets))
	var wg sync.WaitGroup
	for _, off := range testIPOffsets {
		wg.Add(1)
		go func(ip netip.Addr) {
			defer wg.Done()
			if check(ip) {
				found <- struct{}{}
			}
		}(incrementIP(base, off))
	}
	go func() {
		wg.Wait()
		close(found)
	}()

	_, ok := <-found
	return ok
}

// staticKeypair builds a static keypair from a base64-encoded private key.
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

// ephemeralKeypair generates a random ephemeral keypair.
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

// uint32ToBytes encodes n as little-endian bytes.
func uint32ToBytes(n uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return b
}

// initiateHandshake performs a WireGuard handshake with the server and returns
// the round-trip time on success.
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

	// Writes to a bytes.Buffer never fail, so their errors are safely ignored.
	initiationPacket := new(bytes.Buffer)
	binary.Write(initiationPacket, binary.BigEndian, []byte{0x01, 0x00, 0x00, 0x00})
	binary.Write(initiationPacket, binary.BigEndian, uint32ToBytes(28))
	binary.Write(initiationPacket, binary.BigEndian, msg)

	macKey := blake2s.Sum256(append([]byte("mac1----"), peerPublicKey...))
	hasher, err := blake2s.New128(macKey[:])
	if err != nil {
		return 0, err
	}
	if _, err := hasher.Write(initiationPacket.Bytes()); err != nil {
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

	if _, err := initiationPacket.WriteTo(conn); err != nil {
		return 0, err
	}
	t0 := time.Now()

	response := make([]byte, 92)
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return 0, err
	}
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

// isValidWarpIP reports whether a WireGuard handshake with the WARP peer
// succeeds on any scanned port.
func isValidWarpIP(ip netip.Addr) bool {
	for _, port := range scanPorts {
		addr := netip.AddrPortFrom(ip, uint16(port))
		for i := 0; i < RetryCount; i++ {
			if _, err := initiateHandshake(addr, privateKeyB64, publicKeyB64, presharedKeyB64); err == nil {
				return true
			}
			if i < RetryCount-1 {
				time.Sleep(RetryDelay)
			}
		}
	}
	return false
}

// runChecker probes every prefix with check and writes the passing /24 prefixes
// (sorted) to outputFile. label is used only in progress output.
func runChecker(prefixes []netip.Prefix, check func(netip.Addr) bool, outputFile, label string) error {
	results := make(chan PrefixResult)
	sem := make(chan struct{}, ConcurrentPrefixes)
	go func() {
		for _, prefix := range prefixes {
			sem <- struct{}{}
			go func(p netip.Prefix) {
				defer func() { <-sem }()
				results <- PrefixResult{Prefix: p, IsValid: prefixHasValidIP(p, check)}
			}(prefix)
		}
	}()

	var valid []netip.Prefix
	for range prefixes {
		if r := <-results; r.IsValid {
			fmt.Printf("Valid %s Prefix: %v\n", label, r.Prefix)
			valid = append(valid, r.Prefix)
		}
	}
	close(results)

	sort.Slice(valid, func(i, j int) bool {
		return valid[i].Addr().Less(valid[j].Addr())
	})

	out, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer out.Close()

	writer := bufio.NewWriter(out)
	for _, p := range valid {
		if _, err := writer.WriteString(p.String() + "\n"); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flushing output: %w", err)
	}

	fmt.Printf("Processing complete. Valid /24 prefixes written to %s\n", outputFile)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run() error {
	help := flag.Bool("h", false, "Show help")
	flag.BoolVar(help, "help", false, "Show help")
	cdn := flag.Bool("c", false, "Run the CDN checker")
	flag.BoolVar(cdn, "cdn", false, "Run the CDN checker")
	warp := flag.Bool("w", false, "Run the WARP checker")
	flag.BoolVar(warp, "warp", false, "Run the WARP checker")
	fetch := flag.Bool("f", false, "Fetch and convert to /24 only")
	flag.BoolVar(fetch, "fetch", false, "Fetch and convert to /24 only")
	output := flag.String("o", "", "Specify the output file name")
	flag.StringVar(output, "output", "", "Specify the output file name")
	flag.Parse()

	if *help || (!*cdn && !*warp && !*fetch) {
		showHelp()
		return nil
	}

	if *output != "" && *cdn && *warp {
		return errors.New("-o cannot be used when running both -c and -w; they would overwrite each other")
	}

	prefixes, err := fetchAndFilterPrefixes(bgpTableURL, asnsToFilter)
	if err != nil {
		return fmt.Errorf("fetching prefixes: %w", err)
	}
	if len(prefixes) == 0 {
		return errors.New("no matching prefixes found (the upstream feed may have changed)")
	}

	fetchOutput := defaultInputFile
	if *output != "" {
		fetchOutput = *output
	}
	blocks, err := convertTo24AndWrite(prefixes, fetchOutput)
	if err != nil {
		return fmt.Errorf("converting to /24: %w", err)
	}

	if *fetch {
		fmt.Println("Prefixes fetched and converted to /24. Output written to", fetchOutput)
		return nil
	}

	if *cdn {
		out := defaultCDNOutputFile
		if *output != "" {
			out = *output
		}
		if err := runChecker(blocks, isValidCDNIP, out, "CDN"); err != nil {
			return fmt.Errorf("CDN checker: %w", err)
		}
	}

	if *warp {
		out := defaultWARPOutputFile
		if *output != "" {
			out = *output
		}
		if err := runChecker(blocks, isValidWarpIP, out, "WARP"); err != nil {
			return fmt.Errorf("WARP checker: %w", err)
		}
	}
	return nil
}

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

// Cloudflare ASNs to keep from the BGP table.
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

// Host offsets sampled inside each /24. If any of these answers a probe, the
// whole block counts as Cloudflare, so we avoid testing all 256 addresses.
var testIPOffsets = []int{8, 13, 69, 144, 234}

const (
	bgpTableURL = "https://bgp.tools/table.jsonl" // table dump, one JSON record per line
	userAgent   = "compassvpn-cf-tools bgp.tools" // User-Agent sent to bgp.tools

	ConcurrentPrefixes = 55              // how many prefixes to scan at once
	RetryCount         = 4               // attempts per probe before giving up
	RetryDelay         = 1 * time.Second // wait between attempts
	RequestTimeout     = 4 * time.Second // timeout for one CDN HTTP probe
	FetchTimeout       = 2 * time.Minute // timeout for downloading the whole table

	defaultInputFile      = "all_cf_v4.txt"   // every Cloudflare /24
	defaultCDNOutputFile  = "all_cdn_v4.txt"  // /24s that answer as CDN
	defaultWARPOutputFile = "all_warp_v4.txt" // /24s that answer as WARP

	// WARP WireGuard keys. These are Cloudflare's public defaults, not secrets.
	privateKeyB64   = "0ALZyBx68KO4by/oQR+3kmPpYbrOuq605aBYv5GKU0Y="
	publicKeyB64    = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	presharedKeyB64 = ""
)

var (
	httpClient = &http.Client{
		Timeout: RequestTimeout,
		// Don't follow redirects. We only trust the direct response from the probed IP.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	scanPorts = []int{2408} // WARP ports to scan, e.g. {2408, 7559, 2371, 894, ...}
)

// Represents one record from the bgp.tools table dump.
type Prefix struct {
	CIDR netip.Prefix `json:"CIDR"`
	ASN  int          `json:"ASN"`
}

// Pairs a prefix with whether it passed a checker.
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

// Downloads the BGP table and returns the IPv4 prefixes that belong to one of
// the given ASNs.
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

	// Build a set once so each line is a map lookup rather than a slice scan.
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

// Expands the prefixes into unique, sorted /24 blocks and writes them to
// outputFile. The blocks are also returned so callers can reuse them without
// re-reading the file.
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

// Sends every /24 block inside prefix to out. Anything already /24 or smaller
// collapses to the single /24 that covers it.
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

// Returns ip advanced by increment, using plain IPv4 (uint32) math.
func incrementIP(ip netip.Addr, increment int) netip.Addr {
	b := ip.As4()
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	n += uint32(increment)
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}

// Reports whether ip serves a Cloudflare /cdn-cgi/trace response, retrying a
// few times before giving up.
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

// Reports whether url returns a real Cloudflare trace body. Checking the body,
// not just the 200 status, keeps an unrelated web server on the same IP from
// being counted as Cloudflare.
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

// Reports whether any sampled IP in the /24 passes check. The probes run
// concurrently, so it returns as soon as one of them succeeds.
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

	// Receives once if any probe reported success, or reads the closed channel
	// (ok == false) once they all finish without one.
	_, ok := <-found
	return ok
}

// Builds a static keypair from a base64-encoded private key.
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

// Generates a random ephemeral keypair.
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

// Encodes n as little-endian bytes.
func uint32ToBytes(n uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return b
}

// Performs a WireGuard handshake with the server and returns the round-trip
// time on success.
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
	epochOffset := int64(4611686018427387914) // TAI64 epoch offset (2^62 + 10 leap seconds)

	tai64nTimestampBuf := make([]byte, 0, 16)
	tai64nTimestampBuf = binary.BigEndian.AppendUint64(tai64nTimestampBuf, uint64(epochOffset+now.Unix()))
	tai64nTimestampBuf = binary.BigEndian.AppendUint32(tai64nTimestampBuf, uint32(now.Nanosecond()))
	msg, _, _, err := hs.WriteMessage(nil, tai64nTimestampBuf)
	if err != nil {
		return 0, err
	}

	// Writes to a bytes.Buffer never fail, so their errors are safe to ignore.
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

// Reports whether a WireGuard handshake with the WARP peer succeeds on any of
// the scanned ports.
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

// Probes every prefix with check and writes the passing /24 blocks, sorted, to
// outputFile. The label only appears in the progress output.
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

	// A single -o can't name two outputs, so refuse to run both checkers with it.
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

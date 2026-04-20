package ssh

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// Config maps lowercase SSH option keys to an ordered list of values.
// Multi-value keys (e.g. identityfile, sendenv) accumulate multiple entries.
type Config map[string][]string

// HostEntry holds the resolved host-specific config for one host in a proxy chain.
type HostEntry struct {
	Name   string
	Config Config
}

// ReadConfig reads an SSH config file and recursively inlines Include
// directives, producing a single flat config string. Relative Include paths
// are resolved against sshDir. Missing include targets are silently skipped
// (matching OpenSSH behavior for glob patterns that match nothing).
func ReadConfig(path string, sshDir string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	var result strings.Builder
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "include ") {
			pattern := strings.TrimSpace(trimmed[len("include "):])
			// Expand ~ to home directory.
			if strings.HasPrefix(pattern, "~/") {
				home, _ := os.UserHomeDir()
				pattern = home + pattern[1:]
			}
			// Resolve relative paths against sshDir.
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join(sshDir, pattern)
			}
			matches, _ := filepath.Glob(pattern)
			if matches == nil {
				// Single file path that doesn't exist — skip silently.
				continue
			}
			for _, match := range matches {
				included, err := ReadConfig(match, sshDir)
				if err != nil {
					continue
				}
				result.WriteString(included)
			}
			continue
		}
		result.WriteString(line)
		result.WriteByte('\n')
	}
	return result.String(), nil
}

// ParseHostnames extracts concrete (non-pattern) hostnames from SSH config text.
// Wildcards (*, ?), negations (!), and pattern hosts (*.example.com) are skipped.
// Results are sorted and deduplicated.
func ParseHostnames(config string) []string {
	seen := make(map[string]bool)
	for _, line := range strings.Split(config, "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if !strings.HasPrefix(lower, "host ") || strings.HasPrefix(lower, "hostname") {
			continue
		}
		fields := strings.Fields(trimmed)
		for _, f := range fields[1:] {
			if strings.ContainsAny(f, "*?!") {
				continue
			}
			seen[f] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	hosts := make([]string, 0, len(seen))
	for h := range seen {
		hosts = append(hosts, h)
	}
	slices.Sort(hosts)
	return hosts
}

// ParseKnownHostnames extracts concrete hostnames from known_hosts content.
// Hashed entries, IP addresses, comments, and blank lines are skipped.
// Bracketed [host]:port entries are unwrapped. Results are sorted and deduplicated.
func ParseKnownHostnames(content string) []string {
	seen := make(map[string]bool)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "|") {
			continue
		}
		// First field is the hostname(s), rest is key type + key data.
		hostField := strings.Fields(line)[0]
		for _, entry := range strings.Split(hostField, ",") {
			host := entry
			// Unwrap [host]:port format.
			if strings.HasPrefix(host, "[") {
				bracket := strings.Index(host, "]")
				if bracket < 0 {
					continue
				}
				host = host[1:bracket]
			}
			// Skip IP addresses (v4 and v6).
			if net.ParseIP(host) != nil {
				continue
			}
			// Skip bare port numbers and entries with stray brackets.
			if host == "" || strings.ContainsAny(host, "[]") || isNumeric(host) {
				continue
			}
			seen[host] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	hosts := make([]string, 0, len(seen))
	for h := range seen {
		hosts = append(hosts, h)
	}
	slices.Sort(hosts)
	return hosts
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

// ParseRawWildcardConfig extracts options from Host * and Match all blocks
// in raw SSH config text. The returned values preserve the original
// un-interpolated form (e.g. %h, %p tokens are kept as-is).
func ParseRawWildcardConfig(config string) Config {
	cfg := make(Config)
	inWildcard := false

	for _, line := range strings.Split(config, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lower := strings.ToLower(trimmed)

		// Check for Host/Match section headers.
		if strings.HasPrefix(lower, "host ") && !strings.HasPrefix(lower, "hostname") {
			fields := strings.Fields(trimmed)
			hasBareStar := slices.Contains(fields[1:], "*")
			inWildcard = hasBareStar
			continue
		}
		if strings.HasPrefix(lower, "match") {
			fields := strings.Fields(trimmed)
			inWildcard = len(fields) == 2 && strings.EqualFold(fields[1], "all")
			continue
		}

		if !inWildcard {
			continue
		}

		// Parse "Key value" lines within a wildcard block.
		parts := strings.SplitN(trimmed, " ", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(parts[0])
		value := parts[1]
		cfg[key] = append(cfg[key], value)
	}
	return cfg
}

// ParseOutput parses the line-oriented output of `ssh -G <hostname>`.
// Each line is "key value"; keys are lowercased. Duplicate keys accumulate.
func ParseOutput(output string) Config {
	cfg := make(Config)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(parts[0])
		value := parts[1]
		cfg[key] = append(cfg[key], value)
	}
	return cfg
}

// Diff returns a new Config containing only keys from effective whose
// values differ from the corresponding values in baseline.
func Diff(effective, baseline Config) Config {
	result := make(Config)
	for key, effectiveVals := range effective {
		baselineVals, exists := baseline[key]
		if !exists || !slices.Equal(effectiveVals, baselineVals) {
			result[key] = effectiveVals
		}
	}
	return result
}

// RunG runs `ssh -G [extraArgs...] <hostname>` and returns parsed output.
func RunG(hostname string, extraArgs ...string) (Config, error) {
	args := append([]string{"-G"}, extraArgs...)
	args = append(args, hostname)
	out, err := exec.Command("ssh", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("ssh -G %s: %w", hostname, err)
	}
	return ParseOutput(string(out)), nil
}

// ModifyBaselineConfig rewrites an SSH config so that Host * and Match all
// blocks will not match excludeHost. This allows the baseline query to return
// only SSH built-in defaults, making user-defined Host * options visible in the diff.
func ModifyBaselineConfig(config string, excludeHost string) string {
	lines := strings.Split(config, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)

		// Handle "Host" lines containing a bare "*" pattern.
		if strings.HasPrefix(lower, "host ") && !strings.HasPrefix(lower, "hostname") {
			fields := strings.Fields(trimmed)
			hasBarestar := false
			for _, f := range fields[1:] {
				if f == "*" {
					hasBarestar = true
					break
				}
			}
			if hasBarestar {
				// Append exclusion to the end of the line, preserving leading whitespace.
				lines[i] = line + " !" + excludeHost
			}
		}

		// Handle "Match all" lines.
		if strings.HasPrefix(lower, "match") {
			fields := strings.Fields(trimmed)
			if len(fields) == 2 && strings.EqualFold(fields[1], "all") {
				// Preserve the original "Match" casing and leading whitespace.
				prefix := line[:len(line)-len(trimmed)]
				lines[i] = prefix + fields[0] + " host !" + excludeHost
			}
		}
	}
	return strings.Join(lines, "\n")
}

// RandomHostname generates a hostname that will not match any SSH config block,
// so that RunG against it returns only SSH built-ins and Host * defaults.
func RandomHostname() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return "no-match-" + hex.EncodeToString(b) + ".invalid"
}

// ParseJumpHosts extracts hostnames from a ProxyJump value.
// Handles [user@]host[:port] format and comma-separated lists.
// Returns nil for "none" or empty input.
func ParseJumpHosts(value string) []string {
	if value == "" || value == "none" {
		return nil
	}
	parts := strings.Split(value, ",")
	hosts := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || part == "none" {
			continue
		}
		// Strip user@ prefix.
		if i := strings.LastIndex(part, "@"); i >= 0 {
			part = part[i+1:]
		}
		// Strip :port suffix.
		if i := strings.LastIndex(part, ":"); i >= 0 {
			part = part[:i]
		}
		if part != "" {
			hosts = append(hosts, part)
		}
	}
	return hosts
}

// ResolveChain returns the target host followed by each host in its ProxyJump
// chain, recursively. visited prevents cycles. The target is always first
// (closest to the intended destination); proxies follow in hop order.
func ResolveChain(hostname string, defaults Config, visited map[string]bool) ([]HostEntry, error) {
	if visited[hostname] {
		return nil, nil
	}
	visited[hostname] = true

	effective, err := RunG(hostname)
	if err != nil {
		return nil, err
	}

	cfg := Diff(effective, defaults)
	var entries []HostEntry

	if jumpVals, ok := cfg["proxyjump"]; ok && len(jumpVals) > 0 {
		for _, jumpHost := range ParseJumpHosts(jumpVals[0]) {
			chain, err := ResolveChain(jumpHost, defaults, visited)
			if err != nil {
				return nil, err
			}
			entries = append(entries, chain...)
		}
	}

	// Append current host last so the outermost proxy (first connection) is first.
	entries = append(entries, HostEntry{Name: hostname, Config: cfg})
	return entries, nil
}

// IsTerminal reports whether stdout is an interactive terminal.
func IsTerminal() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

// titleCase converts a lowercase SSH key name to title case (e.g. "identityfile" → "IdentityFile").
// This matches standard SSH config file convention.
var titleCaseOverrides = map[string]string{
	"identityfile":                     "IdentityFile",
	"identityagent":                    "IdentityAgent",
	"identitiesonly":                   "IdentitiesOnly",
	"certificatefile":                  "CertificateFile",
	"casignaturealgorithms":            "CASignatureAlgorithms",
	"hostbasedacceptedalgorithms":      "HostbasedAcceptedAlgorithms",
	"hostkeyalgorithms":                "HostKeyAlgorithms",
	"kexalgorithms":                    "KexAlgorithms",
	"macs":                             "MACs",
	"pubkeyacceptedalgorithms":         "PubkeyAcceptedAlgorithms",
	"pubkeyauthentication":             "PubkeyAuthentication",
	"serveralivecountmax":              "ServerAliveCountMax",
	"serveraliveinterval":              "ServerAliveInterval",
	"tcpkeepalive":                     "TCPKeepAlive",
	"addkeystoagent":                   "AddKeysToAgent",
	"addressfamily":                    "AddressFamily",
	"batchmode":                        "BatchMode",
	"bindaddress":                      "BindAddress",
	"bindinterface":                    "BindInterface",
	"canonicaldomains":                 "CanonicalDomains",
	"canonicalizefallbacklocal":        "CanonicalizeFallbackLocal",
	"canonicalizehostname":             "CanonicalizeHostname",
	"canonicalizemaxdots":              "CanonicalizeMaxDots",
	"canonicalizepermittedcnames":      "CanonicalizePermittedCNAMEs",
	"checkhostip":                      "CheckHostIP",
	"ciphers":                          "Ciphers",
	"clearallforwardings":              "ClearAllForwardings",
	"compression":                      "Compression",
	"connectionattempts":               "ConnectionAttempts",
	"connecttimeout":                   "ConnectTimeout",
	"controlmaster":                    "ControlMaster",
	"controlpath":                      "ControlPath",
	"controlpersist":                   "ControlPersist",
	"dynamicforward":                   "DynamicForward",
	"enableescapecommandline":          "EnableEscapeCommandline",
	"enablesshkeysign":                 "EnableSSHKeysign",
	"escapechar":                       "EscapeChar",
	"exitonforwardfailure":             "ExitOnForwardFailure",
	"fingerprinthash":                  "FingerprintHash",
	"forkafterauthentication":          "ForkAfterAuthentication",
	"forwardagent":                     "ForwardAgent",
	"forwardx11":                       "ForwardX11",
	"forwardx11timeout":                "ForwardX11Timeout",
	"forwardx11trusted":                "ForwardX11Trusted",
	"gatewayports":                     "GatewayPorts",
	"globalknownhostsfile":             "GlobalKnownHostsFile",
	"gssapiauthentication":             "GSSAPIAuthentication",
	"gssapidelegatecredentials":        "GSSAPIDelegateCredentials",
	"hashknownhosts":                   "HashKnownHosts",
	"hostbasedauthentication":          "HostbasedAuthentication",
	"hostname":                         "Hostname",
	"ignoreunknown":                    "IgnoreUnknown",
	"ipqos":                            "IPQoS",
	"kerberosauthentication":           "KerberosAuthentication",
	"kerberosorlocal":                  "KerberosOrLocal",
	"localcommand":                     "LocalCommand",
	"localforward":                     "LocalForward",
	"loglevel":                         "LogLevel",
	"logverbose":                       "LogVerbose",
	"nohostauthenticationforlocalhost": "NoHostAuthenticationForLocalhost",
	"numberofpasswordprompts":          "NumberOfPasswordPrompts",
	"passwordauthentication":           "PasswordAuthentication",
	"permitlocalcommand":               "PermitLocalCommand",
	"permitremoteopen":                 "PermitRemoteOpen",
	"pkcs11provider":                   "PKCS11Provider",
	"port":                             "Port",
	"preferredauthentications":         "PreferredAuthentications",
	"proxyjump":                        "ProxyJump",
	"proxyusefdpass":                   "ProxyUseFdpass",
	"remotecommand":                    "RemoteCommand",
	"remoteforward":                    "RemoteForward",
	"requesttty":                       "RequestTTY",
	"rekeylimit":                       "RekeyLimit",
	"requiredrsasize":                  "RequiredRSASize",
	"sendenv":                          "SendEnv",
	"sessiontype":                      "SessionType",
	"setenv":                           "SetEnv",
	"securitykeyprovider":              "SecurityKeyProvider",
	"stdinnull":                        "StdinNull",
	"streamlocalbindmask":              "StreamLocalBindMask",
	"streamlocalbindunlink":            "StreamLocalBindUnlink",
	"stricthostkeychecking":            "StrictHostKeyChecking",
	"syslogfacility":                   "SyslogFacility",
	"tunneldevice":                     "TunnelDevice",
	"updatehostkeys":                   "UpdateHostKeys",
	"user":                             "User",
	"userknownhostsfile":               "UserKnownHostsFile",
	"verifyhostkeydns":                 "VerifyHostKeyDNS",
	"visualhostkey":                    "VisualHostKey",
	"xauthlocation":                    "XAuthLocation",
}

// TitleCaseKey converts a lowercase SSH key name to its canonical casing.
func TitleCaseKey(key string) string {
	if v, ok := titleCaseOverrides[key]; ok {
		return v
	}
	// Fallback: capitalize first letter only.
	if len(key) == 0 {
		return key
	}
	return strings.ToUpper(key[:1]) + key[1:]
}

// PriorityKeys defines the keys that are printed first in host-specific blocks,
// in the order they should appear. All other keys are printed alphabetically after.
var PriorityKeys = []string{"hostname", "hostkeyalias", "user", "port", "identityagent", "identityfile", "identitiesonly", "proxyjump"}

// PrintConfig writes the diff result as a valid SSH config block.
// When color is true, ANSI highlighting is applied. PriorityKeys are printed
// first in their defined order; remaining keys follow in alphabetical order.
func PrintConfig(hostname string, cfg Config, color bool) {
	if len(cfg) == 0 {
		return
	}

	const (
		bold     = "\033[1m"
		cyan     = "\033[36m"
		boldCyan = "\033[1;36m"
		reset    = "\033[0m"
	)

	if color {
		fmt.Printf("%sHost%s %s%s%s\n", bold, reset, boldCyan, hostname, reset)
	} else {
		fmt.Printf("Host %s\n", hostname)
	}

	// Skip the "host" key when its value is just the target hostname — it's ssh -G
	// metadata indicating which Host pattern matched, not a real config setting.
	printed := make(map[string]bool)
	if vals, ok := cfg["host"]; ok && len(vals) == 1 && vals[0] == hostname {
		printed["host"] = true
	}

	printKey := func(key string, values []string) {
		displayKey := TitleCaseKey(key)
		for _, v := range values {
			if color {
				fmt.Printf("    %s%-20s%s %s\n", cyan, displayKey, reset, v)
			} else {
				fmt.Printf("    %-20s %s\n", displayKey, v)
			}
		}
		printed[key] = true
	}

	// Print priority keys first for readability.
	for _, key := range PriorityKeys {
		if vals, ok := cfg[key]; ok {
			printKey(key, vals)
		}
	}

	// Collect and sort remaining keys.
	remaining := make([]string, 0, len(cfg))
	for k := range cfg {
		if !printed[k] {
			remaining = append(remaining, k)
		}
	}
	slices.Sort(remaining)
	for _, key := range remaining {
		printKey(key, cfg[key])
	}
}

// Baselines returns:
//   - withWildcard: SSH built-ins plus Host * / Match all settings (for diffing host-specific)
//   - wildcardConfig: only the user's Host * / Match all settings, with raw
//     (un-interpolated) values from the config file for any options that ssh -G
//     would have expanded with the random hostname.
func Baselines() (withWildcard, wildcardConfig Config, err error) {
	randHost := RandomHostname()

	withWildcard, err = RunG(randHost)
	if err != nil {
		return nil, nil, err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return withWildcard, nil, nil
	}

	sshDir := filepath.Join(home, ".ssh")
	configPath := filepath.Join(sshDir, "config")

	configContent, err := ReadConfig(configPath, sshDir)
	if err != nil {
		return withWildcard, nil, nil
	}

	modified := ModifyBaselineConfig(configContent, randHost)

	tmpFile, err := os.CreateTemp("", "ssh-inspect-baseline-*.conf")
	if err != nil {
		return nil, nil, fmt.Errorf("creating temp config: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	// Ensure the temp file is only readable by the owner, as it contains
	// the user's SSH config.
	if err := tmpFile.Chmod(0600); err != nil {
		tmpFile.Close()
		return nil, nil, fmt.Errorf("setting temp config permissions: %w", err)
	}

	if _, err := tmpFile.WriteString(modified); err != nil {
		tmpFile.Close()
		return nil, nil, fmt.Errorf("writing temp config: %w", err)
	}
	tmpFile.Close()

	pureDefaults, err := RunG(randHost, "-F", tmpFile.Name())
	if err != nil {
		return nil, nil, err
	}

	wildcardConfig = Diff(withWildcard, pureDefaults)

	// For values that ssh -G interpolated with the random hostname,
	// substitute the raw value from the config file.
	rawWildcard := ParseRawWildcardConfig(configContent)
	for key, vals := range wildcardConfig {
		for i, v := range vals {
			if strings.Contains(v, randHost) {
				if rawVals, ok := rawWildcard[key]; ok && i < len(rawVals) {
					wildcardConfig[key][i] = rawVals[i]
				}
			}
		}
	}

	return withWildcard, wildcardConfig, nil
}

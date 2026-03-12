package ssh

import (
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// TestParseOutput tests basic line parsing, multi-value keys, and empty input.
func TestParseOutput(t *testing.T) {
	t.Run("basic key-value pairs", func(t *testing.T) {
		input := "hostname myserver.example.com\nuser deploy\nport 22\n"
		got := ParseOutput(input)

		assertConfigValue(t, got, "hostname", []string{"myserver.example.com"})
		assertConfigValue(t, got, "user", []string{"deploy"})
		assertConfigValue(t, got, "port", []string{"22"})
	})

	t.Run("multi-value keys are accumulated", func(t *testing.T) {
		input := "identityfile ~/.ssh/id_rsa\nidentityfile ~/.ssh/id_ed25519\n"
		got := ParseOutput(input)

		assertConfigValue(t, got, "identityfile", []string{"~/.ssh/id_rsa", "~/.ssh/id_ed25519"})
	})

	t.Run("keys are lowercased", func(t *testing.T) {
		input := "HostName myserver.example.com\nUser deploy\n"
		got := ParseOutput(input)

		assertConfigValue(t, got, "hostname", []string{"myserver.example.com"})
		assertConfigValue(t, got, "user", []string{"deploy"})
	})

	t.Run("empty input returns empty map", func(t *testing.T) {
		got := ParseOutput("")
		if len(got) != 0 {
			t.Errorf("expected empty map, got %v", got)
		}
	})

	t.Run("values with spaces are preserved", func(t *testing.T) {
		input := "sendenv LANG LC_ALL LC_CTYPE\n"
		got := ParseOutput(input)

		assertConfigValue(t, got, "sendenv", []string{"LANG LC_ALL LC_CTYPE"})
	})

	t.Run("blank lines are skipped", func(t *testing.T) {
		input := "\nhostname myserver.example.com\n\nuser deploy\n"
		got := ParseOutput(input)

		if len(got) != 2 {
			t.Errorf("expected 2 keys, got %d: %v", len(got), got)
		}
	})
}

// TestDiff tests that Diff returns only keys whose values differ between effective and baseline.
func TestDiff(t *testing.T) {
	t.Run("identical configs return empty diff", func(t *testing.T) {
		cfg := Config{
			"hostname": {"myserver.example.com"},
			"user":     {"deploy"},
		}
		result := Diff(cfg, cfg)
		if len(result) != 0 {
			t.Errorf("expected empty diff, got %v", result)
		}
	})

	t.Run("differing value is included", func(t *testing.T) {
		effective := Config{"hostname": {"myserver.example.com"}, "user": {"deploy"}}
		baseline := Config{"hostname": {"localhost"}, "user": {"deploy"}}

		result := Diff(effective, baseline)

		assertConfigValue(t, result, "hostname", []string{"myserver.example.com"})
		if _, ok := result["user"]; ok {
			t.Errorf("expected 'user' to be absent (same in both), but it was present")
		}
	})

	t.Run("key present in effective but absent in baseline is included", func(t *testing.T) {
		effective := Config{"hostname": {"myserver.example.com"}, "identityfile": {"~/.ssh/deploy"}}
		baseline := Config{"hostname": {"myserver.example.com"}}

		result := Diff(effective, baseline)

		assertConfigValue(t, result, "identityfile", []string{"~/.ssh/deploy"})
		if _, ok := result["hostname"]; ok {
			t.Errorf("expected 'hostname' to be absent (same in both), but it was present")
		}
	})

	t.Run("multi-value key differing in one entry is included", func(t *testing.T) {
		effective := Config{"identityfile": {"~/.ssh/id_rsa", "~/.ssh/deploy"}}
		baseline := Config{"identityfile": {"~/.ssh/id_rsa"}}

		result := Diff(effective, baseline)

		assertConfigValue(t, result, "identityfile", []string{"~/.ssh/id_rsa", "~/.ssh/deploy"})
	})
}

// TestRandomHostname verifies the generated hostname has expected format and randomness.
func TestRandomHostname(t *testing.T) {
	h1 := RandomHostname()
	h2 := RandomHostname()

	if !strings.HasPrefix(h1, "no-match-") {
		t.Errorf("expected prefix 'no-match-', got %q", h1)
	}
	if !strings.HasSuffix(h1, ".invalid") {
		t.Errorf("expected suffix '.invalid', got %q", h1)
	}
	if h1 == h2 {
		t.Errorf("expected different hostnames each call, got %q twice", h1)
	}
}

// TestPrintConfigFiltersHostKey verifies that the "host" metadata key is suppressed
// from output when its value equals the target hostname.
func TestPrintConfigFiltersHostKey(t *testing.T) {
	cfg := Config{
		"host":     {"myserver"},
		"hostname": {"myserver.example.com"},
		"user":     {"deploy"},
	}

	// Capture stdout.
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	PrintConfig("myserver", cfg, false, false)

	w.Close()
	os.Stdout = old

	buf, _ := io.ReadAll(r)
	out := string(buf)

	if strings.Contains(out, "\n    Host ") {
		t.Errorf("expected 'host' key to be filtered, but found it in output:\n%s", out)
	}
	if !strings.Contains(out, "Hostname") {
		t.Errorf("expected 'Hostname' to appear in output:\n%s", out)
	}
}

// TestParseJumpHosts verifies ProxyJump value parsing for various formats.
func TestParseJumpHosts(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"bastion", []string{"bastion"}},
		{"user@bastion", []string{"bastion"}},
		{"bastion:22", []string{"bastion"}},
		{"user@bastion:2222", []string{"bastion"}},
		{"jump1,jump2", []string{"jump1", "jump2"}},
		{"user@jump1:2222,jump2.example.com", []string{"jump1", "jump2.example.com"}},
		{"none", nil},
		{"", nil},
	}
	for _, tt := range tests {
		got := ParseJumpHosts(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("ParseJumpHosts(%q) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range tt.want {
			if got[i] != tt.want[i] {
				t.Errorf("ParseJumpHosts(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

// TestResolveChain is an integration test that verifies chain resolution for localhost.
func TestResolveChain(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not found in PATH")
	}

	defaults, err := RunG(RandomHostname())
	if err != nil {
		t.Fatalf("failed to get defaults: %v", err)
	}

	entries, err := ResolveChain("localhost", defaults, make(map[string]bool))
	if err != nil {
		t.Fatalf("ResolveChain error: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one entry")
	}
	// Target host is always last; proxies (if any) precede it.
	if last := entries[len(entries)-1]; last.Name != "localhost" {
		t.Errorf("expected last entry to be 'localhost', got %q", last.Name)
	}
}

// TestRunG is an integration test that shells out to ssh.
func TestRunG(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not found in PATH")
	}

	cfg, err := RunG("localhost")
	if err != nil {
		t.Fatalf("RunG(localhost) error: %v", err)
	}
	if len(cfg) == 0 {
		t.Fatal("expected non-empty config for localhost")
	}
	if _, ok := cfg["hostname"]; !ok {
		t.Errorf("expected 'hostname' key in config, got keys: %v", configKeys(cfg))
	}
}

// TestParseKnownHostnames tests extraction of hostnames from known_hosts format.
func TestParseKnownHostnames(t *testing.T) {
	t.Run("extracts simple hostnames", func(t *testing.T) {
		input := "myserver.example.com ssh-rsa AAAA...\nbastion.example.com ecdsa-sha2-nistp256 AAAA...\n"
		got := ParseKnownHostnames(input)
		want := []string{"bastion.example.com", "myserver.example.com"}
		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("extracts comma-separated hostnames", func(t *testing.T) {
		input := "alpha.example.com,bravo.example.com ssh-rsa AAAA...\n"
		got := ParseKnownHostnames(input)
		want := []string{"alpha.example.com", "bravo.example.com"}
		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("extracts bracketed host:port entries", func(t *testing.T) {
		input := "[myserver.example.com]:2222 ssh-rsa AAAA...\n"
		got := ParseKnownHostnames(input)
		want := []string{"myserver.example.com"}
		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("skips hashed entries", func(t *testing.T) {
		input := "|1|abc123|def456 ssh-rsa AAAA...\nmyserver.example.com ssh-rsa AAAA...\n"
		got := ParseKnownHostnames(input)
		want := []string{"myserver.example.com"}
		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("skips comments and blank lines", func(t *testing.T) {
		input := "# a comment\n\nmyserver.example.com ssh-rsa AAAA...\n"
		got := ParseKnownHostnames(input)
		want := []string{"myserver.example.com"}
		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("deduplicates hostnames", func(t *testing.T) {
		input := "myserver.example.com ssh-rsa AAAA...\nmyserver.example.com ecdsa-sha2-nistp256 AAAA...\n"
		got := ParseKnownHostnames(input)
		want := []string{"myserver.example.com"}
		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("skips IP addresses", func(t *testing.T) {
		input := "192.168.1.1 ssh-rsa AAAA...\n10.0.0.1,myserver.example.com ssh-rsa AAAA...\n[::1]:22 ssh-rsa AAAA...\n"
		got := ParseKnownHostnames(input)
		want := []string{"myserver.example.com"}
		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("skips bare port numbers", func(t *testing.T) {
		input := "64242 ssh-rsa AAAA...\nmyserver.example.com ssh-rsa AAAA...\n"
		got := ParseKnownHostnames(input)
		want := []string{"myserver.example.com"}
		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("skips entries with stray brackets", func(t *testing.T) {
		input := "6[myserver.example.com]:64242 ssh-rsa AAAA...\nreal.example.com ssh-rsa AAAA...\n"
		got := ParseKnownHostnames(input)
		want := []string{"real.example.com"}
		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("empty input returns nil", func(t *testing.T) {
		got := ParseKnownHostnames("")
		if got != nil {
			t.Errorf("got %v, want nil", got)
		}
	})
}

// TestParseHostnames tests extraction of concrete hostnames from SSH config.
func TestParseHostnames(t *testing.T) {
	t.Run("extracts simple hostnames", func(t *testing.T) {
		input := "Host myserver\n    User deploy\nHost bastion\n    Port 22\n"
		got := ParseHostnames(input)
		want := []string{"bastion", "myserver"}
		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("skips wildcard patterns", func(t *testing.T) {
		input := "Host *\n    User deploy\nHost *.example.com\n    Port 22\nHost myserver\n    Port 22\n"
		got := ParseHostnames(input)
		want := []string{"myserver"}
		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("skips negated patterns", func(t *testing.T) {
		input := "Host !internal myserver\n    Port 22\n"
		got := ParseHostnames(input)
		want := []string{"myserver"}
		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("extracts multiple hostnames from one Host line", func(t *testing.T) {
		input := "Host alpha bravo\n    User deploy\n"
		got := ParseHostnames(input)
		want := []string{"alpha", "bravo"}
		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("deduplicates hostnames", func(t *testing.T) {
		input := "Host myserver\n    User a\nHost myserver\n    User b\n"
		got := ParseHostnames(input)
		want := []string{"myserver"}
		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("returns sorted results", func(t *testing.T) {
		input := "Host charlie\n    Port 1\nHost alpha\n    Port 2\nHost bravo\n    Port 3\n"
		got := ParseHostnames(input)
		want := []string{"alpha", "bravo", "charlie"}
		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("empty config returns nil", func(t *testing.T) {
		got := ParseHostnames("")
		if got != nil {
			t.Errorf("got %v, want nil", got)
		}
	})
}

// TestParseRawWildcardConfig tests extraction of options from Host * and Match all blocks.
func TestParseRawWildcardConfig(t *testing.T) {
	t.Run("extracts options from Host * block", func(t *testing.T) {
		input := "Host *\n    ControlMaster auto\n    ControlPath ~/.ssh/control/%h__%p__%r\n"
		got := ParseRawWildcardConfig(input)

		assertConfigValue(t, got, "controlmaster", []string{"auto"})
		assertConfigValue(t, got, "controlpath", []string{"~/.ssh/control/%h__%p__%r"})
	})

	t.Run("extracts options from Match all block", func(t *testing.T) {
		input := "Match all\n    AddKeysToAgent true\n"
		got := ParseRawWildcardConfig(input)

		assertConfigValue(t, got, "addkeystoagent", []string{"true"})
	})

	t.Run("ignores options from host-specific blocks", func(t *testing.T) {
		input := "Host myserver\n    User deploy\n\nHost *\n    ControlMaster auto\n"
		got := ParseRawWildcardConfig(input)

		if _, ok := got["user"]; ok {
			t.Error("expected host-specific 'user' to be excluded")
		}
		assertConfigValue(t, got, "controlmaster", []string{"auto"})
	})

	t.Run("handles multiple wildcard blocks", func(t *testing.T) {
		input := "Host *\n    User a\n\nHost *\n    SendEnv LANG\n"
		got := ParseRawWildcardConfig(input)

		assertConfigValue(t, got, "user", []string{"a"})
		assertConfigValue(t, got, "sendenv", []string{"LANG"})
	})

	t.Run("stops wildcard block at next Host/Match line", func(t *testing.T) {
		input := "Host *\n    ControlMaster auto\nHost myserver\n    User deploy\n"
		got := ParseRawWildcardConfig(input)

		assertConfigValue(t, got, "controlmaster", []string{"auto"})
		if _, ok := got["user"]; ok {
			t.Error("expected 'user' from non-wildcard block to be excluded")
		}
	})

	t.Run("bare Host * among other patterns is included", func(t *testing.T) {
		input := "Host *.example.com *\n    Port 2222\n"
		got := ParseRawWildcardConfig(input)

		assertConfigValue(t, got, "port", []string{"2222"})
	})

	t.Run("Host without bare star is excluded", func(t *testing.T) {
		input := "Host *.example.com\n    Port 2222\n"
		got := ParseRawWildcardConfig(input)

		if _, ok := got["port"]; ok {
			t.Error("expected non-wildcard Host to be excluded")
		}
	})
}

// TestModifyBaselineConfig tests that Host * and Match all lines are rewritten
// to exclude the given hostname.
func TestModifyBaselineConfig(t *testing.T) {
	const exclude = "no-match-abc123.invalid"

	t.Run("Host * gets exclusion added", func(t *testing.T) {
		input := "Host *\n    User deploy\n"
		got := ModifyBaselineConfig(input, exclude)
		want := "Host * !" + exclude + "\n    User deploy\n"
		if got != want {
			t.Errorf("got:\n%s\nwant:\n%s", got, want)
		}
	})

	t.Run("Host * among other patterns", func(t *testing.T) {
		input := "Host *.example.com *\n    User deploy\n"
		got := ModifyBaselineConfig(input, exclude)
		want := "Host *.example.com * !" + exclude + "\n    User deploy\n"
		if got != want {
			t.Errorf("got:\n%s\nwant:\n%s", got, want)
		}
	})

	t.Run("Host without bare star is unchanged", func(t *testing.T) {
		input := "Host myserver\n    User deploy\n"
		got := ModifyBaselineConfig(input, exclude)
		if got != input {
			t.Errorf("expected no change, got:\n%s", got)
		}
	})

	t.Run("Host *.example.com without bare star is unchanged", func(t *testing.T) {
		input := "Host *.example.com\n    User deploy\n"
		got := ModifyBaselineConfig(input, exclude)
		if got != input {
			t.Errorf("expected no change, got:\n%s", got)
		}
	})

	t.Run("Match all gets rewritten", func(t *testing.T) {
		input := "Match all\n    User deploy\n"
		got := ModifyBaselineConfig(input, exclude)
		want := "Match host !no-match-abc123.invalid\n    User deploy\n"
		if got != want {
			t.Errorf("got:\n%s\nwant:\n%s", got, want)
		}
	})

	t.Run("case insensitive Host and Match", func(t *testing.T) {
		input := "host *\n    User a\nMATCH ALL\n    User b\n"
		got := ModifyBaselineConfig(input, exclude)
		wantHost := "host * !" + exclude
		wantMatch := "MATCH host !" + exclude
		if !strings.Contains(got, wantHost) {
			t.Errorf("expected %q in output, got:\n%s", wantHost, got)
		}
		if !strings.Contains(got, wantMatch) {
			t.Errorf("expected %q in output, got:\n%s", wantMatch, got)
		}
	})

	t.Run("multiple Host * blocks are all modified", func(t *testing.T) {
		input := "Host *\n    User a\n\nHost myserver\n    User b\n\nHost *\n    SendEnv LANG\n"
		got := ModifyBaselineConfig(input, exclude)
		count := strings.Count(got, "!"+exclude)
		if count != 2 {
			t.Errorf("expected 2 exclusions, got %d in:\n%s", count, got)
		}
	})

	t.Run("indented Host * is handled", func(t *testing.T) {
		input := "  Host *\n    User deploy\n"
		got := ModifyBaselineConfig(input, exclude)
		want := "  Host * !" + exclude + "\n    User deploy\n"
		if got != want {
			t.Errorf("got:\n%s\nwant:\n%s", got, want)
		}
	})
}

// TestReadConfig tests reading SSH config files with Include resolution.
func TestReadConfig(t *testing.T) {
	tmp := t.TempDir()
	sshDir := tmp + "/.ssh"
	os.MkdirAll(sshDir, 0700)
	os.MkdirAll(sshDir+"/config.d", 0700)

	t.Run("reads a simple config file", func(t *testing.T) {
		path := sshDir + "/config_simple"
		os.WriteFile(path, []byte("Host myserver\n    User deploy\n"), 0600)

		got, err := ReadConfig(path, sshDir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(got, "Host myserver") || !strings.Contains(got, "User deploy") {
			t.Errorf("expected config content, got:\n%s", got)
		}
	})

	t.Run("resolves Include with absolute path", func(t *testing.T) {
		included := sshDir + "/extra"
		os.WriteFile(included, []byte("Host extra\n    Port 2222\n"), 0600)

		main := sshDir + "/config_inc_abs"
		os.WriteFile(main, []byte("Include "+included+"\nHost main\n    User root\n"), 0600)

		got, err := ReadConfig(main, sshDir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(got, "Host extra") {
			t.Errorf("expected included content, got:\n%s", got)
		}
		if !strings.Contains(got, "Host main") {
			t.Errorf("expected main content, got:\n%s", got)
		}
	})

	t.Run("resolves Include with glob pattern", func(t *testing.T) {
		os.WriteFile(sshDir+"/config.d/one.conf", []byte("Host one\n    Port 1111\n"), 0600)
		os.WriteFile(sshDir+"/config.d/two.conf", []byte("Host two\n    Port 2222\n"), 0600)

		main := sshDir + "/config_inc_glob"
		os.WriteFile(main, []byte("Include "+sshDir+"/config.d/*.conf\n"), 0600)

		got, err := ReadConfig(main, sshDir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(got, "Host one") || !strings.Contains(got, "Host two") {
			t.Errorf("expected both included hosts, got:\n%s", got)
		}
	})

	t.Run("resolves relative Include paths against sshDir", func(t *testing.T) {
		os.WriteFile(sshDir+"/relative_inc", []byte("Host relative\n    Port 3333\n"), 0600)

		main := sshDir + "/config_inc_rel"
		os.WriteFile(main, []byte("Include relative_inc\n"), 0600)

		got, err := ReadConfig(main, sshDir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(got, "Host relative") {
			t.Errorf("expected relative included content, got:\n%s", got)
		}
	})

	t.Run("missing include file is silently skipped", func(t *testing.T) {
		main := sshDir + "/config_missing_inc"
		os.WriteFile(main, []byte("Include /nonexistent/path\nHost ok\n    User root\n"), 0600)

		got, err := ReadConfig(main, sshDir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(got, "Host ok") {
			t.Errorf("expected remaining content, got:\n%s", got)
		}
	})

	t.Run("missing config file returns error", func(t *testing.T) {
		_, err := ReadConfig("/nonexistent/config", sshDir)
		if err == nil {
			t.Error("expected error for missing config file")
		}
	})
}

// assertConfigValue is a helper to check a key has expected values.
func assertConfigValue(t *testing.T, cfg Config, key string, want []string) {
	t.Helper()
	got, ok := cfg[key]
	if !ok {
		t.Errorf("key %q not found in config", key)
		return
	}
	if len(got) != len(want) {
		t.Errorf("key %q: got %v, want %v", key, got, want)
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("key %q[%d]: got %q, want %q", key, i, got[i], want[i])
		}
	}
}

// configKeys returns the keys of a Config for error messages.
func configKeys(m Config) []string {
	result := make([]string, 0, len(m))
	for k := range m {
		result = append(result, k)
	}
	return result
}

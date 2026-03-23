package cmd

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestEndToEnd runs the compiled binary as a subprocess and checks output.
func TestEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not found in PATH")
	}

	// Build binary to a temp file.
	tmp, err := os.MkdirTemp("", "ssh-inspect-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmp)

	binPath := tmp + "/ssh-inspect"
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = ".."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	t.Run("version prints version string", func(t *testing.T) {
		cmd := exec.Command(binPath, "version")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("version command failed: %v\n%s", err, out)
		}
		outStr := strings.TrimSpace(string(out))
		if outStr != "dev" {
			t.Errorf("expected 'dev', got: %q", outStr)
		}
	})

	t.Run("version with ldflags prints set version", func(t *testing.T) {
		// Rebuild with a custom version injected via ldflags.
		binVersioned := tmp + "/ssh-inspect-versioned"
		build := exec.Command("go", "build",
			"-ldflags", "-X ssh-inspect/cmd.Version=1.2.3",
			"-o", binVersioned, ".")
		build.Dir = ".."
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build with ldflags failed: %v\n%s", err, out)
		}

		cmd := exec.Command(binVersioned, "version")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("version command failed: %v\n%s", err, out)
		}
		outStr := strings.TrimSpace(string(out))
		if outStr != "1.2.3" {
			t.Errorf("expected '1.2.3', got: %q", outStr)
		}
	})

	t.Run("no args prints error to stderr and exits 1", func(t *testing.T) {
		cmd := exec.Command(binPath)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Error("expected non-zero exit, got success")
		}
		if !strings.Contains(string(out), "Error") {
			t.Errorf("expected error message, got: %q", string(out))
		}
	})

	t.Run("localhost output is valid SSH config blocks", func(t *testing.T) {
		cmd := exec.Command(binPath, "localhost")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("binary failed: %v", err)
		}
		outStr := string(out)
		// Either empty or starts with a Host block.
		if len(outStr) > 0 && !strings.HasPrefix(outStr, "Host ") {
			t.Errorf("expected output to start with 'Host ', got: %q", outStr)
		}
		// Every Host line must be a valid section header.
		for _, line := range strings.Split(outStr, "\n") {
			if strings.HasPrefix(line, "Host ") {
				// Valid section header.
				continue
			}
			if strings.HasPrefix(line, "    ") || line == "" {
				// Indented config line or blank separator.
				continue
			}
			if line != "" {
				t.Errorf("unexpected line format: %q", line)
			}
		}
	})
}

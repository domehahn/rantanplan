package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// ExecConfig configures isolated subprocess execution.
type ExecConfig struct {
	Command        []string          // Argv slice (Command[0] is executable, no sh -c)
	Dir            string            // Working directory
	Env            map[string]string // Custom environment overrides
	Timeout        time.Duration     // Execution wall-clock limit
	MaxStdoutBytes int               // Max output capture limit
}

// ExecResult contains execution outputs and metadata.
type ExecResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
	Duration time.Duration
	TimedOut bool
}

// RunSubprocess executes an external command with security boundaries and isolation controls.
func RunSubprocess(ctx context.Context, cfg ExecConfig) (*ExecResult, error) {
	if len(cfg.Command) == 0 {
		return nil, fmt.Errorf("empty command slice provided")
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, cfg.Command[0], cfg.Command[1:]...)
	if cfg.Dir != "" {
		cmd.Dir = cfg.Dir
	}

	// Sanitize environment: pass minimal safe system variables + explicit config env
	safeEnv := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin",
		"HOME=" + os.TempDir(),
		"TMPDIR=" + os.TempDir(),
	}
	for k, v := range cfg.Env {
		safeEnv = append(safeEnv, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = safeEnv

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	startTime := time.Now()
	err := cmd.Run()
	duration := time.Since(startTime)

	res := &ExecResult{
		Duration: duration,
		Stdout:   stdoutBuf.String(),
		Stderr:   stderrBuf.String(),
	}

	if max := cfg.MaxStdoutBytes; max > 0 && len(res.Stdout) > max {
		res.Stdout = res.Stdout[:max] + "\n...[truncated output]"
	}

	if ctx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		res.ExitCode = -1
		return res, fmt.Errorf("process execution timed out after %v", timeout)
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			res.ExitCode = exitErr.ExitCode()
		} else {
			res.ExitCode = -1
			return res, fmt.Errorf("failed to run process: %w", err)
		}
	} else {
		res.ExitCode = 0
	}

	return res, nil
}

// CreateTempWorkspace sets up a temporary directory with fixture files written inside it.
func CreateTempWorkspace(files []struct{ Path, Content string }) (string, func(), error) {
	tempDir, err := os.MkdirTemp("", "rantanplan-workspace-*")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp workspace: %w", err)
	}

	cleanup := func() {
		_ = os.RemoveAll(tempDir)
	}

	for _, f := range files {
		fullPath := filepath.Join(tempDir, f.Path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("failed to create parent dirs for %s: %w", f.Path, err)
		}
		if err := os.WriteFile(fullPath, []byte(f.Content), 0644); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("failed to write fixture file %s: %w", f.Path, err)
		}
	}

	return tempDir, cleanup, nil
}

//go:build e2e

// This fixture executable is built explicitly for process acceptance. It uses
// public HTTPS/MCP boundaries and imports no Gateway production package.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		if _, writeErr := fmt.Fprintln(os.Stderr, failureOutput(err)); writeErr != nil {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("fixture command required")
	}
	set := flag.NewFlagSet("e2e fixture", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	input := set.String("input", "", "private input JSON")
	if err := set.Parse(args[1:]); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return errors.New("unexpected argument")
	}
	switch args[0] {
	case "material":
		var request materialInput
		if err := readPrivate(*input, &request); err != nil {
			return err
		}
		result, err := material(request)
		if err != nil {
			return err
		}
		return writeOutput(out, result)
	case "mcp":
		var request callInput
		if err := readPrivate(*input, &request); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		result, err := callMCP(ctx, request)
		if err != nil {
			return err
		}
		return writeOutput(out, result)
	case "metadata":
		var request callInput
		if err := readPrivate(*input, &request); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		result, err := readMetadata(ctx, request)
		if err != nil {
			return err
		}
		return writeOutput(out, result)
	default:
		return errors.New("unknown fixture command")
	}
}

func readPrivate(path string, target any) error {
	if !filepath.IsAbs(path) {
		return errors.New("absolute private file required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > 1<<20 {
		return errors.New("invalid private file")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, opened) {
		return errors.Join(errors.New("private input changed"), file.Close())
	}
	decoder := json.NewDecoder(io.LimitReader(file, (1<<20)+1))
	decoder.DisallowUnknownFields()
	decodeErr := decoder.Decode(target)
	if decodeErr == nil {
		var extra any
		if err = decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			decodeErr = errors.New("multiple JSON values")
		}
	}
	return errors.Join(decodeErr, file.Close())
}

func privateWrite(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	return errors.Join(writeErr, file.Close())
}

// Bound the entire serialized stdout before writing any bytes to the capture.
// The newline is included in the fixed 2 MiB output budget.
func writeOutput(out io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) >= maxOutputBytes {
		return errors.New("fixture output limit exceeded")
	}
	data = append(data, '\n')
	n, err := out.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

// Only the exact normalized marker certifies successful fault cleanup. A joined
// or wrapped marker retains ordinary failure reporting and cannot pass E2E.
func failureOutput(err error) string {
	if err == errExpectedResponseLoss { //nolint:errorlint // Exact marker identity excludes joined or wrapped cleanup failures.
		return `{"code":"fixture_response_discarded"}`
	}
	return `{"code":"fixture_failed"}`
}

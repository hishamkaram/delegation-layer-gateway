// Package cli owns fixed command parsing and operator I/O. Runtime packages own
// networking, identity durability and actual cleanup; CLI owns no task state.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
)

const Version = "0.0.0-dev"
const (
	exitSuccess = 0
	exitRuntime = 1
	exitUsage   = 2
	exitCleanup = 3
)

type commandError struct {
	exit  int
	code  string
	cause error
}

func (e *commandError) Error() string { return e.code }
func (e *commandError) Unwrap() error { return e.cause }
func problem(exit int, code string, cause error) error {
	return &commandError{exit: exit, code: code, cause: cause}
}

type message struct {
	Code string `json:"code"`
}

const help = `Usage:
  gateway init --database ABS
  gateway identity --database ABS
  gateway migrate --database ABS
  gateway begin-recovery --database ABS --recovery-id ID
  gateway serve --config ABS
  gateway connector enroll --config ABS --token-file ABS [--replace-existing]
  gateway connector run --config ABS
  gateway admin --socket ABS --action ENUM --input-file ABS [--output-file ABS]
  gateway version

Admin actions: register-device, register-project, resolve-principal, put-grant,
revoke-grant, revoke-principal, revoke-device, issue-enrollment-token,
initialize-root, root-progress, abandon-root, refresh-project,
begin-recovery, register-recovery-root, register-routing-recovery-roster,
seal-recovery, recovery-progress,
advance-recovery, finish-recovery, list-administrative-tasks,
get-administrative-task, drain-administrative-task, list-routing-permits,
routing-drain-target, attest-routing-drained.
initialize-root advances one durable phase; repeat the same input until ready.
advance-recovery advances one durable phase for the selected device/root.
refresh-project inspects the selected project's current execution readiness.
After restoring a database, run offline begin-recovery before serve.
Use a fresh recovery ID for each distinct restore event.
issue-enrollment-token requires a new private --output-file.
Token files contain the JSON returned by issue-enrollment-token.
Inputs require bounded regular 0600 files. Credential outputs require a private
0700 parent and exclusive 0600 file. Secrets never belong in flag values.
Exit codes: 0 success; 2 usage/config; 1 runtime fault; 3 unconfirmed cleanup
or credential output after all owned work has returned.
`

// Run uses only the supplied context/writers. Signal registration belongs to
// main; errors are closed JSON codes and never include arguments or native data.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if ctx == nil || stdout == nil || stderr == nil {
		return exitUsage
	}
	if ctx.Err() != nil {
		return exitSuccess
	}
	if helpRequested(args) {
		if _, err := io.WriteString(stdout, help); err != nil {
			return exitRuntime
		}
		return exitSuccess
	}
	err := run(ctx, args, stdout)
	if err == nil {
		return exitSuccess
	}
	if errors.Is(err, flag.ErrHelp) {
		if _, writeErr := io.WriteString(stdout, help); writeErr != nil {
			return exitRuntime
		}
		return exitSuccess
	}
	var failure *commandError
	if !errors.As(err, &failure) {
		failure = &commandError{exit: exitRuntime, code: "runtime_failed"}
	}
	if encodeErr := json.NewEncoder(stderr).Encode(message{Code: failure.code}); encodeErr != nil {
		return exitRuntime
	}
	return failure.exit
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
	switch args[0] {
	case "version":
		if err := parse(flags("version"), args[1:]); err != nil {
			return err
		}
		return writeJSON(stdout, struct {
			Version string `json:"version"`
		}{Version})
	case "init", "identity", "migrate", "begin-recovery":
		return databaseCommand(ctx, args[1:], stdout, args[0])
	case "serve":
		return serve(ctx, args[1:], stdout)
	case "connector":
		return connector(ctx, args[1:], stdout)
	case "admin":
		return admin(ctx, args[1:], stdout)
	default:
		return problem(exitUsage, "invalid_arguments", nil)
	}
}

func flags(name string) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	return set
}

func parse(set *flag.FlagSet, args []string) error {
	if err := set.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return flag.ErrHelp
		}
		return problem(exitUsage, "invalid_arguments", err)
	}
	if set.NArg() != 0 {
		return problem(exitUsage, "invalid_arguments", nil)
	}
	return nil
}

func writeJSON[T any](writer io.Writer, value T) error {
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		return problem(exitRuntime, "output_unavailable", err)
	}
	return nil
}

func helpRequested(args []string) bool {
	if len(args) == 0 {
		return true
	}
	switch args[0] {
	case "-h", "--help", "help":
		return true
	default:
		return false
	}
}

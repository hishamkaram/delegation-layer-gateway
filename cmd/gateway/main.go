package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/hishamkaram/delegation-layer-gateway/internal/cli"
)

func main() {
	owner, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(owner, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

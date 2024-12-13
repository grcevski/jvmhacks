package main

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/grafana/jattach/jvm"
)

func validCommand(arg string) bool {
	validCmds := map[string]struct{}{
		"load":            {},
		"threaddump":      {},
		"dumpheap":        {},
		"setflag":         {},
		"properties":      {},
		"jcmd":            {},
		"inspectheap":     {},
		"datadump":        {},
		"printflag":       {},
		"agentProperties": {},
	}

	_, ok := validCmds[arg]
	return ok
}

func main() {
	logger := slog.With("component", "jattach")

	if len(os.Args) < 3 {
		fmt.Println("Usage: jattach <pid> <cmd> [args ...]")
		fmt.Println("Commands:")
		fmt.Println("    load  threaddump   dumpheap  setflag    properties")
		fmt.Println("    jcmd  inspectheap  datadump  printflag  agentProperties")
		os.Exit(1)
	}

	pid, err := strconv.Atoi(os.Args[1])
	if err != nil || pid <= 0 {
		fmt.Fprintf(os.Stderr, "%s is not a valid process ID\n", os.Args[1])
		os.Exit(1)
	}

	if ok := validCommand(os.Args[2]); !ok {
		fmt.Printf("%v is not a valid jattach command\n", os.Args[2])
		fmt.Println("Valid Commands:")
		fmt.Println("    load  threaddump   dumpheap  setflag    properties")
		fmt.Println("    jcmd  inspectheap  datadump  printflag  agentProperties")
		os.Exit(1)
	}

	status, err := jvm.EnableDynamicAgentLoading(pid)

	if err != nil {
		logger.Error("encountered error while enabling dynamic loading", "error", err)
	} else {
		logger.Info("dynamic loading status", "result", status)
	}

	out := make(chan []byte)

	go func() {
		for data := range out {
			os.Stdout.Write(data)
		}
	}()

	exitCode := jvm.Jattach(pid, os.Args[2:], out, logger)

	os.Exit(exitCode)
}

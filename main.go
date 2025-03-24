package main

import (
	"os"

	"github.com/aymaneallaoui/kafka-http-scanner/cmd"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

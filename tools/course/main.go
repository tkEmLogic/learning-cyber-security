package main

import (
	"os"

	"github.com/tkEmLogic/learning-cyber-security/internal/courseapp"
)

func main() {
	os.Exit(courseapp.Run(os.Args[1:], os.Stdout, os.Stderr))
}

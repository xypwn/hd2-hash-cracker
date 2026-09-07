package main

import (
	"bytes"
	"encoding/gob"
	"os"

	"github.com/xypwn/hd2-hash-cracker/pattern"
)

func main() {
	var out bytes.Buffer
	stdSrc, err := os.ReadFile("std.hcpat")
	if err != nil {
		panic(err)
	}
	rootFs, err := os.OpenRoot(".")
	var vars map[string]pattern.IrSegment
	if _, err := pattern.Compile(stdSrc, "-", rootFs.FS(), pattern.CompileOptions{OutVars: &vars}); err != nil {
		panic(err)
	}
	enc := gob.NewEncoder(&out)
	if err := enc.Encode(vars); err != nil {
		panic(err)
	}

	if err := os.WriteFile("std_vars.gob", out.Bytes(), 0666); err != nil {
		panic(err)
	}
}

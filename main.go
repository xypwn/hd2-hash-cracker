package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hellflame/argparse"
	"github.com/xypwn/gocl/cl-3.1"

	"github.com/xypwn/hd2-hash-cracker/cli"
	"github.com/xypwn/hd2-hash-cracker/hash"
	"github.com/xypwn/hd2-hash-cracker/pattern"
	pcl "github.com/xypwn/hd2-hash-cracker/pattern/cl"
	"github.com/xypwn/hd2-hash-cracker/stdlib"
	"github.com/xypwn/hd2-hash-cracker/util"
)

type cracker struct {
	ctx    context.Context
	err    error
	ctxErr error

	mu sync.Mutex
	// Guarded by mu //
	msgBuf            []string
	newHashes         map[string]struct{} // newly cracked hashes
	lastStr           string
	extraStatusStr    string
	triesCnt          int
	triesPerSecondBuf util.RingBuf[float64]
	// End           //
}

func runCracker(ctx context.Context, patternSrc []byte, patternFilename string, patternFs fs.FS, mode pcl.HashMode, targetHashes []uint64, datalibTargetHashes []uint64, workersHint int, writeClCode bool, keepGuessing bool) (newHashes []string, err error) {
	c := &cracker{
		ctx:       ctx,
		newHashes: make(map[string]struct{}),
	}

	prog, err := pattern.Compile(patternSrc, patternFilename, patternFs, pattern.CompileOptions{
		Vars: stdlib.Vars,
	})
	if err != nil {
		return nil, err
	}
	cli.Print("Pattern compiled successfully (total complexity: %d ≈ %.2e, max length: %d)", prog.Comp, float64(prog.Comp), prog.MaxLen())

	var workerErr error
	done := make(chan error)
	go func() {
		done <- crack(c, prog, mode, targetHashes, datalibTargetHashes, workersHint, writeClCode, keepGuessing)
		close(done)
	}()

loop:
	for range time.Tick(500 * time.Millisecond) {
		// update CLI status
		c.mu.Lock()
		tries := c.triesCnt
		lastStr := c.lastStr
		c.mu.Unlock()

		rateStr := "???"
		etaStr := "???"
		if c.triesPerSecondBuf.Len() != 0 {
			// Average the buffer values
			a, b := c.triesPerSecondBuf.PeekAll()
			rate := (util.Sum(a) + util.Sum(b)) / float64(c.triesPerSecondBuf.Len())
			rateStr = fmt.Sprintf("%.2fMH/s", rate/1e6)

			eta := time.Duration(float64(time.Second) * float64((prog.Comp - tries)) / float64(rate))
			etaStr = eta.Round(time.Second).String()
		}
		extraStatus := c.extraStatusStr
		if extraStatus != "" {
			extraStatus = ", " + extraStatus
		}
		cli.Status("Progress=%.3f%% (ETA %s), Rate=%s, Last=%q%s", float64(tries)/float64(prog.Comp)*100, etaStr, rateStr, lastStr, extraStatus)

		for c.triesPerSecondBuf.Len() > 20 {
			c.triesPerSecondBuf.Read()
		}

		c.mu.Lock()
		for _, s := range c.msgBuf {
			cli.Print("%s", s)
		}
		c.msgBuf = c.msgBuf[:0]
		c.mu.Unlock()

		select {
		case workerErr = <-done:
			if workerErr == nil {
				cli.Print("Worker done")
			}
			break loop
		default:
		}
		if ctx.Err() != nil {
			cli.Print("Shutting down worker")
			workerErr = <-done
			break loop
		}
	}

	if err := workerErr; err != nil {
		return nil, err
	}
	return slices.Sorted(maps.Keys(c.newHashes)), nil
}

func (c *cracker) Msg(format string, args ...any) {
	s := fmt.Sprintf(format, args...)
	c.mu.Lock()
	c.msgBuf = append(c.msgBuf, s)
	c.mu.Unlock()
}

func (c *cracker) Status(format string, args ...any) {
	s := fmt.Sprintf(format, args...)
	c.mu.Lock()
	c.extraStatusStr = s
	c.mu.Unlock()
}

func crack(c *cracker, prog pattern.Segment, mode pcl.HashMode, targetHashes []uint64, datalibTargetHashes []uint64, workersHint int, writeClCode bool, keepGuessing bool) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	platforms, err := cl.GetPlatformIDs()
	if err != nil {
		return err
	}
	if len(platforms) == 0 {
		return fmt.Errorf("no OpenCL platforms")
	}
	platform := platforms[0]
	platformName, err := cl.GetPlatformInfo[string](platform, cl.PLATFORM_NAME)
	if err != nil {
		return err
	}
	devices, err := cl.GetDeviceIDs(platform, cl.DEVICE_TYPE_GPU)
	if err != nil {
		return err
	}
	if len(devices) == 0 {
		return fmt.Errorf("no OpenCL devices")
	}
	device := devices[0]
	deviceName, err := cl.GetDeviceInfo[string](device, cl.DEVICE_NAME)
	if err != nil {
		return err
	}
	c.Msg("Using OpenCL platform %q with device %q", platformName, deviceName)

	crackerOpts := pcl.Options{
		Workers: max(workersHint/2, 256),
		Tries:   8192,
	}
	tuner := NewTuner(crackerOpts.Workers, crackerOpts.Tries)

	c.Msg("Initializing buffers and compiling OpenCL kernel")
	cr, err := pcl.NewCracker(device, prog, mode, targetHashes, crackerOpts)
	if err != nil {
		return err
	}
	defer cr.Delete()

	if writeClCode {
		if err := os.WriteFile("kernel.cl", []byte(cr.DebugInfo.OpenClCode), 0666); err != nil {
			return err
		}
		c.Msg("wrote generated OpenCL code to kernel.cl")
	}

	var datalibTargetHashesSet map[uint64]struct{}
	if mode == pcl.HashDatalib {
		datalibTargetHashesSet = make(map[uint64]struct{})
		for _, h := range datalibTargetHashes {
			datalibTargetHashesSet[h] = struct{}{}
		}
	}

	c.Msg("Making guesses")
	c.Status("Warming up / collecting baseline")
	prevTotalIdx := 0
	var prevTime time.Time
	idx := prog.MakeIndex()
	for {
		matches, err := cr.Dispatch()
		if err == pcl.Done {
			break
		} else if err != nil {
			return err
		}
		idx.Reset()
		if cr.TotalIdx() > 0 {
			idx.Add(prog, cr.TotalIdx())
		}

		for _, s := range matches {
			if mode == pcl.HashDatalib {
				// Prevent collision-based false positives that may happen
				// due to our splitmixing for datalib hashes.
				h := (uint64(len(s)) << 32) | uint64(hash.DatalibHashSum(s))
				if _, ok := datalibTargetHashesSet[h]; !ok {
					continue
				}
			}

			c.mu.Lock()
			_, wasntNew := c.newHashes[s]
			c.mu.Unlock()
			if wasntNew {
				continue
			}
			var hashHex string
			switch mode {
			case pcl.HashMurmur64a:
				hashHex = fmt.Sprintf("%016x", hash.Murmur64aSum(s))
			case pcl.HashMurmur64aThin:
				hashHex = fmt.Sprintf("%08x", hash.Thin(hash.Murmur64aSum(s)))
			case pcl.HashDatalib:
				hashHex = fmt.Sprintf("%08x", hash.DatalibHashSum(s))
			}
			c.Msg("found: %s = %s", hashHex, s)
			c.mu.Lock()
			c.newHashes[s] = struct{}{}
			c.mu.Unlock()
		}

		now := time.Now()
		newTries := cr.TotalIdx() - prevTotalIdx
		var lastStr string
		{
			idx.Reset()
			idx.Add(prog, cr.TotalIdx())
			lastStr = prog.StringAt(idx)
		}
		triesPerSecond := float64(-1)
		if !prevTime.IsZero() {
			triesPerSecond = float64(newTries) / now.Sub(prevTime).Seconds()
		}

		c.mu.Lock()
		c.triesCnt += newTries
		c.lastStr = lastStr
		if triesPerSecond >= 0 {
			c.triesPerSecondBuf.Write(triesPerSecond)
		}
		allFound := len(c.newHashes) == len(targetHashes)
		c.mu.Unlock()

		if w, t, done, changed := tuner.Step(int(cr.LastComputeRunDuration().Nanoseconds()), newTries); changed {
			var tuneStr string
			if done {
				tuneStr = "Tuned"
			} else {
				tuneStr = "Tuning"
			}
			c.Status("%s (WxT=%dx%d)", tuneStr, w, t)
			cr.ChangeNumWorkers(w)
			cr.ChangeNumTries(t)
		}

		prevTotalIdx = cr.TotalIdx()
		prevTime = now

		if allFound && !keepGuessing {
			c.Msg("All hashes found")
			break
		}

		if c.ctx.Err() != nil {
			return err
		}
	}
	return nil
}

func run() error {
	var epilog strings.Builder
	{
		// TODO: Pattern syntax guide
	}

	argp := argparse.NewParser("hd2-hash-cracker", "Helldivers 2 filename hash cracking tool", &argparse.ParserConfig{
		EpiLog: epilog.String(),
	})
	optMode := argp.String("m", "mode", &argparse.Option{
		Choices: []any{"M", "m", "d"},
		Default: "M",
		Help:    "select type of hash to crack (M = murmurhash64a [default], m = murmurhash64a thin, d = datalib hash)",
	})
	optExpr := argp.Flag("e", "expr", &argparse.Option{
		Help: "evaluate expression instead of input file",
	})
	optInput := argp.String("", "input", &argparse.Option{
		Help:       "input file (or expression if -e is set)",
		Positional: true,
		Required:   true,
	})
	optHashes := argp.String("t", "target", &argparse.Option{
		Help: "custom file listing target hashes to crack (default is builtin unknown HD2 hashes for selected mode)",
	})
	optOutput := argp.String("o", "output", &argparse.Option{
		Help: "output file to append found hashes to (default is cracked.txt for murmur64a, cracked_thin.txt for murmur64a thin, or cracked_datalib.txt for datalib hash)",
	})
	optWorkersHint := argp.Int("w", "workers", &argparse.Option{
		Help: "hint to number of workers; increasing this to ~5000+/- may speed up the tuning process, but can also worsen performance significantly; very dependent on your system and pattern",
	})
	optCpuProfile := argp.Flag("", "debug-cpuprofile", &argparse.Option{
		Help: "(debug) write CPU profile to file cpu.prof",
	})
	optWriteClCode := argp.Flag("", "debug-oclcode", &argparse.Option{
		Help: "(debug) write generated OpenCL code to file kernel.cl",
	})
	optKeepGuessing := argp.Flag("", "keep-guessing", &argparse.Option{
		Help: "continue guessing even after all hashes are found",
	})

	if err := argp.Parse(nil); err != nil {
		if errors.Is(err, argparse.BreakAfterHelpError) {
			return nil
		}
		return err
	}

	var hashMode pcl.HashMode
	switch *optMode {
	case "M":
		hashMode = pcl.HashMurmur64a
	case "m":
		hashMode = pcl.HashMurmur64aThin
	case "d":
		hashMode = pcl.HashDatalib
	default:
		panic(fmt.Sprintf("unknown hash mode %q", *optMode))
	}

	if *optCpuProfile {
		const filename = "cpu.prof"
		f, err := os.Create(filename)
		if err != nil {
			return fmt.Errorf("creating CPU profile file: %w", err)
		}
		cli.Print("Starting CPU profile")
		if err := pprof.StartCPUProfile(f); err != nil {
			return fmt.Errorf("starting CPU profile: %w", err)
		}
		defer func() {
			pprof.StopCPUProfile()
			cli.Print("CPU profile written to %s", filename)
		}()
	}

	workDir, err := os.Getwd()
	if err != nil {
		return err
	}
	var patternSrc []byte
	var patternFilename string
	patternRootFs, err := os.OpenRoot(workDir)
	if err != nil {
		return err
	}
	if *optExpr {
		patternFilename = "-"
		patternSrc = []byte(*optInput)
	} else {
		b, err := fs.ReadFile(patternRootFs.FS(), filepath.ToSlash(filepath.Clean(*optInput)))
		if err != nil {
			return fmt.Errorf("reading input file: %w", err)
		}
		patternFilename = *optInput
		patternSrc = b
	}

	var targetHashes []uint64
	var datalibTargetHashes []uint64 // if datalib mode: target hashes without splitmixing
	{
		var data []byte
		if *optHashes != "" {
			var err error
			data, err = os.ReadFile(*optHashes)
			if err != nil {
				return fmt.Errorf("reading target hashes file: %w", err)
			}
		} else {
			switch hashMode {
			case pcl.HashMurmur64a:
				data = stdlib.TargetHashesMurmur64a
			case pcl.HashMurmur64aThin:
				data = stdlib.TargetHashesMurmur64aThin
			case pcl.HashDatalib:
				data = stdlib.TargetHashesDatalib
			}
		}
		for line := range bytes.SplitSeq(data, []byte("\n")) {
			line = bytes.TrimSuffix(line, []byte("\r"))
			if len(line) == 0 {
				continue
			}
			if bytes.HasPrefix(line, []byte("//")) || bytes.HasPrefix(line, []byte("#")) {
				continue
			}

			var h uint64
			var hDatalib uint64
			var err error
			switch hashMode {
			case pcl.HashMurmur64a:
				h, err = hash.Parse64(string(line))
			case pcl.HashMurmur64aThin:
				var h32 uint32
				h32, err = hash.Parse32(string(line))
				h = uint64(h32)
			case pcl.HashDatalib:
				hashStr, lenStr, ok := bytes.Cut(line, []byte("##"))
				if !ok {
					err = fmt.Errorf("expected <hash>##<length>, but got %q (please ensure you provided a datalib hash list)", line)
				}
				var h32 uint32
				var l uint64
				h32, err = hash.Parse32(string(hashStr))
				if err != nil {
					break
				}
				l, err = strconv.ParseUint(string(lenStr), 10, 32)
				hDatalib = (l << 32) | uint64(h32) // pack length and actual hash into a single u64
				h = hash.SplitMix64(hDatalib)
			}
			if err != nil {
				var sfx string
				if errors.Is(err, strconv.ErrRange) && hashMode.Bits() == 32 {
					sfx = " (it looks like you selected a 32-bit hash, but gave a 64-bit hash list)"
				}
				return fmt.Errorf("parsing target hash: %w%s", err, sfx)
			}
			targetHashes = append(targetHashes, h)
			if hashMode == pcl.HashDatalib {
				datalibTargetHashes = append(datalibTargetHashes, hDatalib)
			}
		}
		slices.Sort(targetHashes)
		util.Uniq(targetHashes)
		if hashMode.Bits() == 64 {
			all32Bit := true
			for _, h := range targetHashes {
				if h > math.MaxUint32 {
					all32Bit = false
					break
				}
			}
			if len(targetHashes) > 0 && all32Bit {
				cli.Error("All target hashes look like they're 32-bit, but you have selected a 64-bit hash mode. Please ensure that you gave the correct hash list.")
			}
		}
	}

	cli.Print("Ctrl+C to quit")
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	newHashes, err := runCracker(ctx, patternSrc, patternFilename, patternRootFs.FS(), hashMode, targetHashes, datalibTargetHashes, *optWorkersHint, *optWriteClCode, *optKeepGuessing)
	if err != nil {
		return err
	}

	// Write back new hash strings to output file by appending and deduplicating
	{
		outputFile := *optOutput
		if outputFile == "" {
			switch hashMode {
			case pcl.HashMurmur64a:
				outputFile = "cracked.txt"
			case pcl.HashMurmur64aThin:
				outputFile = "cracked_thin.txt"
			case pcl.HashDatalib:
				outputFile = "cracked_datalib.txt"
			}
		}
		cli.Print("Adding %d hashes to %s", len(newHashes), outputFile)
		b, err := os.ReadFile(outputFile)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		var lines [][]byte
		if b != nil {
			lines = bytes.Split(b, []byte("\n"))
			for i := range lines {
				lines[i] = bytes.TrimSuffix(lines[i], []byte("\r"))
			}
			lines = slices.DeleteFunc(lines, func(b []byte) bool { return len(b) == 0 })
		}
		for _, h := range newHashes {
			lines = append(lines, []byte(h))
		}
		slices.SortFunc(lines, bytes.Compare)
		lines = util.UniqFunc(lines, bytes.Equal)
		if err := os.WriteFile(outputFile, bytes.Join(lines, []byte("\n")), 0666); err != nil {
			return err
		}
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		cli.Error("Error: %v", err)
	}
	os.Stderr.WriteString("\n")
}

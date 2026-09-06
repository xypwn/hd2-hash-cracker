package cl

import (
	"errors"
	"fmt"
	"time"

	cl "github.com/xypwn/gocl/cl-3.1"
	"github.com/xypwn/hd2-hash-cracker/pattern"
)

var Done = errors.New("cracker done")

// Options meant for debugging and/or testing.
// You probably don't need to touch these.
type DebugOptions struct {
	// Treat any guess as valid. Used for testing
	// index synchronization.
	AcceptAllAsMatch bool
	// Set to start at a candidate that isn't the first.
	InitialTotalIdx int
}

// Advanced options for the cracker.
//
// Any zeroed field will be treated as if set to
// its default value.
type Options struct {
	// Number of workers to run concurrently (default: 4096).
	Workers int
	// Minimum length of the match buffer per worker; determines
	// how many matches can be output without returning early.
	// The final match buffer length is guaranteed to be able
	// to hold 2 maximum length candidates (default: 128).
	MinMatchBufLen int
	// Number of tries per worker per dispatch (default: 65536).
	Tries int

	// Options meant for debugging and/or testing.
	// You probably don't need to touch these.
	Debug DebugOptions
}

type Cracker struct {
	DebugInfo struct {
		OpenClCode string
	}

	newWorkers int

	hashMode              HashMode
	device                cl.DeviceId
	context               cl.Context
	queue                 cl.CommandQueue
	kernel                cl.Kernel
	opts                  Options
	prog                  pattern.Segment
	bufs                  *clBuffers
	idx                   pattern.SegIdx
	totalIdx              int
	lastKernelRunDuration time.Duration
}

func NewCracker(device cl.DeviceId, prog pattern.Segment, mode HashMode, targetHashes []uint64, opts Options) (_ *Cracker, err error) {
	if opts.Workers == 0 {
		opts.Workers = 4096
	}
	if opts.MinMatchBufLen == 0 {
		opts.MinMatchBufLen = 128
	}
	if opts.Tries == 0 {
		opts.Tries = 65536
	}
	c := &Cracker{
		hashMode: mode,
		prog:     prog,
		idx:      prog.MakeIndex(),
		opts:     opts,
		totalIdx: opts.Debug.InitialTotalIdx,
	}
	defer func() {
		if err != nil {
			if clErr := (*cl.Error)(nil); errors.As(err, &clErr) {
				err = fmt.Errorf("OpenCL: %w", err)
			}
			c.Delete()
		}
	}()

	c.context, err = cl.CreateContext(nil, []cl.DeviceId{device}, nil)
	if err != nil {
		return nil, err
	}

	matchBufLen := opts.MinMatchBufLen
	matchBufLen = max(matchBufLen, 2*(prog.MaxLen()+1))
	c.bufs, err = makeClBuffers(c.context, prog, mode, targetHashes, opts.Workers, matchBufLen)
	if err != nil {
		return nil, fmt.Errorf("creating buffers: %w", err)
	}

	code := string(generateClCode(prog, c.bufs))
	if opts.Debug.AcceptAllAsMatch {
		code = "#define DEBUG_ACCEPT_ALL_AS_MATCH\n\n" + code
	}
	c.DebugInfo.OpenClCode = code
	program, err := cl.CreateProgramWithSource(c.context, []string{code})
	if err != nil {
		return nil, fmt.Errorf("creating program: %w", err)
	}
	defer cl.ReleaseProgram(program)
	if err := cl.BuildProgram(program, []cl.DeviceId{device}, "", nil); err != nil {
		var errLog string
		if err := cl.GetProgramBuildInfo(program, device, cl.PROGRAM_BUILD_LOG, &errLog); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("compiling program: %s", errLog)
	}
	c.kernel, err = cl.CreateKernel(program, "kmain")
	if err != nil {
		return nil, fmt.Errorf("creating kernel: %w", err)
	}
	if err := c.setKernelArgValues(); err != nil {
		return nil, err
	}

	c.queue, err = cl.CreateCommandQueueWithProperties(c.context, device, nil)
	if err != nil {
		return nil, fmt.Errorf("creating command queue: %w", err)
	}
	return c, nil
}

func (c *Cracker) Delete() {
	if c.context != nil {
		cl.ReleaseContext(c.context)
	}
	if c.queue != nil {
		cl.ReleaseCommandQueue(c.queue)
	}
	if c.kernel != nil {
		cl.ReleaseKernel(c.kernel)
	}
	if c.bufs != nil {
		c.bufs.Delete()
	}
}

func (c *Cracker) setKernelArgValues() error {
	var targetHashesMem cl.Mem
	switch c.hashMode.Bits() {
	case 64:
		targetHashesMem = c.bufs.bs.targetHashes64.Mem
	case 32:
		targetHashesMem = c.bufs.bs.targetHashes32.Mem
	default:
		panic("invalid hash mod bit size")
	}
	if err := cl.SetKernelArgValues(c.kernel, 0,
		c.bufs.bs.tries.Mem, c.bufs.bs.idxs.Mem,
		c.bufs.bs.strs.Mem, c.bufs.bs.strsOffsets.Mem, c.bufs.bs.strLens.Mem,
		c.bufs.bs.hashBitmap.Mem, targetHashesMem,
		c.bufs.bs.matchFound.Mem, c.bufs.bs.matches.Mem, c.bufs.bs.matchesLens.Mem); err != nil {
		return fmt.Errorf("setting arg values: %w", err)
	}
	return nil
}

// TotalIdx returns the total iteration index,
// which is approximately the number of total
// strings checked.
func (c *Cracker) TotalIdx() int {
	return c.totalIdx
}

func (c *Cracker) LastKernelRunDuration() time.Duration {
	return c.lastKernelRunDuration
}

// Will be realized once no matches were found in the previous dispatch.
func (c *Cracker) ChangeNumWorkers(newNumWorkers int) {
	c.newWorkers = newNumWorkers
}

func (c *Cracker) ChangeNumTries(newNumTries int) {
	c.opts.Tries = newNumTries
}

// Dispatch dispatches a single batch of workers.
//
// Returns a slice with any newly found matching strings.
//
// Returns nil, [Done] when done.
func (c *Cracker) Dispatch() (matches []string, err error) {
	// Initialize new buffer values
	{
		matchFound := c.bufs.bs.matchFound.Items[0] != 0

		// Resize buffer if requested and no match was found
		// (otherwise we would falsely zero all fields in the
		// tries and matchesLens buffers).
		if c.newWorkers != 0 && c.newWorkers != c.opts.Workers && !matchFound {
			if err := c.bufs.ResizeToWorkers(c.context, c.queue, c.newWorkers); err != nil {
				return nil, err
			}
			c.opts.Workers = c.newWorkers
			if err := c.setKernelArgValues(); err != nil {
				return nil, err
			}
		}

		fillTries := true
		done := true
		for i := range c.bufs.numWorkers {
			if matchFound && // tries is only valid if a match was found
				c.bufs.bs.tries.Items[i] != 0 {
				// Worker stopped early because result
				// buffer was full.
				done = false
				fillTries = false
				continue
			}
			c.idx.Reset()
			if c.totalIdx > 0 {
				c.idx.Add(c.prog, c.totalIdx)
			}
			readIdx(c.bufs.bs.idxs.Items[i*c.bufs.idxLen:], c.prog, c.idx)
			tries := c.opts.Tries
			if c.totalIdx+tries > c.prog.Comp {
				tries = c.prog.Comp - c.totalIdx
				fillTries = false
			}
			c.bufs.bs.tries.Items[i] = uint32(tries)
			c.totalIdx += tries
			if tries > 0 {
				done = false
			}
		}
		if done {
			return nil, Done
		}
		c.bufs.bs.matchFound.Items[0] = 0
		//fmt.Println("tries:", c.bufs.data.tries)
		//fmt.Println("matches:", c.bufs.data.matchesLens)
		triesFillValue := 0 // read from host buffer (don't just fill)
		if fillTries {
			// faster: fill all tries with the same value
			triesFillValue = c.opts.Tries
		}
		if err := c.bufs.write(c.queue,
			// If the tries buffer has the same value every
			// where, we just fill by pattern instead of
			// copying byte-by-byte.
			uint32(triesFillValue),
			// If no match was found, we know matchLens is
			// still zero everywhere, and hence there's no
			// reason to zero matchLens.
			matchFound,
		); err != nil {
			return nil, fmt.Errorf("writing buffers: %w", err)
		}
	}

	// Actual OpenCL dispatch
	tStart := time.Now()
	if err := cl.EnqueueNDRangeKernel(c.queue, c.kernel, 1, nil, []uint64{uint64(c.bufs.numWorkers)}, nil, nil, nil); err != nil {
		return nil, fmt.Errorf("running kernel: %w", err)
	}
	if err := cl.Finish(c.queue); err != nil {
		return nil, fmt.Errorf("finishing queue: %w", err)
	}
	c.lastKernelRunDuration = time.Since(tStart)

	// Read back necessary data
	{
		// The most common case is no match found, meaning every
		// worker finished its assigned tries and we don't have
		// to read back any further buffers.
		if err := c.bufs.readMatchFound(c.queue); err != nil {
			return nil, fmt.Errorf("reading back data: %w", err)
		}
		matchFound := c.bufs.bs.matchFound.Items[0] != 0

		if matchFound {
			// We only need to read back additional data if a match was found;
			// if no match was found, we always know that all tries were
			// exhausted and matchLens is zero everywhere.
			if err := c.bufs.readTriesIdxsAndMatches(c.queue); err != nil {
				return nil, fmt.Errorf("reading back data: %w", err)
			}

			// Match buffers are only valid if a match was found
			matches = c.bufs.getMatches()
		}
	}

	return
}

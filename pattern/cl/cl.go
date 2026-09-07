package cl

import (
	"bytes"
	_ "embed"
	"fmt"
	"math"
	"runtime"
	"slices"
	"strings"
	"unicode/utf8"

	cl "github.com/xypwn/gocl/cl-3.1"
	"github.com/xypwn/hd2-hash-cracker/pattern"
	"github.com/xypwn/hd2-hash-cracker/util"
)

//go:embed prelude.cl
var preludeClCode string

type HashMode int

const (
	HashMurmur64a = iota
	HashMurmur64aThin
	HashDatalib
)

func (m HashMode) String() string {
	switch m {
	case HashMurmur64a:
		return "murmurhash 64a"
	case HashMurmur64aThin:
		return "murmurhash 64a thin"
	case HashDatalib:
		return "datalib"
	default:
		panic("unhandled case")
	}
}

func (m HashMode) Bits() int {
	switch m {
	case HashMurmur64a:
		return 64
	case HashMurmur64aThin, HashDatalib:
		return 32
	default:
		panic("unhandled case")
	}
}

// Returns the number of elements needed in the index
// for the given program.
func getSegmentIdxLen(s pattern.Segment) int {
	n := 0
	for _, segs := range s.Segs {
		n += 1
		for _, seg := range segs {
			n += getSegmentIdxLen(seg)
		}
	}
	return n
}

// Reads the SegIdx into a flat array.
func readIdx(dest []uint32, s pattern.Segment, idx pattern.SegIdx) int {
	p := 0
	for i, segs := range s.Segs {
		dest[p] = uint32(idx.Idxs[i])
		p++
		if s.Comps[i] != len(s.Segs[i]) {
			for j, seg := range segs {
				p += readIdx(dest[p:], seg, idx.Segs[i][j])
			}
		}
	}
	return p
}

type clBuffers struct {
	hashMode         HashMode
	strArrs          [][]string
	strArrsFirstIdxs []int
	numWorkers       int
	idxLen           int
	matchBufLen      int
	maxCandidateLen  int
	bs               struct { // buffers
		tries          cl.BackedBuffer[uint32]
		idxs           cl.BackedBuffer[uint32]
		strs           cl.BackedBuffer[byte]
		strsOffsets    cl.BackedBuffer[uint32]
		strLens        cl.BackedBuffer[uint32]
		hashBitmap     cl.BackedBuffer[uint32]
		targetHashes32 cl.BackedBuffer[uint32]
		targetHashes64 cl.BackedBuffer[uint64]
		matchFound     cl.BackedBuffer[int32] // len always 1
		matches        cl.BackedBuffer[byte]
		matchesLens    cl.BackedBuffer[uint32]
	}
}

func makeClBuffers(context cl.Context, s pattern.Segment, hashMode HashMode, targetHashes []uint64, numWorkers, matchBufLen int) (*clBuffers, error) {
	var targetHashes32 []uint32
	var targetHashes64 []uint64
	switch hashMode.Bits() {
	case 32:
		targetHashes32 = make([]uint32, len(targetHashes))
		for i, h := range targetHashes {
			if h > math.MaxUint32 {
				return nil, fmt.Errorf("expected 32-bit-only hashes for mode %s, but got 64-bit hash 0x%016x", hashMode.String(), h)
			}
			targetHashes32[i] = uint32(h)
		}
	case 64:
		targetHashes64 = slices.Clone(targetHashes)
	default:
		panic("unhandled target hash bits")
	}

	b := &clBuffers{
		hashMode:        hashMode,
		numWorkers:      numWorkers,
		idxLen:          getSegmentIdxLen(s),
		matchBufLen:     matchBufLen,
		maxCandidateLen: s.MaxLen(),
	}

	if b.matchBufLen < b.maxCandidateLen+1 {
		return nil, fmt.Errorf("matchBufLen (%d) must be at least 1 more than the maximum candidate string length (%d)", b.matchBufLen, b.maxCandidateLen)
	}

	var check func(s pattern.Segment) error
	check = func(s pattern.Segment) error {
		if s.Comp == math.MaxInt {
			return fmt.Errorf("pattern: complexity must be less than 64-bit signed integer limit")
		}
		for _, segs := range s.Segs {
			if len(segs) > math.MaxUint32 {
				return fmt.Errorf("pattern: operands of union must be no more than the 32-bit unsigned integer limit (4294967295)")
			}
			for _, seg := range segs {
				if err := check(seg); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := check(s); err != nil {
		return nil, err
	}

	// Collect string arrays for all cases
	// of unions of single string operands.
	var strs []byte
	var strsOffsets []uint32
	var strLens []uint32
	{
		var addStrArrs func(s pattern.Segment)
		addStrArrs = func(s pattern.Segment) {
			if s.Type == pattern.SegmentText {
				return
			}
			for i, segs := range s.Segs {
				if len(segs) == s.Comps[i] {
					strs := make([]string, len(segs))
					for j, seg := range segs {
						strs[j] = seg.Str
					}
					b.strArrs = append(b.strArrs, strs)
				} else {
					for _, seg := range segs {
						addStrArrs(seg)
					}
				}
			}
		}
		addStrArrs(s)
		slices.SortFunc(b.strArrs, slices.Compare)
		b.strArrs = util.UniqFunc(b.strArrs, slices.Equal)

		b.strArrsFirstIdxs = make([]int, len(b.strArrs))
		var strArr []string
		for i := range b.strArrs {
			b.strArrsFirstIdxs[i] = len(strArr)
			strArr = append(strArr, b.strArrs[i]...)
		}

		strsOffsets = make([]uint32, len(strArr))
		strLens = make([]uint32, len(strArr))
		for i := range strArr {
			strsOffsets[i] = uint32(len(strs))
			strLens[i] = uint32(len(strArr[i]))
			strs = append(strs, strArr[i]...)
		}
	}

	// Prepare target hash array (sort and dedupe).
	switch hashMode.Bits() {
	case 32:
		slices.Sort(targetHashes32)
		targetHashes32 = util.Uniq(targetHashes32)
	case 64:
		slices.Sort(targetHashes64)
		targetHashes64 = util.Uniq(targetHashes64)
	}

	// Create hash bitmap (bloom filter)
	var hashBitmap []uint32
	{
		const BITS = 24
		hashBitmap = make([]uint32, 1<<(BITS-4))
		for _, h := range targetHashes {
			hl := uint32(h)
			idxl := hl >> (32 - (BITS - 4))
			bitl := uint32(1) << (hl & 31)
			hashBitmap[idxl] |= bitl
			if hashMode.Bits() == 64 {
				hh := uint32(h >> 32)
				idxh := hh >> (32 - (BITS - 4))
				bith := uint32(1) << (hh & 31)
				hashBitmap[idxh] |= bith
			}
		}
	}

	// Create OpenCL Buffers
	{
		var err error
		if err = b.createWorkerDependentbuffers(context, numWorkers); err != nil {
			return nil, err
		}
		b.bs.strs, err = cl.CreateBackedBuffer(context, cl.MEM_READ_ONLY|cl.MEM_COPY_HOST_PTR, strs)
		if err != nil {
			return nil, fmt.Errorf("creating strings buffer: %w", err)
		}
		b.bs.strsOffsets, err = cl.CreateBackedBuffer(context, cl.MEM_READ_ONLY|cl.MEM_COPY_HOST_PTR, strsOffsets)
		if err != nil {
			return nil, fmt.Errorf("creating strings offsets buffer: %w", err)
		}
		b.bs.strLens, err = cl.CreateBackedBuffer(context, cl.MEM_READ_ONLY|cl.MEM_COPY_HOST_PTR, strLens)
		if err != nil {
			return nil, fmt.Errorf("creating string lengths buffer: %w", err)
		}
		b.bs.hashBitmap, err = cl.CreateBackedBuffer(context, cl.MEM_READ_ONLY|cl.MEM_COPY_HOST_PTR, hashBitmap)
		if err != nil {
			return nil, fmt.Errorf("creating hash bitmap buffer: %w", err)
		}
		switch hashMode.Bits() {
		case 64:
			b.bs.targetHashes64, err = cl.CreateBackedBuffer(context, cl.MEM_READ_ONLY|cl.MEM_COPY_HOST_PTR, targetHashes64)
		case 32:
			b.bs.targetHashes32, err = cl.CreateBackedBuffer(context, cl.MEM_READ_ONLY|cl.MEM_COPY_HOST_PTR, targetHashes32)
		}
		if err != nil {
			return nil, fmt.Errorf("creating target hash buffer: %w", err)
		}
		b.bs.matchFound, err = cl.CreateBackedBuffer(context, cl.MEM_WRITE_ONLY, make([]int32, 1))
		if err != nil {
			return nil, fmt.Errorf("creating match found boolean: %w", err)
		}
	}

	return b, nil
}

func (b *clBuffers) createWorkerDependentbuffers(context cl.Context, numWorkers int) (err error) {
	b.bs.tries, err = cl.CreateBackedBuffer(context, cl.MEM_READ_WRITE, make([]uint32, numWorkers))
	if err != nil {
		return fmt.Errorf("creating tries buffer: %w", err)
	}
	b.bs.idxs, err = cl.CreateBackedBuffer(context, cl.MEM_READ_WRITE, make([]uint32, b.idxLen*numWorkers))
	if err != nil {
		return fmt.Errorf("creating indices buffer: %w", err)
	}
	b.bs.matches, err = cl.CreateBackedBuffer(context, cl.MEM_WRITE_ONLY, make([]byte, b.matchBufLen*numWorkers))
	if err != nil {
		return fmt.Errorf("creating match buffer: %w", err)
	}
	b.bs.matchesLens, err = cl.CreateBackedBuffer(context, cl.MEM_READ_WRITE|cl.MEM_COPY_HOST_PTR, make([]uint32, numWorkers))
	if err != nil {
		return fmt.Errorf("creating matches length buffer: %w", err)
	}
	return
}

func (b *clBuffers) Delete() {
	b.bs.tries.Release()
	b.bs.idxs.Release()
	b.bs.strs.Release()
	b.bs.strsOffsets.Release()
	b.bs.strLens.Release()
	b.bs.hashBitmap.Release()
	switch b.hashMode.Bits() {
	case 64:
		b.bs.targetHashes64.Release()
	case 32:
		b.bs.targetHashes32.Release()
	}
	b.bs.matchFound.Release()
	b.bs.matches.Release()
	b.bs.matchesLens.Release()
}

// Only valid if no match was found the previous dispatch, as it zeroes
// all tries and matchesLens.
//
// If this returns a nonzero error, clBuffers state should be seen as corrupted
// and the clBuffers should be discarded.
func (b *clBuffers) ResizeToWorkers(context cl.Context, queue cl.CommandQueue, newNumWorkers int) error {
	b.bs.tries.Release()
	b.bs.idxs.Release()
	b.bs.matches.Release()
	b.bs.matchesLens.Release()
	if err := b.createWorkerDependentbuffers(context, newNumWorkers); err != nil {
		return err
	}
	if err := b.bs.tries.EnqueueFill(queue, []uint32{0}, 0, -1, nil, nil); err != nil {
		return err
	}
	if err := cl.Finish(queue); err != nil {
		return err
	}
	b.numWorkers = newNumWorkers
	return nil
}

func (b *clBuffers) strArrOffset(s pattern.Segment, unionIdx int) int {
	i := unionIdx
	if s.Comps[i] != len(s.Segs[i]) {
		panic("expected strArrOffset to be called on union of only strings")
	}
	arr := make([]string, len(s.Segs[i]))
	for j := range s.Segs[i] {
		arr[j] = s.Segs[i][j].Str
	}
	strArrIdx, found := slices.BinarySearchFunc(b.strArrs, arr, slices.Compare)
	if !found {
		panic("expected to find string array")
	}
	return b.strArrsFirstIdxs[strArrIdx]
}

func (b *clBuffers) readMatchFound(queue cl.CommandQueue) (err error) {
	return b.bs.matchFound.EnqueueRead(queue, true, 0, -1, nil, nil)
}

func (b *clBuffers) readTriesIdxsAndMatches(queue cl.CommandQueue) (err error) {
	if err = b.bs.tries.EnqueueRead(queue, false, 0, -1, nil, nil); err != nil {
		return
	}
	if err = b.bs.idxs.EnqueueRead(queue, false, 0, -1, nil, nil); err != nil {
		return
	}
	if err = b.bs.matches.EnqueueRead(queue, false, 0, -1, nil, nil); err != nil {
		return
	}
	if err = b.bs.matchesLens.EnqueueRead(queue, false, 0, -1, nil, nil); err != nil {
		return
	}
	if err = cl.Finish(queue); err != nil {
		return
	}
	return
}

// Pass 0 as triesFillValue to fill with buffer contents instead of fixed value.
//
// If altIdxsSourceBuffer is not nil, it will be used to fill the device indices
// instead of the internal backed idxs buffer.
func (b *clBuffers) write(queue cl.CommandQueue, triesFillValue uint32, altIdxsSourceBuffer []uint32, zeroMatchesLens bool) error {
	if triesFillValue == 0 {
		if err := b.bs.tries.EnqueueWrite(queue, false, 0, -1, nil, nil); err != nil {
			return err
		}
	} else {
		if err := b.bs.tries.EnqueueFill(queue, []uint32{triesFillValue}, 0, -1, nil, nil); err != nil {
			return err
		}
	}
	if altIdxsSourceBuffer != nil {
		// Needed since altIdxsSourceBuffer needs to live longer than the EnqueueWrite call
		// (until cl.Finish) and we're not using blocking_write.
		var pin runtime.Pinner
		defer pin.Unpin()
		pin.Pin(&altIdxsSourceBuffer[0])

		if err := cl.EnqueueWriteBufferSlice(queue, b.bs.idxs.Mem, false, 0, altIdxsSourceBuffer, nil, nil); err != nil {
			return err
		}
	} else {
		if err := b.bs.idxs.EnqueueWrite(queue, false, 0, -1, nil, nil); err != nil {
			return err
		}
	}
	if err := b.bs.matchFound.EnqueueWrite(queue, false, 0, -1, nil, nil); err != nil {
		return err
	}
	if zeroMatchesLens {
		if err := b.bs.matchesLens.EnqueueFill(queue, []uint32{0}, 0, -1, nil, nil); err != nil {
			return err
		}
	}
	if err := cl.Finish(queue); err != nil {
		return err
	}
	return nil
}

// Gets the match strings from host buffer data.
func (b *clBuffers) getMatches() (matches []string) {
	var buf bytes.Buffer
	for i := range b.numWorkers {
		offs := i * b.matchBufLen
		for j := range int(b.bs.matchesLens.Items[i]) {
			c := b.bs.matches.Items[offs+j]
			if c != 0 {
				buf.WriteByte(c)
			} else {
				matches = append(matches, buf.String())
				buf.Reset()
			}
		}
	}
	return
}

func generateClCode(s pattern.Segment, bufs *clBuffers) (code []byte) {
	// Quotes an OpenCL string (doesn't cover
	// all escape sequences).
	quote := func(s string) string {
		var b strings.Builder
		b.WriteByte('"')
		for _, r := range s {
			switch r {
			case '"':
				b.WriteString(`\"`)
			case '\n':
				b.WriteString(`\n`)
			case '\r':
				b.WriteString(`\r`)
			case '\\':
				b.WriteString(`\\`)
			default:
				if r >= 0x20 && r <= 0x7e {
					b.WriteByte(byte(r))
				} else {
					var p [4]byte
					for _, c := range p[:utf8.EncodeRune(p[:], r)] {
						fmt.Fprintf(&b, `\x%02x`, c)
					}
				}
			}
		}
		b.WriteByte('"')
		return b.String()
	}

	cb := &codeBuilder{IndentStr: "  "}
	cb.L("#define MAX_CANDIDATE_LEN %d", bufs.maxCandidateLen)
	cb.L("#define MAX_MATCH_BUF_LEN %d", bufs.matchBufLen)
	switch bufs.hashMode.Bits() {
	case 64:
		cb.L("#define NUM_TARGET_HASHES %d", len(bufs.bs.targetHashes64.Items))
		cb.L("#define HASH_BITS 64")
	case 32:
		cb.L("#define NUM_TARGET_HASHES %d", len(bufs.bs.targetHashes32.Items))
		cb.L("#define HASH_BITS 32")
	}
	switch bufs.hashMode {
	case HashMurmur64a:
		cb.L("#define HASH_FUNCTION murmur64a_sum")
	case HashMurmur64aThin:
		cb.L("#define HASH_FUNCTION murmur64a_thin_sum")
	case HashDatalib:
		cb.L("#define HASH_FUNCTION datalib_hash_sum")
	}
	cb.L("#define IDX_LEN %d", bufs.idxLen)
	cb.L("")
	cb.L("%s", preludeClCode)

	writeExprPushStr := func(cb *codeBuilder, memcpyFn, str string) {
		cb.L("%s((char*)candidate + candidate_len, %s, str_len);", memcpyFn, str)
		cb.L("candidate_len += str_len;")
	}
	writeExprPopStr := func(cb *codeBuilder) {
		cb.L("candidate_len -= str_len;")
	}
	var guessFns []*codeBuilder
	pushGuessFn := func() (cb *codeBuilder, name string) {
		fnIdx := len(guessFns)
		name = fmt.Sprintf("guess_%d", fnIdx)
		cb = &codeBuilder{IndentStr: "  "}
		cb.L("bool %s(size_t id, u32 *n, u32 *i, u64 *candidate, i32 candidate_len, __global const char *strs, __global const u32 *strs_offsets, __global const u32 *str_lens, __global const u32 *hash_bitmap, __global const hash_t *target_hashes, __global char *matches, __global u32 *matches_lens) {", name)
		guessFns = append(guessFns, cb)
		return
	}
	popGuessFn := func(cb *codeBuilder) {
		cb.L("return true;")
		cb.L("}")
	}
	writeExprCallGuessFn := func(cb *codeBuilder, name string) {
		if name == "try" {
			cb.L("if (!(*n) || !try(candidate, candidate_len, id, hash_bitmap, target_hashes, matches, matches_lens)) return false;")
			cb.L("(*n)--;")
		} else {
			cb.L("if (!%s(id, n, i, candidate, candidate_len, strs, strs_offsets, str_lens, hash_bitmap, target_hashes, matches, matches_lens)) return false;", name)
		}
	}

	//fmt.Println("strs:", bufs.strArrs)

	cIdxCounter := 0
	// guessFn is the function to call after the current segment has reached
	// its last cartesian product term. For the root node, it's "try", since we
	// always want to try the string produced on after the rightmost cartesian
	// product.
	//
	// For any union, each union operand should have the same guessFn. To avoid
	// repetition, we generate the next cartesian product term outside the union
	// as a new guessing function and then make the union guess via that.
	var genCode func(cb *codeBuilder, s pattern.Segment, idx int, guessFn string)
	genCode = func(cb *codeBuilder, s pattern.Segment, idx int, guessFn string) {
		if (s.Type == pattern.SegmentText) || (s.Type == pattern.SegmentProdOfSets && len(s.Segs) == 0) {
			cb.L("const u32 str_len = %d;", len(s.Str))
			writeExprPushStr(cb, "memcpy_pc", quote(s.Str))
			writeExprCallGuessFn(cb, guessFn)
			writeExprPopStr(cb)
			return
		}

		segs := s.Segs[idx]

		cIdx := cIdxCounter
		cIdxCounter++

		if len(segs) == s.Comps[idx] { // List of single strings (NOTE that this is only reliable due to the single element flattening optimization)
			if len(segs) != 1 {
				cb.L("for (; i[%d] < %d; i[%d]++) {", cIdx, len(segs), cIdx)
			} else {
				cb.L("{")
			}
			offs := bufs.strArrOffset(s, idx)
			cb.L("const u32 str_idx = %d+i[%d];", offs, cIdx)
			cb.L("const u32 str_len = str_lens[str_idx];", offs, cIdx)
			writeExprPushStr(cb, "memcpy_pg", "strs + strs_offsets[str_idx]")
			if idx == len(s.Segs)-1 {
				writeExprCallGuessFn(cb, guessFn)
			} else {
				genCode(cb, s, idx+1, guessFn)
			}
			writeExprPopStr(cb)
			cb.L("}")
		} else { // Some union operand with more nesting exists
			var fname string
			var guessFnCb *codeBuilder
			if idx == len(s.Segs)-1 {
				fname = guessFn
			} else {
				guessFnCb, fname = pushGuessFn()
			}
			cb.L("switch (i[%d]) {", cIdx)
			for j, seg := range segs {
				cb.L("case %d: {", j)
				genCode(cb, seg, 0, fname)
				if j != len(segs)-1 {
					cb.L("i[%d]++;", cIdx)
					cb.L("//fallthrough")
				}
				cb.L("}")
			}
			cb.L("}")
			if guessFnCb != nil {
				genCode(guessFnCb, s, idx+1, guessFn)
				popGuessFn(guessFnCb)
			}
		}
		if len(segs) != 1 {
			cb.L("i[%d] = 0;", cIdx)
		}
	}

	var guessEntryFnName string
	{
		var fcb *codeBuilder
		fcb, guessEntryFnName = pushGuessFn()
		genCode(fcb, s, 0, "try")
		popGuessFn(fcb)
	}

	for _, fcb := range slices.Backward(guessFns) {
		cb.L("%s", fcb.B.String())
	}

	cb.L(`__kernel void kmain(__global u32* tries, __global u32* idxs, __global const char *strs, __global const u32 *strs_offsets, __global const u32 *str_lens, __global const u32 *hash_bitmap, __global const hash_t *target_hashes, __global int *match_found, __global char *matches, __global u32 *matches_lens) {`)
	cb.L("size_t id = get_global_id(0);")
	cb.L("u32 n = tries[id]; // number of tries left")
	cb.L("u64 candidate[(MAX_CANDIDATE_LEN+7)/8]; // using u64 to force correct alignment to be able to speed up murmurhash algorithm")
	cb.L("i32 candidate_len = 0;")
	cb.L("u32 i[IDX_LEN];")
	cb.L("memcpy_pg(i, idxs + id*IDX_LEN, sizeof(i));")
	cb.L("%s(id, &n, i, candidate, candidate_len, strs, strs_offsets, str_lens, hash_bitmap, target_hashes, matches, matches_lens);", guessEntryFnName)
	cb.L("memcpy_gp(idxs + id*IDX_LEN, i, sizeof(i));")
	cb.L("tries[id] = n;")
	cb.L("if (matches_lens[id] != 0) atomic_xchg(match_found, 1);")
	cb.L("}")
	return cb.B.Bytes()
}

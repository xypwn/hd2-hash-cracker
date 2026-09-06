package cl_test

import (
	"runtime"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	cl "github.com/xypwn/gocl/cl-3.1"
	"github.com/xypwn/hd2-hash-cracker/hash"
	"github.com/xypwn/hd2-hash-cracker/pattern"
	pcl "github.com/xypwn/hd2-hash-cracker/pattern/cl"
)

func TestCl(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	platforms, err := cl.GetPlatformIDs()
	require.NoError(t, err)
	if len(platforms) == 0 {
		require.Fail(t, "no OpenCL platforms")
	}
	platform := platforms[0]
	devices, err := cl.GetDeviceIDs(platform, cl.DEVICE_TYPE_GPU)
	require.NoError(t, err)
	if len(devices) == 0 {
		require.Fail(t, "no OpenCL devices")
	}
	device := devices[0]

	testCases := []struct {
		name                string
		opts                pcl.Options
		pattern             string
		patternOpts         pattern.CompileOptions
		mode                pcl.HashMode
		targetHashes        []string
		expectedFoundHashes []string
	}{
		{
			"basic",
			pcl.Options{MinMatchBufLen: 1},
			"[0-9]{3}",
			pattern.CompileOptions{NoOptimize: true},
			pcl.HashMurmur64a,
			[]string{"000", "123", "124", "125", "997", "998", "999"},
			[]string{"000", "123", "124", "125", "997", "998", "999"},
		},
		{
			"accept all",
			pcl.Options{Workers: 1, MinMatchBufLen: 1, Tries: 4, Debug: pcl.DebugOptions{AcceptAllAsMatch: true}},
			"[0-9]{1}|[a-b]{1}|x|<<y>>",
			pattern.CompileOptions{NoOptimize: true},
			pcl.HashMurmur64a,
			[]string{""},
			[]string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "x", "y"},
		},
		{
			"index",
			pcl.Options{Workers: 1, MinMatchBufLen: 1, Tries: 4, Debug: pcl.DebugOptions{InitialTotalIdx: 456}},
			"<[0-7]|8|9>{3}",
			pattern.CompileOptions{NoOptimize: true},
			pcl.HashMurmur64a,
			[]string{"123", "455", "456", "457", "458", "999"},
			[]string{"456", "457", "458", "999"},
		},
	}

	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			require := require.New(t)
			prog, err := pattern.Compile([]byte(c.pattern), "-", nil, c.patternOpts)
			require.NoError(err)
			var targetHashes []uint64
			for _, s := range c.targetHashes {
				var h uint64
				switch c.mode {
				case pcl.HashMurmur64a:
					h = hash.Murmur64aSum(s)
				case pcl.HashMurmur64aThin:
					h = uint64(hash.Thin(hash.Murmur64aSum(s)))
				case pcl.HashDatalib:
					h = uint64(hash.DatalibHashSum(s))
				}
				targetHashes = append(targetHashes, h)
			}
			cr, err := pcl.NewCracker(device, prog, c.mode, targetHashes, c.opts)
			require.NoError(err)
			defer cr.Delete()
			var gotMatches []string
			for {
				//fmt.Println(cr.TotalIdx(), "/", prog.Comp)
				matches, err := cr.Dispatch()
				if err == pcl.Done {
					break
				}
				require.NoError(err)
				gotMatches = append(gotMatches, matches...)
			}
			expectMatches := slices.Clone(c.expectedFoundHashes)
			slices.Sort(expectMatches)
			slices.Sort(gotMatches)
			require.Equal(expectMatches, gotMatches)
		})
	}
}

package pattern

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	cases := []struct {
		name    string
		expr    string
		want    IrSegment
		wantErr string
	}{
		{"basic", "<a|b>cd",
			IrSegmentConcat{
				IrSegmentChoice{
					IrSegmentStr("a"),
					IrSegmentStr("b"),
				},
				IrSegmentStr("cd"),
			}, ""},
		{"repeat 1", "<a|b>{5,10}",
			IrSegmentRepeat{
				Seg: IrSegmentChoice{
					IrSegmentStr("a"),
					IrSegmentStr("b"),
				},
				Min: 5,
				Max: 10,
			}, ""},
		{"repeat 2", "<a|b>{10}",
			IrSegmentRepeat{
				Seg: IrSegmentChoice{
					IrSegmentStr("a"),
					IrSegmentStr("b"),
				},
				Min: 10,
				Max: 10,
			}, ""},
		{"repeat sep 1", "<a|b>{5,10,<c|d>}",
			IrSegmentRepeat{
				Seg: IrSegmentChoice{
					IrSegmentStr("a"),
					IrSegmentStr("b"),
				},
				Min: 5,
				Max: 10,
				Sep: IrSegmentChoice{
					IrSegmentStr("c"),
					IrSegmentStr("d"),
				},
			}, ""},
		{"repeat sep 2", "a{5,<c|d>}",
			IrSegmentRepeat{
				Seg: IrSegmentStr("a"),
				Min: 5,
				Max: 5,
				Sep: IrSegmentChoice{
					IrSegmentStr("c"),
					IrSegmentStr("d"),
				},
			}, ""},
		{"char class", "[a-f]",
			IrSegmentChoice{
				IrSegmentStr("a"), IrSegmentStr("b"), IrSegmentStr("c"), IrSegmentStr("d"), IrSegmentStr("e"), IrSegmentStr("f"),
			}, ""},
		{"repeat invalid range", "<a|b>{10,5}", nil,
			"pattern error at test.pat:1:11: expected minimum repetitions (10) to be less than maximum (5) repetitions"},
		{"empty string 1", "<|b>cd",
			IrSegmentConcat{
				IrSegmentChoice{
					IrSegmentStr(""),
					IrSegmentStr("b"),
				},
				IrSegmentStr("cd"),
			}, ""},
		{"empty string 2", "a<>",
			IrSegmentStr("a"),
			""},
		{"empty string 3", "#{produce-nil}|a",
			IrSegmentStr("a"),
			""},
		{"empty string 4", "#{produce-nil}a",
			IrSegmentStr("a"),
			""},
		{"empty string 5", "#{produce-empty-str}|a",
			IrSegmentChoice{IrSegmentStr(""), IrSegmentStr("a")},
			""},
		{"escape sequences 1", `\{\}\|\<\>\\\//abc\w`,
			IrSegmentStr(`{}|<>\//abc\w`),
			""},
		{"escape sequences 2", `#{echo \w+|abc{1}\\\\}`,
			IrSegmentStr(`\w+|abc{1}\\`),
			""},
		{"escape sequences 3", `#{echo "\w\"{xy"}`,
			IrSegmentStr(`\w"{xy`),
			""},
		{"comment 1", "//abc\nxyz",
			IrSegmentStr(`xyz`),
			""},
		{"comment 2", "/*abc*/\nxyz",
			IrSegmentStr(`xyz`),
			""},
		{"comment 3", "xyz//abc",
			IrSegmentStr(`xyz`),
			""},
		{"comment crlf", "//abc\r\nxyz",
			IrSegmentStr(`xyz`),
			""},
		{"comment escaped 1", `\//`,
			IrSegmentStr(`//`),
			""},
		{"comment escaped 2", `\/*abc*/`,
			IrSegmentStr(`/*abc*/`),
			""},
	}
	funcs := map[string]any{
		"produce-nil": func() IrSegment {
			return nil
		},
		"produce-empty-str": func() IrSegment {
			return IrSegmentStr("")
		},
		"echo": func(s string) IrSegmentStr {
			return IrSegmentStr(s)
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require := require.New(t)
			_, irSeg, err := parse([]byte(c.expr), "test.pat", nil, nil, funcs)
			if c.wantErr == "" {
				require.NoError(err)
			} else {
				require.EqualError(err, c.wantErr)
			}
			require.Equal(c.want, irSeg)
		})
	}
}

func TestCompile(t *testing.T) {
	cases := []struct {
		name    string
		expr    string
		opts    CompileOptions
		want    Segment
		wantErr string
	}{
		{"basic", "a|b",
			CompileOptions{},
			Segment{
				Type: SegmentProdOfSets,
				Segs: [][]Segment{
					{
						{Type: SegmentText, Str: "a", Comp: 1},
						{Type: SegmentText, Str: "b", Comp: 1},
					},
				},
				Comp:  2,
				Comps: []int{2},
			}, "",
		},
		{"concat", "c<a|b>d",
			CompileOptions{},
			Segment{
				Type: SegmentProdOfSets,
				Segs: [][]Segment{
					{{Type: SegmentText, Str: "c", Comp: 1}},
					{
						{Type: SegmentText, Str: "a", Comp: 1},
						{Type: SegmentText, Str: "b", Comp: 1},
					},
					{{Type: SegmentText, Str: "d", Comp: 1}},
				},
				Comp:  2,
				Comps: []int{1, 2, 1},
			}, "",
		},
		{"or empty", "a|",
			CompileOptions{},
			Segment{
				Type: SegmentProdOfSets,
				Segs: [][]Segment{{
					{Type: SegmentText, Str: "a", Comp: 1},
					{Type: SegmentProdOfSets, Comp: 1},
				}},
				Comp:  2,
				Comps: []int{2},
			}, "",
		},
		{"range 0,1", "a{0,1}",
			CompileOptions{},
			Segment{
				Type: SegmentProdOfSets,
				Segs: [][]Segment{{
					{Type: SegmentProdOfSets, Comp: 1},
					{Type: SegmentText, Str: "a", Comp: 1},
				}},
				Comp:  2,
				Comps: []int{2},
			}, "",
		},
		{"optimize empty 1", "a<><b|c>",
			CompileOptions{},
			Segment{
				Type: SegmentProdOfSets,
				Segs: [][]Segment{
					{{Type: SegmentText, Str: "a", Comp: 1}},
					{{Type: SegmentText, Str: "b", Comp: 1}, {Type: SegmentText, Str: "c", Comp: 1}},
				},
				Comp:  2,
				Comps: []int{1, 2},
			}, "",
		},
		{"optimize empty 2", "a<|<>><b|c>",
			CompileOptions{},
			Segment{
				Type: SegmentProdOfSets,
				Segs: [][]Segment{
					{{Type: SegmentText, Str: "a", Comp: 1}},
					{{Type: SegmentText, Str: "b", Comp: 1}, {Type: SegmentText, Str: "c", Comp: 1}},
				},
				Comp:  2,
				Comps: []int{1, 2},
			}, "",
		},
		{"optimize empty 3", "a|b|<>",
			CompileOptions{},
			Segment{
				Type: SegmentProdOfSets,
				Segs: [][]Segment{{
					{Type: SegmentText, Str: "a", Comp: 1},
					{Type: SegmentText, Str: "b", Comp: 1},
					{Type: SegmentProdOfSets, Comp: 1},
				}},
				Comp:  3,
				Comps: []int{3},
			}, "",
		},
		{"flatten single possibility", "a<b>c<d>",
			CompileOptions{},
			Segment{
				Type: SegmentText,
				Str:  "abcd",
				Comp: 1,
			}, "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require := require.New(t)
			prog, err := Compile([]byte(c.expr), "", nil, c.opts)
			if c.wantErr == "" {
				require.NoError(err)
			} else {
				require.EqualError(err, c.wantErr)
			}
			require.Equal(c.want, prog, "compiled program not equal: want %s, but got %s", c.want, prog)
		})
	}
}

func TestAdd(t *testing.T) {
	cases := []struct {
		name  string
		expr  string
		nwant []any
	}{
		{"basic", "<0|1|2|3|4|5|6|7|8|9>{10}",
			[]any{
				69420, "0000069420",
				12345678, "0012415098",
			},
		},
		{"nested_or", "<0|1|2|3|4|5|6|7|8|9>{3}|one_thousand",
			[]any{
				999, "999",
				1, "one_thousand",
			},
		},
	}
	for _, c := range cases {
		for _, optimize := range []bool{false, true} {
			name := c.name
			if optimize {
				name += "_opt"
			} else {
				name += "_no_opt"
			}
			t.Run(name, func(t *testing.T) {
				require := require.New(t)
				prog, err := Compile([]byte(c.expr), "", nil, CompileOptions{NoOptimize: !optimize})
				require.NoError(err)
				idx := prog.MakeIndex()
				for i := 0; i < len(c.nwant); i += 2 {
					n := c.nwant[i].(int)
					want := c.nwant[i+1].(string)
					idx.Add(prog, n)
					require.Equal(want, prog.StringAt(idx))
				}
			})
		}
	}
}

package pattern

import (
	"fmt"
	"iter"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/xypwn/hd2-hash-cracker/util"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var builtinVars = map[string]IrSegment{}

func builtinHelperCheckChoiceOfStrings(choices IrSegmentChoice) error {
	prevStr := ""
	for i, seg := range choices {
		s, ok := seg.(IrSegmentStr)
		if !ok {
			var sfx string
			if i > 0 {
				sfx = fmt.Sprintf(" (after %q)", prevStr)
			}
			return fmt.Errorf("expected choice to consist only of strings, but got non-string at index %d%s", i, sfx)
		}
		prevStr = string(s)
	}
	return nil
}

func builtinHelperTransformChoiceOfStrings(
	choices IrSegmentChoice,
	transform func(choices iter.Seq2[int, string]) (res []IrSegment, err error),
) (IrSegmentChoice, error) {
	if err := builtinHelperCheckChoiceOfStrings(choices); err != nil {
		return nil, err
	}
	newChoices, err := transform(func(yield func(int, string) bool) {
		for i, seg := range choices {
			if !yield(i, string(seg.(IrSegmentStr))) {
				break
			}
		}
	})
	if err != nil {
		return nil, err
	}
	return IrSegmentChoice(newChoices), nil
}

func builtinHelperDedupeChoiceOfStrings(choices []IrSegment) []IrSegment {
	seen := make(map[string]struct{})
	j := 0
	for i := range choices {
		s := string(choices[i].(IrSegmentStr))
		if _, exists := seen[s]; exists {
			continue
		}
		if j != i {
			choices[j] = IrSegmentStr(s)
		}
		j++
		seen[s] = struct{}{}
	}
	clear(choices[j:])
	return choices[:j]
}

func builtinYieldNDuplicates(s string, n int) iter.Seq[string] {
	return func(yield func(val string) bool) {
		for range n {
			if !yield(s) {
				return
			}
		}
	}
}

var builtinFuncs = map[string]any{
	// limit limits the number of choices to at most n, where
	// n must be a non-negative number.
	"limit": func(s IrSegmentChoice, n string) (IrSegmentChoice, error) {
		nInt, err := strconv.Atoi(n)
		if err != nil {
			return nil, err
		}
		if len(s) > nInt {
			s = s[:nInt]
		}
		return s, nil
	},
	// filter only keeps items that match the given regex.
	//
	// All choices must be strings.
	"filter": func(choices IrSegmentChoice, re string) (IrSegmentChoice, error) {
		r, err := regexp.Compile(re)
		if err != nil {
			return nil, err
		}
		return builtinHelperTransformChoiceOfStrings(choices, func(choices iter.Seq2[int, string]) (res []IrSegment, err error) {
			for _, s := range choices {
				if r.MatchString(s) {
					res = append(res, IrSegmentStr(s))
				}
			}
			return
		})
	},
	// Like filter, but REMOVES all choices that match the given regex.
	"remove": func(choices IrSegmentChoice, re string) (IrSegmentChoice, error) {
		r, err := regexp.Compile(re)
		if err != nil {
			return nil, err
		}
		return builtinHelperTransformChoiceOfStrings(choices, func(choices iter.Seq2[int, string]) (res []IrSegment, err error) {
			for _, s := range choices {
				if !r.MatchString(s) {
					res = append(res, IrSegmentStr(s))
				}
			}
			return
		})
	},
	// For each item, replace replaces all matches of the given regex with the given replacement pattern
	// (e.g. $1 for capture group 1, $name for named capture group). Eliminates any duplicates.
	"replace": func(choices IrSegmentChoice, re, repl string) (IrSegmentChoice, error) {
		r, err := regexp.Compile(re)
		if err != nil {
			return nil, err
		}
		return builtinHelperTransformChoiceOfStrings(choices, func(choices iter.Seq2[int, string]) (res []IrSegment, err error) {
			for _, s := range choices {
				s := r.ReplaceAllString(s, repl)
				res = append(res, IrSegmentStr(s))
			}
			res = builtinHelperDedupeChoiceOfStrings(res)
			return
		})
	},
	// For each item, dup duplicates the string n times, inserting the given separator.
	// eg `#{dup <a|b|c> 2 /} -> <a/a|b/b|c/c>`
	"dup": func(choices IrSegmentChoice, n, sep string) (IrSegmentChoice, error) {
		nInt, err := strconv.Atoi(n)
		if err != nil {
			return nil, err
		}
		return builtinHelperTransformChoiceOfStrings(choices, func(choices iter.Seq2[int, string]) (res []IrSegment, err error) {
			for _, s := range choices {
				s := strings.Join(slices.Collect(builtinYieldNDuplicates(s, nInt)), sep)
				res = append(res, IrSegmentStr(s))
			}
			res = builtinHelperDedupeChoiceOfStrings(res)
			return
		})
	},
	// Convert each item to title case and deduplicate.
	"title": func(choices IrSegmentChoice) (IrSegmentChoice, error) {
		caser := cases.Title(language.English)
		return builtinHelperTransformChoiceOfStrings(choices, func(choices iter.Seq2[int, string]) (res []IrSegment, err error) {
			for _, s := range choices {
				s := caser.String(s)
				res = append(res, IrSegmentStr(s))
			}
			res = builtinHelperDedupeChoiceOfStrings(res)
			return
		})
	},
	// split splits each string in a choice of strings by any of the
	// given delimiters. Eliminates any duplicates.
	"split": func(choices IrSegmentChoice, delims string) (IrSegmentChoice, error) {
		return builtinHelperTransformChoiceOfStrings(choices, func(choices iter.Seq2[int, string]) (res []IrSegment, err error) {
			for _, choice := range choices {
				for s := range util.SplitStringAnySeq(choice, delims) {
					res = append(res, IrSegmentStr(s))
				}
			}
			res = builtinHelperDedupeChoiceOfStrings(res)
			return
		})
	},
	// returns a list of non-empty deduplicated prefixes of the input up to any of delims.
	//
	// Example: <a/b/c|0/1|a/b_d> -> <a|a/b|a/b/c|0|0/1|a/b_d>
	"prefixes": func(choices IrSegmentChoice, delims string) (IrSegmentChoice, error) {
		return builtinHelperTransformChoiceOfStrings(choices, func(choices iter.Seq2[int, string]) (res []IrSegment, err error) {
			for _, s := range choices {
				sp := util.SplitStringAfterAny(s, delims)
				for i := 1; i <= len(sp); i++ {
					pfx := strings.Join(sp[:i], "")
					if len(pfx) > 0 && strings.ContainsRune(delims, rune(pfx[len(pfx)-1])) {
						pfx = pfx[:len(pfx)-1]
					}
					if pfx == "" {
						continue
					}
					res = append(res, IrSegmentStr(pfx))
				}
			}
			res = builtinHelperDedupeChoiceOfStrings(res)
			return
		})
	},
	// returns a list of non-empty deduplicated suffixes of the input up to any of delims.
	//
	// Example: <a/b/c|0/1|x_b/c> -> <c|b/c|a/b/c|1|0/1|x_b/c>
	"suffixes": func(choices IrSegmentChoice, delims string) (IrSegmentChoice, error) {
		return builtinHelperTransformChoiceOfStrings(choices, func(choices iter.Seq2[int, string]) (res []IrSegment, err error) {
			for _, s := range choices {
				sp := util.SplitStringAfterAny(s, delims)
				for i := len(sp) - 1; i >= 0; i-- {
					sfx := strings.Join(sp[i:], "")
					if sfx == "" {
						continue
					}
					res = append(res, IrSegmentStr(sfx))
				}
			}
			res = builtinHelperDedupeChoiceOfStrings(res)
			return
		})
	},
	// merges lists of choices of strings, while leaving out any duplicates.
	"merge": func(choices ...IrSegmentChoice) (IrSegmentChoice, error) {
		for _, choices := range choices {
			if err := builtinHelperCheckChoiceOfStrings(choices); err != nil {
				return nil, err
			}
		}
		var res IrSegmentChoice
		for _, choices := range choices {
			for _, choice := range choices {
				res = append(res, choice)
			}
		}
		res = builtinHelperDedupeChoiceOfStrings(res)
		return res, nil
	},

	// =====================
	// Special functions
	// =====================
	// These have to be implemented in the parser, as they
	// modify the current parser state.

	// load loads the given pattern from a file.
	"load": (func(filename string) (IrSegment, error))(nil),
	// import imports any variables from the given
	// file.
	"import": (func(filename string) (IrSegment, error))(nil),
	// wordlist loads a wordlist from a file as a choice expression.
	//
	// Each non-empty line is counted as a word.
	//
	// Lines starting with "//" or "#" are ignored.
	"wordlist": (func(filename string) (IrSegmentChoice, error))(nil),

	// =====================
	// End special functions
	// =====================
}

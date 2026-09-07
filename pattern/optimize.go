package pattern

import "slices"

// Result of a single optimization.
//
// The zero value is default and sensible
// for most optimizations to return.
type OptimizationResult struct {
	// If the complexity change is non-trivial, the Optimization may
	// set this to true, in which case the new complexity will be
	// automatically fully recalculated recursively.
	NeedRecalcComps bool
	// The optimization may set this to true to indicate that no
	// further optimization is possible and any following optimizations
	// in the pass on that segment should be skipped.
	Final bool
}

// An Optimization is a single, simple algorithm that may mutate
// its given Segment. If the optimization changes a Segment's
// complexity, the segment MUST be updated to reflect that change.
type Optimization func(s *Segment) (res OptimizationResult)

// Optimizations are applied depth-first (meaning on inner expressions
// before outer expressions). An OptimizationPass is a list of [Optimization] s
// that will sequentially be applied for each segment. The segments are
// iterated over in depth-first order.
type OptimizationPass []Optimization

func (s *Segment) Optimize(op OptimizationPass) {
	// Optimize inner segments first.
	innerCompChanged := false
	for i := range s.Segs {
		for j := range s.Segs[i] {
			prevComp := s.Segs[i][j].Comp
			s.Segs[i][j].Optimize(op)
			if s.Segs[i][j].Comp != prevComp {
				innerCompChanged = true
			}
		}
	}
	if innerCompChanged {
		// We may have changed the segment's complexity
		// through inner optimizations, so superficially
		// recalculate the current segment's complexity.
		s.Comps = nil
		s.Comp = 0
		s.calculateComps()
	}

	// Run each optimization.
	for _, o := range op {
		res := o(s)
		if res.NeedRecalcComps {
			// Full complexity recalculation
			// requested.
			s.resetComps()
			s.calculateComps()
		}
		if res.Final {
			break
		}
	}
}

var builtinOptimizationPass = OptimizationPass{
	func(s *Segment) (res OptimizationResult) {
		// Union element that only yields empty string should be replaced with empty segment
		// (to fully flatten any nested empty strings).
		// e.g. <><|> becomes <> (remove redundant complexity)
		if s.MaxLen() == 0 {
			*s = Segment{Type: SegmentProdOfSets, Comp: 1}
			// Nothing more can be done to optimize this segment.
			res.Final = true
		}
		return
	},
	func(s *Segment) (res OptimizationResult) {
		// Cartesian product only yielding one string should be flattened
		// to that string.
		if s.Comp == 1 {
			*s = Segment{Type: SegmentText, Str: s.StringAt(s.MakeIndex()), Comp: 1}
			// Nothing more can be done to optimize this segment.
			res.Final = true
		}
		return
	},
	func(s *Segment) (res OptimizationResult) {
		// Cartesian product element that only yields empty string can be removed.
		cartProdElementMaxLen := func(s Segment, idx int) int {
			maxLen := 0
			for _, seg := range s.Segs[idx] {
				maxLen = max(maxLen, seg.MaxLen())
			}
			return maxLen
		}
		var newSegs [][]Segment
		for i := range s.Segs {
			if cartProdElementMaxLen(*s, i) > 0 {
				newSegs = append(newSegs, s.Segs[i])
			} else {
				// Complexity may have changed if expression was e.g. <|>
				// (redundant empty string).
				res.NeedRecalcComps = true
			}
		}
		s.Segs = newSegs
		return
	},
	func(s *Segment) (res OptimizationResult) {
		// Cartesian product of single-parameter unions
		// of cartesian product can be flattened.
		//
		// Example:
		// x(A, u(x(B, C)), u(x(D))) -> x(A, B, C, D)
		if i := slices.IndexFunc(s.Segs, func(segs []Segment) bool {
			return len(segs) == 1
		}); i != -1 {
			var newSegs [][]Segment
			var newComps []int
			for ; i < len(s.Segs); i++ {
				if len(s.Segs[i]) == 1 && s.Segs[i][0].Type == SegmentProdOfSets {
					newSegs = append(newSegs, s.Segs[i][0].Segs...)
					newComps = append(newComps, s.Segs[i][0].Comps...)
				} else {
					newSegs = append(newSegs, s.Segs[i])
					newComps = append(newComps, s.Comps[i])
				}
			}
			s.Segs = newSegs
			s.Comps = newComps
		}
		return
	},
	func(s *Segment) (res OptimizationResult) {
		// Cartesian product with single parameter
		// of union with single parameter can be
		// flattened.
		//
		// Example:
		// x(u(A)) -> A
		if len(s.Segs) == 1 && len(s.Segs[0]) == 1 {
			*s = s.Segs[0][0]
		}
		return
	},
}

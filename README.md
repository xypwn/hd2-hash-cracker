# Helldivers 2 Hash Cracker

Fast GPU-based hash cracking for Helldivers 2, optimized for file paths.

## Usage
- `go run . -h` for a list of options

## Pattern language
### Syntax
- strings without any special characters are parsed as strings (prefix any special character with `\` escape)
- `<`, `>`: group inner contents together (works like parentheses)
- `<a><b>` or `a<b>` etc.: concatenate a and b
- `a|b|c`: a or b or c
- newline is equivalent to `|`
- `[a-z0-9~_-]`, `[^a-z]`: character classes mostly like in regex
- `...{m,n}`, `...{m}`: repeat expression m-n times (`,n` can be omitted if `m == n`)
- `...{m,n,s}`, `...{m,s}`: repeat expression m-n times, separated by s (`,n` can be omitted if `m == n` and if `s` doesn't start with a digit)
- `#{var = ...}`: assign value of ... to variable `var`
- `#{var}`: expand value of variable `var`
- `#{func arg1 arg2 ...}`: call function with arguments `arg1`, `arg2` etc.
    - string/regex arguments are parsed differently from expression arguments
        - in string/regex arguments, only the characters `\`, `{`, `}`, space and tab need to be escaped
            - balanced braces [`{}`] don't need to be escaped
        - `\` does not need to be escaped if succeeded by a non-special character (e.g. `\w`, `\+` works in regex)
        - you may also surround an argument with single or double quotes (`'abc'` or `"abc"`), which makes it so only quotes and `\` need to be escaped
        - this makes it so you can call a function like `#{filter x \w{1,3}}` without the need for crazy escaping
- operator precedences:
    - `|` binds weakest
    - concatenation binds stronger than `|`
    - `{n,m}` (range suffix) binds stronger than concatenation
    - `ab` is counted as a single string meaning `ab{5}` ≡ `<ab>{5}`, but `<a>b{5}` ≡ `<a><b{5}>`
    - `<...>`, `#{...}` and `[...]` expressions are not separable
    - to summarize, the operators precendences from strongest to weakest are:
        1. range (`...{n,m}`, unary)
        2. concatenation (e.g. `<...><...>`)
        3. or (`|`)

### Builtin variables and functions
- `#{load filename}`: loads pattern from file `filename` and returns it
- `#{import filename}`: import variables from file `filename` (never returns a value)
- `#{wordlist filename}`: import wordlist from file as or (`|`) expression
- `#{split x delims}`: split each string in the or expression `x` into words by any of the characters in delims and return each deduplicated word
- `#{limit x n}`: limit the or expression `x` to the first `n` elements
- `#{filter x regex}`: filter the or expression `x` to only the elements that match `regex`
- `#{remove x regex}`: like `filter`, but keeps the elements that *don't* match `regex`
- `#{replace x regex repl}`: for each item, replace all matches of the given regex with the given replacement pattern (e.g. $1 for capture group 1, $name for named capture group)
- `#{prefixes x delims}`: collect all prefixes of `x`, split by any of `delims` and deduplicate (e.g. `#{prefixes <a/b/c|a/b_d> _/}` -> `<a|a/b|a/b/c|a/b_d>`)
- `#{suffixes x delims}`: collect all suffixes of `x`, split by any of `delims` and deduplicate (e.g. `#{prefixes <a/b/c|x_b/c> _/}` -> `<c|b/c|a/b/c|x_b/c>`)
- `#{merge x y ...}`: merge all items in `x`, `y`, or any additional number of or expressions of strings, resulting in a flat or expression of strings with duplicates removed (you'll want to use this e.g. when combining word lists)

### Examples
- `content/#{known-words}{1,3,[_:]}`: `content/` followed by 1-3 known words, separated by `_` or `:`

## License
Copyright (c) xypwn

This program is licensed under the 3-Clause BSD License (https://opensource.org/license/bsd-3-clause).
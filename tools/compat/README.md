# Compat tool

`livemap_compat` judges a new Enshrouded server build against the last supported one. It reads the supported builds from
`data/builds.json`, scans both exes with the sigset of the previous build's row (the same patterns and offsets
`src/scan.cpp` applies), and compares the code around every site. Its output is a verdict and a JSON report.

It builds on Linux and Windows. The Linux binary is statically linked and is published as a release asset next to its
`.sha256`; the terms of the libraries linked into it are in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## Usage

```text
livemap_compat --builds FILE --previous EXE --exe EXE --build-id ID --manifest ID --depot ID
               --report FILE [--builds-out FILE]
```

| Argument       | Meaning                                                                                      |
| -------------- | -------------------------------------------------------------------------------------------- |
| `--builds`     | The supported builds, `data/builds.json`                                                     |
| `--previous`   | The server exe of the last supported build, the reference                                    |
| `--exe`        | The server exe of the new build                                                              |
| `--build-id`   | Steam build id of the new build                                                              |
| `--manifest`   | Steam manifest id of the new build                                                           |
| `--depot`      | Steam depot id of the new build                                                              |
| `--report`     | Where to write the JSON report                                                               |
| `--builds-out` | Where to write the builds file with the change a known or easy verdict asks for              |

The ids are Steam ids: decimal digits without a leading zero. The exit code is `0` for any verdict, `1` when the inputs
cannot be judged (an unreadable file, an exe that is not a PE file, a previous exe that is not the build its row
describes), and `2` for a wrong command line.

## Check a sigset

```text
livemap_compat check --builds FILE --exe EXE
```

`check` finds the row of `--builds` whose fingerprint is the exe's, and checks the sigset that row names against the exe,
whoever wrote the sigset. CI runs it on every exe of the exe store that a row lists, so a pull request that adds or
changes a sigset passes only when every check holds. Each problem names the site and the RVA it concerns.

- Each hook starts on a whole instruction, decoded from the start of its function through the exe's `.pdata`.
- No branch lands inside the bytes a hook overwrites.
- Every register a callback reads from the context is one the code at the hook uses: the instruction there, the code it
  leads to, or the instruction just before the hook. A call uses an argument register only when the code just before it
  wrote that register. A hook whose code from there cannot be followed is refused. The registers each callback reads are
  listed in `src/callbacks.cpp`; a test keeps that list in step with the callbacks.
- The exe is the one the row lists, and every site the row lists is found once, at the RVA the row lists.

The exit code is `0` when every check holds, `1` when the inputs cannot be judged (an unreadable file, an exe that no row
describes), `2` for a wrong command line, and `3` when a check failed. The problems go to standard output.

`tools/hook_check.py` runs the check on every row that lists an `exe_sha256`, and refuses a change to a row that lists none.

## Verdicts

- `known`: the fingerprint of the exe is already a row of the builds file, the exe is the one the row lists, and every
  site is where the row says. `--builds-out` holds the builds file with the build id as an alias of that row.
- `easy`: every pattern matches once, the function around each site equals the previous build's once addresses are
  normalized, no branch lands inside the bytes a hook overwrites, and the accessor operand is read by signature.
  `--builds-out` holds the builds file with a new row.
- `hard`: anything else. The reasons name each site that differs and how. `--builds-out` is not written, and a file
  an earlier run left there is removed. The same happens on exit `1`. A `--builds-out` that is one of the inputs is
  refused.

Comparison works on decoded instructions. Relative branch targets and RIP-relative displacements are normalized, and the
bytes the DLL reads as values of its own (the pattern operands) are left out. A jump table that sits inside a function is
compared as offsets from the start of the function. For the hook check the tool collects the branch targets of the whole
exe, including the entries of the jump tables it reads, so a branch from another function counts.

## Report

The report keys are `result`, `build_id`, `manifest`, `exe`, `base`, `matched_row`, `reasons`, `undecodable_functions`,
`operands` and `sites`. `undecodable_functions` is the number of functions the decoder could not read to their end, or
`null` when no branch collection ran. A site lists its match count, its RVA in both exes, the code region compared,
whether its hook starts on an instruction, the branches that land inside the hook, and the first difference. It holds
RVAs, counts and kinds only, never game bytes or disassembly.

## Build and test

```sh
cmake -S tools/compat -B build/compat -DCMAKE_BUILD_TYPE=Release
cmake --build build/compat
ctest --test-dir build/compat --output-on-failure --no-tests=error
```

Zydis comes from the dependency pinned in `cmake/zydis.cmake`. The tests build synthetic PE files in memory and carry no
game bytes.

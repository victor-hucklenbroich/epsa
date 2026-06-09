# EPSA (Evolutionary Program Similarity Attacks)

> **Devising Practical Attacks against Spectral Analysis for Program Clone Detection**

Bachelor's Thesis in Computer Science · Ludwig-Maximilians-Universität München
Chair of Programming Languages and Artificial Intelligence

**Author:** Victor Hucklenbroich

**Supervisor:** Prof. Dr. Johannes Kinder · **Advisor:** Dr. Tristan Benoit

**Submitted:** December 17, 2024


---

## Abstract

In this thesis we explore the resilience of program similarity measures against premeditated
attacks designed to manipulate clone detection results. We interpret program similarity and
program clone search as copyright infringement and malware detection in order to motivate our
practical attacks. Our approach is divided into two attack strategies: the first tries to hide a
program's identity, while the second aims to disguise a program as another. In both, we target a
specific similarity measure using spectral analysis on program graphs. The attacks are based on
deliberate source code changes that impact the analysis conducted on the program's compiled
binary. We build our attacks as evolutionary algorithms and propose a genetic encoding framework
for this problem. We achieve a consistent increase and decrease in similarity measures and some
successfully misidentified clones, and we analyze what characterizes programs from successful and
unsuccessful attacks.

**Keywords:** program similarity, spectral analysis, clone search, evolutionary algorithms

## Background

Program similarity measures identify how alike two whole programs are based on their compiled
binaries. This technique is used in reverse engineering, software theft detection, and malware
detection. **Program Spectral Similarity (PSS)** combines metrics gathered from spectral graph
analysis of a program's *call graph* and *control flow graphs* into a single similarity index
between `0` (disjunct) and `1` (identical). To detect clones, a query program is compared
pairwise against a repository of known programs, which are then ranked by their shared PSS value.
PSS remains accurate across changes in compiler options and differing versions of a program.

To test how robust such measures are against premeditated attacks, we attempt to evade PSS. The
problem is hard because of three layers of abstraction: an attacker can only edit the query's
**source code**, while the measure operates on the **compiled binary**, from which **graph
metrics** are extracted. We also assume the attacker does not know the contents of the comparison
repository. Crucially, any altered program must keep the original functionality, so we may only
*add* functionally null code, never remove existing code.

## Attack Strategies

EPSA consists of two strategies, both producing a functionally identical, source-modified version
`Q'` of a query program `Q`:

- **Obfuscation**: a PSS *minimization* problem. Hide a program's identity by lowering
  `PSS(Q', Q)` below the perfect self-similarity of `1.0`, ideally so that PSS no longer
  recognises `Q'` as a clone of itself.
- **Harmonisation**: a PSS *maximization* problem, and the harder of the two. Given an additional
  target program `T`, raise `PSS(Q', T)` so that PSS misidentifies the query as the target. This
  is an adaptation of a masquerade attack: the program is made to *look* different without *acting*
  differently.

## Approach

We frame both attacks as optimization problems and solve them with **evolutionary algorithms**,
introducing a genetic encoding framework for C programs.

- **Genes** are additions to the existing source code. They come in four types:
  *statements*, *function calls*, *control flow* (loops, if/else ladders), and
  whole *functions*. All identifiers and literals are randomly generated.
- **Genomes** are the locations in a source file where genes may be inserted, identified by parsing
  the bracket/parenthesis patterns of the original code so that genes are always placed at the
  start of existing control flow.
- **Individuals** are candidate solutions: a complete set of source files plus a generated
  "noise header" that declares all added functions, making them callable from any scope.

The evolutionary algorithm uses a **direct fitness function** (the PSS value itself; inverted and
compile-time-penalized for obfuscation, to favor quality of genes over quantity). Each generation
of **100 individuals** is evolved through **truncation selection** (best 22%), **elitist uniform
crossover** (10 elites + 2 random parents → 78 offspring), and **mutation** (25% chance per
individual, with the number of new genes scaled to the program's logical lines of code). Unfit
individuals (those that fail to compile or to be analyzed) are assigned a minimum fitness so they
cannot poison the gene pool. Every attack is given a ten-hour timeout.

## Results

The study is qualitative: six query programs (`fpconv`, `lft`, `linenoise`, `lua`, `make`, `tldr`)
were each attacked once with obfuscation and four times with harmonization, against a repository
of 105 binary entries from 22 open-source C projects compiled at optimization levels `-O0`–`-O3`.

- **Obfuscation** reduced the self-similarity of every program except `make`, by **~15% on average**
  (up to 25% for `tldr`). The repository rank changed for 4 of 6 programs, and **2 of 6** attacks
  fully deceived the clone search.
- **Harmonisation** increased the query→target PSS value in **22 of 24** executions (~0.03 on
  average), improved the target's repository rank in 18 of 24, and was **fully successful in 2 of
  24** (`lua`→`make` and `fpconv`→`cmp`).
- **Program size and complexity** hurt performance most (`make`, the largest, converged early and
  barely moved), since EPSA can currently only alter a single source directory.
- **Initial similarity** matters: harmonization works best when query and target share an
  *intermediate* initial PSS value (≈0.6–0.85), and poorly at the extremes.
- **Repository side effects** are the greatest impediment: because edits shift similarity to *all*
  programs, an attack can move the query toward an unrelated repository entry and fail despite a
  large, well-directed PSS change.

EPSA can consistently move PSS values and repository rankings, and occasionally deceives clone
search outright, within a constrained attack space and limited runtime. Because the attacks edit
source code and target graph metrics, they apply not only to PSS but to graph-based program
similarity measures in general.

## Repository layout

```
src/
  __main__.py      attack entry point (obfuscation / harmonisation demo)
  constants.py     configuration, attack mode, dataset loading, dependency checks
  genetics.py      genetic encoding (genes, genomes, individuals) and evolutionary steps
  pss.py           Program Spectral Similarity: angr analysis, graph spectra, comparison
  preprocessor.py  source discovery, compilation, cleanup, LoC counting
  logger.py        run logging
data/
  config           the active query program (a pickled config dict)
  configs/         ready-made configs for the demo query programs
  demo/            zipped source archives of the demo query programs
  BO_REPO_DATA     pickled repository of pre-computed feature vectors to compare against
```

## Running the attacks

> [!NOTE]
> This code accompanies a qualitative study and was built for a fixed Linux experimental
> environment (binaries compiled on Ubuntu with GCC). It is published primarily to document the
> thesis rather than as a turn-key tool reproducing results faithfully requires that same
> toolchain.

**Requirements:** Python 3.13 and the packages in [`requirements.txt`](requirements.txt) (`angr`,
`networkx`, `numpy`, `pandas`, `multipledispatch`). The host also needs `gcc`, `make`, and
[`scc`](https://github.com/boyter/scc) on the `PATH` for compilation and line counting.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Select a query program by copying one of the presets in `data/configs/` over `data/config`, choose
the attack in `src/constants.py` (`MODE = ModMode.OBFUSCATE` or `ModMode.HARMONIZE`), then run:

```bash
python -m src
```

Results per-generation logs, evolved feature vectors, and the final repository comparison are
written to `data/results/`.

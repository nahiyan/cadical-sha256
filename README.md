# CaDiCaL with SHA-256 Routines

This variant of CaDiCaL 1.8.0 SAT Solver has SHA-256 cryptanalysis routines
embedded. The purpose of this project is to find SHA-256 semi-free-start
collisions more efficiently than a pure CaDiCaL approach.

Please note that this solver is designed to only work with specific SAT
encodings, specifically the [SHA-256 Collision
Encoder by Saeed Nejati](https://github.com/nahiyan/cryptanalysis/tree/master/encoders/nejati-collision).

# Getting Started

## Configure

By default, the programmatic techniques are turned off and the encoding type
isn't specified. To provide the information, please edit the pre-processor
directives in the
[src/sha256/types.hpp](https://github.com/nahiyan/cadical-sha256/blob/master/src/sha256/types.hpp)
file.

## Build

To build the project, you can use CMake (recommended) or the original
CaDiCaL build scripts.

If you want to build through CMake, run the following command in the root of
this project:
```bash
cmake -Bbuild . && cmake --build build
```

If you want to build using the original CaDiCaL way, run the following command
in the root of this project:
```bash
./configure && make
```

## Verify

The SAT solutions can be verified from the log file of the solver (and the
encoding) using a [Python
script](https://github.com/nahiyan/cryptanalysis/blob/master/collision/verify_from_log.py).
For example, if you have a log file `log.txt` and an encoding file
`encoding.cnf`, the following command can verify the solution:

```bash
python verify_from_log.py encoding.cnf < log.txt
```

# Existing Benchmarks

Existing benchmarks with and without the programmatic techniques are available
at [GitHub repository](https://github.com/nahiyan/sha256-data). The programmatic
SAT results should be reproducible with this variant of the programmatic SAT
solver with the respective configurations.

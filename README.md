# CaDiCaL with SHA-256 Routines

This variant of CaDiCaL SAT Solver has SHA-256 cryptanalysis routines embedded. The purpose of this project is to find SHA-256 semi-free-start collisions more efficiently than a pure CaDiCaL approach.

Please note that this solver is designed to only work with specific SAT encodings. See the [Nejati Collision Encoder](https://github.com/nahiyan/cryptanalysis/tree/master/encoders/nejati-collision).

## Build

To build the project, you can use CMake (recommended) or the original
CaDiCaL build scripts.

If you want to build through CMake, run the following command in the root of this project:
```bash
cmake -Bbuild . && cmake --build build
```

If you want to build using the original CaDiCaL way, run the following command in the root of this project:
```bash
./configure && make
```

## Configuration

By default the programmatic techniques are turned off. Edit the pre-processor directives in the `src/sha256/types.hpp` file.

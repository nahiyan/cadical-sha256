#!/bin/bash

cd build
../scripts/make-build-header.sh >build.hpp
g++ -Wall -Wextra -O3 -DNDEBUG -I../build -c ../src/sha256.cpp
ar rc libcadical.a analyze.o arena.o assume.o averages.o backtrack.o backward.o bins.o block.o ccadical.o checker.o clause.o collect.o compact.o condition.o config.o constrain.o contract.o cover.o decide.o decompose.o deduplicate.o elim.o ema.o extend.o external.o external_propagate.o file.o flags.o flip.o format.o gates.o instantiate.o internal.o ipasir.o limit.o logging.o lookahead.o lratbuilder.o lratchecker.o lucky.o message.o minimize.o occs.o options.o parse.o phases.o probe.o profile.o proof.o propagate.o queue.o random.o reap.o reduce.o rephase.o report.o resources.o restart.o restore.o score.o sha256.o shrink.o signal.o solution.o solver.o stats.o subsume.o terminal.o ternary.o tracer.o transred.o util.o var.o version.o vivify.o walk.o watch.o
g++ -Wall -Wextra -O3 -DNDEBUG -I../build -o cadical cadical.o -L. -lcadical

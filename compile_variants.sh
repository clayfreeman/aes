#!/bin/bash
# Compiles all variants of the program based on worker count and size

# Clean the build environment before attempting to compile
make clean

# Compile the single threaded variant separately
make WORKER_COUNT=1

# Iterate over each amount of workers to be tested
for ((i = 2; i <= 16; i *= 2))
do
  # Iterate over each worker size to be tested
  for ((j = 32; j <= 16384; j *= 2))
  do
    # Compile this variant with `i` workers that operate on `j` blocks
    make WORKER_COUNT=$i WORKER_BLOCK_COUNT=$j
  done
done

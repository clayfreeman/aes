#!/bin/bash
# Tests all variants of the program based on worker count and size

# Exit on error
set -e

# Fetch a random nonce and key value
NCE=$(hexdump -n  8 -e '4/4 "%08X" 1 "\n"' /dev/urandom)
KEY=$(hexdump -n 16 -e '4/4 "%08X" 1 "\n"' /dev/urandom)

for ((s = 1; s <= 128; s *= 2))
do
  # Allocate a file of this size
  dd if=/dev/zero of=./test.bin bs=1m count=$s &> /dev/null

  # Test the single threaded application separately
  for k in {1..16}
  do
    ./main_1w_*b ./test.bin $NCE $KEY 2>&1 | \
      awk '{printf "1,1,%d,1:1:%d,%f,%f\n", $3, $3, $6, $3/$6}'
  done

  # Iterate over each amount of workers to be tested
  for ((i = 2; i <= 16; i *= 2))
  do
    # Iterate over each worker size to be tested
    for ((j = 32; j <= 16384; j *= 2))
    do
      # Test this variant with `i` workers that operate on `j` blocks
      for k in {1..16}
      do
        ./main_${i}w_${j}b ./test.bin $NCE $KEY 2>&1 | \
          awk '{printf "'$i,$j',%d,'$i:$j':%d,%f,%f\n", $3, $3, $6, $3/$6}'
      done
    done
  done
done

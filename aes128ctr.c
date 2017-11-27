/**
 * Copyright (C) 2017  Clay Freeman.
 * This file is part of clayfreeman/aes.
 *
 * clayfreeman/aes is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * clayfreeman/aes is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with the GNU C Library; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "aes.h"
#include "aes128.h"
#include "aes128ctr.h"

#ifdef __APPLE__
#define lseek64 lseek
#define open64  open
#endif

void aes128ctr_get_key(const aes128_nonce_t* nonce, const aes128_key_t* key,
  uint64_t counter, aes128_state_t* state);

void aes128ctr_get_key(const aes128_nonce_t* nonce,
    const aes128_key_t* key, uint64_t counter, aes128_state_t* state) {
  // Convert the counter to big-endian byte order
  counter = htonll(counter);
  // Copy the corresponding nonce and counter into the input
  memcpy(state->val,                      nonce->val, sizeof(nonce->val));
  memcpy(state->val + sizeof(nonce->val), &counter, sizeof(counter));
  // Crypt the input to generate a key stream for this block
  aes128_encrypt(key, state);
}

extern void aes128ctr_crypt(const aes128_nonce_t* nonce,
    const aes128_key_t* key, aes128_state_t* state, const uint64_t counter) {
  // Fetch the key stream for this counter
  aes128_state_t    key_stream;
  aes128ctr_get_key(nonce, key, counter, &key_stream);
  // XOR the state with the key stream
  for (uint8_t i = 0; i < sizeof(state->val); ++i)
    state->val[i] ^= key_stream.val[i];
}

extern size_t aes128ctr_crypt_block_file(const aes128_nonce_t* nonce,
    const aes128_key_t* key, FILE* ifp, FILE* ofp, const uint64_t counter) {
  aes128_state_t state;
  // Reliably read a block from the file into the state structure
  size_t bytes_read = fread(state.val, 1, sizeof(state.val), ifp);
  // Crypt this block from the file
  aes128ctr_crypt(nonce, key, &state, counter);
  // Reliably write a block to the file from the state structure
  return fwrite(state.val, 1, bytes_read, ofp);
}

extern fpos_t aes128ctr_crypt_path(const aes128_nonce_t* nonce,
    const aes128_key_t* key, const char* path) {
  // Open two files; one for read, one for write
  FILE* ifp = fopen(path, "rb"); FILE* ofp = fopen(path, "r+b");
  // Set the buffer size for the file to increase throughput
  setvbuf(ifp, NULL, _IOFBF, 1 << 12);
  setvbuf(ofp, NULL, _IOFBF, 1 << 12);
  // Iterate over each chunk to encrypt its blocks
  for (uint64_t counter = 0, result = 16; result == 16; ++counter)
    result = aes128ctr_crypt_block_file(nonce, key, ifp, ofp, counter);
  // Return the current position of the output stream
  fpos_t size; fgetpos(ofp, &size);
  fclose(ifp); fclose(ofp);
  return size;
}

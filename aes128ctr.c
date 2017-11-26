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

#include <errno.h>
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

inline void aes128ctr_get_key(const aes128_nonce_t* nonce,
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

extern int aes128ctr_crypt_block_fd(const aes128_nonce_t* nonce,
    const aes128_key_t* key, const int fd, const uint64_t counter) {
  aes128_state_t state;
  // Reliably read a block from the file into the state structure
  int n = 0; // Keep track of the number of bytes that were read
  for (int ret = 1; ret > 0 && n < 16; n += ret) {
    // Attempt to read up to 16 bytes from the file
    ret = read(fd, state.val + n, 16 - n);
    // Check for a fatal error while reading the file
    if (ret < 0 && errno != EINTR && errno != EAGAIN)
      { perror("read()"); return 1; }
  } // Crypt this block from the file
  aes128ctr_crypt(nonce, key, &state, counter);
  // Seek to the start of the block
  lseek64(fd, -n, SEEK_CUR);
  // Reliably write a block to the file from the state structure
  for (int l = 0, ret = 0; l < n; l += ret) {
    // Attempt to write up to 16 bytes to the file
    ret = write(fd, state.val + l, n - l);
    // Check for a fatal error while writing to the file
    if (ret < 0 && errno != EINTR && errno != EAGAIN)
      { perror("write()"); return 1; }
  } return 0;
}

extern int aes128ctr_crypt_fd(const aes128_nonce_t* nonce,
    const aes128_key_t* key, const int fd, struct timespec* elapsed) {
  // Fetch the file size of the provided file descriptor
  const uint64_t size = lseek64(fd, 0, SEEK_END); lseek64(fd, 0, SEEK_SET);
  // Iterate over each block of the file and crypt it
  for (uint64_t block = 0; block < (size >> 4) + ((size & 16) > 0); ++block) {
    // Check that the block was crypted successfully
    if (aes128ctr_crypt_block_fd(nonce, key, fd, block) != 0)
      return 1;
  } return 0;
}

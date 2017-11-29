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

#include <stdint.h>
#include <string.h>

#include "aes.h"
#include "aes128.h"

void aes128_add_round_key(const aes128_state_t* in, aes128_state_t* out,
  const aes128_key_t* key, const uint8_t round_num);
void aes128_key_advance(const uint8_t* in, uint8_t* out,
  const uint8_t round_num);
void aes128_sbox_repl(const aes128_state_t* in, aes128_state_t* out);
void aes128_shift_col(const aes128_state_t* in, aes128_state_t* out,
  const uint8_t column, uint8_t amount);
void aes128_shift_cols(const aes128_state_t* in, aes128_state_t* out);
void aes128_mix_row(const uint8_t* in, uint8_t* out);
void aes128_mix_rows(const aes128_state_t* in, aes128_state_t* out);

extern void aes128_encrypt(const aes128_key_t* key, aes128_state_t* state) {
  // Repeat for 11 rounds of the algorithm
  for (uint8_t round_num = 0; round_num < 11; ++round_num) {
    // Substitute each byte of the state with one from the S-box
    if (round_num > 0)                   aes128_sbox_repl(state, state);
    // Perform a circular shift on each row of the state
    if (round_num > 0)                   aes128_shift_cols(state, state);
    // Run mix_row() on each row of the state
    if (round_num > 0 && round_num < 10) aes128_mix_rows(state, state);
    // XOR the round key with the state
    aes128_add_round_key(state, state, key, round_num);
  }
}

extern void aes128_key_init(aes128_key_t* key) {
  // Zero all key slots after the first
  memset(key->val + (1 << 4), 0, sizeof(key->val) - (1 << 4));
  // Calculate the full key schedule from the original key
  for (uint8_t i = 0, j = 1; i < 10; ++i, ++j)
    // Use the previous round's key to incrementally advance the key
    aes128_key_advance(key->val + (i << 4), key->val + (j << 4), j);
}

void aes128_add_round_key(const aes128_state_t* in, aes128_state_t* out,
    const aes128_key_t* key, const uint8_t round_num) {
  // XOR each state byte with the corresponding key byte
  for (uint8_t i = 0; i < 16; ++i)
    out->val[i] = in->val[i] ^ key->val[(round_num << 4) + i];
}

void aes128_sbox_repl(const aes128_state_t* in, aes128_state_t* out) {
  // Iterate over each byte of the input and replace it with its S-box value
  for (uint8_t i = 0; i < 16; ++i)
    out->val[i] = aes_sbox[in->val[i]];
}

void aes128_shift_cols(const aes128_state_t* in, aes128_state_t* out) {
  // Circular shift each column using its index as the shift amount
  for (uint8_t i = 0; i < 4; ++i)
    aes128_shift_col(in, out, i, i);
}

void aes128_shift_col(const aes128_state_t* in, aes128_state_t* out,
    const uint8_t column, uint8_t amount) {
  amount %= 4;
  // Store the original values held in this column
  uint8_t temp[4] = {
    in->val[column + 0], in->val[column + 4],
    in->val[column + 8], in->val[column + 12]
  }; // Shift the temporary array by the desired amount
  *(uint32_t*)temp = ((*(uint32_t*)temp) >> ((    amount) << 3)) |
                     ((*(uint32_t*)temp) << ((4 - amount) << 3));
  // Assign the shifted column to the output
  out->val[column +  0] = temp[0];
  out->val[column +  4] = temp[1];
  out->val[column +  8] = temp[2];
  out->val[column + 12] = temp[3];
}

void aes128_mix_rows(const aes128_state_t* in, aes128_state_t* out) {
  // Iterate through each row in the table to mix it
  for (uint8_t i = 0; i < 4; ++i)
    aes128_mix_row(in->val + (i << 2), out->val + (i << 2));
}

void aes128_mix_row(const uint8_t* in, uint8_t* out) {
  // Store the original values held in this row
  uint8_t temp[4] = {
    in[0], in[1], in[2], in[3]
  }; // Calculate the mixed column using the pre-calculated values
  out[0] = temp[1] ^ aes_gal2[temp[0]] ^ aes_gal2[temp[1]] ^ temp[2] ^ temp[3];
  out[1] = temp[2] ^ temp[0] ^ aes_gal2[temp[1]] ^ aes_gal2[temp[2]] ^ temp[3];
  out[2] = temp[3] ^ temp[0] ^ temp[1] ^ aes_gal2[temp[2]] ^ aes_gal2[temp[3]];
  out[3] = temp[0] ^ aes_gal2[temp[0]] ^ temp[1] ^ temp[2] ^ aes_gal2[temp[3]];
}

void aes128_key_advance(const uint8_t* in, uint8_t* out,
    const uint8_t round_num) {
  // Create a pointer to the last row of the input key
  const uint8_t _in[4] = { 13, 14, 15, 12 };
  // Assign the round constant to the first byte
  out[0] = aes_rcon[round_num];
  // Iterate over and copy each input byte to the output byte
  for (uint8_t i = 0; i < 16; ++i) {
    // XOR this output byte with ...
    out[i] ^= in[i] ^ (i < 4 ?
      // ... the forward S-box substitution of in[13, 14, 15, 12] ...
      aes_sbox[in[_in[i]]] :
      // ... or the previous word's matching byte of output
      out[i - 4]);
  }
}

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

#ifndef __AES128CTR_H
#define __AES128CTR_H

#include <time.h>

#include "aes.h"
#include "aes128.h"

extern void aes128ctr_crypt(const aes128_nonce_t* nonce,
  const aes128_key_t* key, aes128_state_t* state, uint64_t counter);
extern size_t aes128ctr_crypt_block_file(const aes128_nonce_t* nonce,
  const aes128_key_t* key, FILE* fp, const uint64_t counter);
extern fpos_t aes128ctr_crypt_file(const aes128_nonce_t* nonce,
  const aes128_key_t* key, FILE* fp);

#endif

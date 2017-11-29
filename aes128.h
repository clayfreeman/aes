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
 * License along with clayfreeman/aes; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef __AES128_H
#define __AES128_H

#include <stdint.h>

#include "aes.h"

typedef struct {
  uint8_t val[8];
} aes128_nonce_t;

typedef struct {
  uint8_t val[176];
} aes128_key_t;

typedef struct {
  uint8_t val[16];
} aes128_state_t;

extern void aes128_encrypt(const aes128_key_t* key, aes128_state_t* state);
extern void aes128_key_init(aes128_key_t* key);

#endif

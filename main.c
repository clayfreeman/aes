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

#define _LARGEFILE64_SOURCE
#define _POSIX_C_SOURCE 199309L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "aes.h"
#include "aes128.h"
#include "aes128ctr.h"

size_t          size;
aes128_nonce_t  nonce;
aes128_key_t    key;

#ifndef AES128CTR_WORKER_COUNT
  #define AES128CTR_WORKER_COUNT 8
#endif

void timespec_diff(const struct timespec* start, struct timespec* end);
void usage(int argc, char* argv[]);

int main(int argc, char* argv[]) {
  FILE* fp = NULL;
  // Ensure that the minimum of three arguments was provided
  if (argc < 4) {
    fprintf(stderr, "error: Not enough arguments.\n");
    usage(argc, argv);
    return 1;
  }
  errno = 0;
  // Attempt to open the file at the path held by the first argument
  if ((fp = fopen(argv[1], "r+b")) == NULL) {
    perror("file: fopen()");
    usage(argc, argv);
    return 2;
  }
  // Determine the size of the file
  fseek(fp, 0, SEEK_END); size = ftell(fp); fclose(fp); fp = NULL;
  // Ensure that the provided NONCE argument is the correct length
  if (strlen(argv[2]) != 16) {
    fprintf(stderr, "error: nonce must be 16 hexadecimal characters\n");
    usage(argc, argv);
    return 3;
  }
  errno = 0;
  // Attempt to read the NONCE held by the second argument
  { uint64_t tmp = htonll(strtoull(argv[2], NULL, 16));
  memcpy(nonce.val, &tmp, 8); tmp = 0; }
  if (errno != 0) {
    perror("nonce: strtoull()");
    usage(argc, argv);
    return 4;
  }
  // Ensure that the provided KEY argument is the correct length
  if (strlen(argv[3]) != 32) {
    fprintf(stderr, "error: key must be 32 hexadecimal characters\n");
    usage(argc, argv);
    return 5;
  }
  errno = 0;
  // Attempt to read the low portion of the key first
  { uint64_t tmp = htonll(strtoull(argv[3] + 16, NULL, 16));
  memcpy(key.val + 8, &tmp, 8); tmp = 0; }
  // Replace the first byte of the low portion with a NULL character
  argv[3][16] = 0;
  // Finally, attempt to read the high portion of the key
  { uint64_t tmp = htonll(strtoull(argv[3],      NULL, 16));
  memcpy(key.val,     &tmp, 8); tmp = 0; }
  // Check for an error during either HIGH/LOW strtoull() operation
  if (errno != 0) {
    perror("key: strtoull()");
    usage(argc, argv);
    return 6;
  }
  // Create some state to store the status and duration of the ops
  size_t status = 0; struct timespec start = {0, 0}, end = {0, 0};
  // Attempt to initialize the key and crypt the file
  aes128_key_init(&key);
  clock_gettime(CLOCK_MONOTONIC, &start);
  #if (AES128CTR_WORKER_COUNT == 1)
    status = aes128ctr_crypt_path(&nonce, &key, argv[1]);
  #else
    status = aes128ctr_crypt_path_pthread(&nonce, &key, argv[1],
      AES128CTR_WORKER_COUNT);
  #endif
  clock_gettime(CLOCK_MONOTONIC, &end);
  timespec_diff(&start, &end);
  double duration = ((double)end.tv_sec + (end.tv_nsec / 1000000000.0));
  // Zero-initialize the nonce and key for security
  memset(nonce.val, 0, sizeof(nonce.val));
  memset(  key.val, 0, sizeof(  key.val));
  // Check the status of the cryption operation
  if (status != size) {
    fprintf(stderr, "error: Cryption failed\n");
    return 127;
  }
  fprintf(stderr, "success: Crypted %f MB in %f sec (%f MB/s)\n",
    (status / (double)(1 << 20)),  duration,
    (status / (double)(1 << 20)) / duration);
  return 0;
}

void timespec_diff(const struct timespec* start, struct timespec* end) {
  if ((end->tv_nsec - start->tv_nsec) < 0) {
    end->tv_sec  -= start->tv_sec  - 1;
    end->tv_nsec -= start->tv_nsec + 1000000000;
  } else {
    end->tv_sec  -= start->tv_sec;
    end->tv_nsec -= start->tv_nsec;
  }
}

void usage(int argc, char* argv[]) {
  if (argc > 0) {
    fprintf(stderr, "\nUsage: %s <file> <nonce> <key>\n", argv[0]);
    fprintf(stderr, "  * nonce is a  64-bit hexadecimal value\n"
                    "  * key   is a 128-bit hexadecimal value\n");
  } else {
    fprintf(stderr, "error: argc <= 0\n");
  }
}

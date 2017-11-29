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

#include <pthread.h>
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

#if DEBUG
  pthread_mutex_t io = PTHREAD_MUTEX_INITIALIZER;
#endif

void aes128ctr_get_key(const aes128_nonce_t* nonce, const aes128_key_t* key,
  uint64_t counter, aes128_state_t* state);
void* aes128ctr_pthread_target(void* arg);

void aes128ctr_get_key(const aes128_nonce_t* nonce,
    const aes128_key_t* key, uint64_t counter, aes128_state_t* state) {
  // Convert the counter to big-endian byte order
  counter = htonll(counter);
  // Copy the corresponding nonce and counter into the input
  memcpy(state->val,                      nonce->val, sizeof(nonce->val));
  memcpy(state->val + sizeof(nonce->val), &counter, sizeof(counter));
  #if DEBUG
    fprintf(stderr, "[AES] KEY  : ");
    for (size_t i = 0; i < 16; ++i)
      fprintf(stderr, "%s%02x", i > 0 ? " " : "", key->val[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "[AES] STATE: ");
    for (size_t i = 0; i < 16; ++i)
      fprintf(stderr, "%s%02x", i > 0 ? " " : "", state->val[i]);
    fprintf(stderr, "\n");
  #endif
  // Crypt the input to generate a key stream for this block
  aes128_encrypt(key, state);
  #if DEBUG
    fprintf(stderr, "[AES] ENCPT: ");
    for (size_t i = 0; i < 16; ++i)
      fprintf(stderr, "%s%02x", i > 0 ? " " : "", state->val[i]);
    fprintf(stderr, "\n\n");
  #endif
}

extern void aes128ctr_crypt(const aes128_nonce_t* nonce,
    const aes128_key_t* key, aes128_state_t* state, const uint64_t counter) {
  // Fetch the key stream for this counter
  aes128_state_t    key_stream;
  aes128ctr_get_key(nonce, key, counter, &key_stream);
  #if DEBUG
    fprintf(stderr, "[AES] BEFOR: ");
    for (size_t i = 0; i < 16; ++i)
      fprintf(stderr, "%s%02x", i > 0 ? " " : "", state->val[i]);
    fprintf(stderr, "\n");
  #endif
  // XOR the state with the key stream
  for (uint8_t i = 0; i < sizeof(state->val); ++i)
    state->val[i] ^= key_stream.val[i];
  #if DEBUG
    fprintf(stderr, "[AES] AFTER: ");
    for (size_t i = 0; i < 16; ++i)
      fprintf(stderr, "%s%02x", i > 0 ? " " : "", state->val[i]);
    fprintf(stderr, "\n\n");
  #endif
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

extern size_t aes128ctr_crypt_path(const aes128_nonce_t* nonce,
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
  size_t size = ftell(ofp); fclose(ifp); fclose(ofp);
  return size;
}

extern size_t aes128ctr_crypt_path_pthread(const aes128_nonce_t* nonce,
    const aes128_key_t* key, const char* path, const size_t threads) {
  // Create a pool of workers to process data
  aes128ctr_worker_t workers[threads];
  // Open two files; one for read, one for write
  FILE* ifp = fopen(path, "rb"); FILE* ofp = fopen(path, "r+b");
  // Set the buffer size for the file to increase throughput
  setvbuf(ifp, NULL, _IOFBF, threads * (AES128CTR_WORKER_BLOCK_COUNT << 4));
  setvbuf(ofp, NULL, _IOFBF, threads * (AES128CTR_WORKER_BLOCK_COUNT << 4));
  // Iterate over each thread to prepare it for launch
  for (size_t i = 0; i < threads; ++i) {
    // Ensure that the control flags are initialized
    workers[i].stop  = 0;
    workers[i].tid   = i;
    workers[i].vi    = workers[i].vo = 0;
    // Assign the nonce and key pointers for this worker
    workers[i].nonce = nonce; workers[i].key = key;
    // Initialize the mutexes and conditions for this worker
    pthread_mutex_init(&workers[i].mi, NULL);
    pthread_mutex_init(&workers[i].mo, NULL);
    pthread_cond_init (&workers[i].ci, NULL);
    pthread_cond_init (&workers[i].co, NULL);
    // Launch this thread by calling pthread_create()
    pthread_create(&workers[i].thread, NULL,
      aes128ctr_pthread_target, &workers[i]);
  }
  // Continue reading until sentinel, error or EOF
  uint64_t counter = 0;
  while (!feof(ifp) && !ferror(ifp) && !ferror(ofp)) {
    #if DEBUG
      pthread_mutex_lock(&io);
      fprintf(stderr, "[MAIN] Loop start.\n");
      pthread_mutex_unlock(&io);
    #endif
    // Prepare each thread for data processing
    for (size_t i = 0; !feof(ifp) && !ferror(ifp) && i < threads; ++i) {
      pthread_mutex_lock(&workers[i].mi);
      #if DEBUG
        pthread_mutex_lock(&io);
        fprintf(stderr, "[MAIN] Loading data for Thread %lu ...\n", i);
        pthread_mutex_unlock(&io);
      #endif
      size_t pos = ftell(ifp);
      // Attempt to read as many blocks for this worker as specified
      workers[i].length = (workers[i].blocks = fread(workers[i].state,
        16, AES128CTR_WORKER_BLOCK_COUNT, ifp)) << 4;
      // Check to see that the requested number of blocks could not be read
      if (workers[i].blocks < AES128CTR_WORKER_BLOCK_COUNT) {
        fseek(ifp, pos + workers[i].length, SEEK_SET);
        // Attempt to read a partial block into the next block
        size_t bytes = fread(&workers[i].state[workers[i].blocks], 1, 16, ifp);
        // If we read non-zero bytes, then increment the block count and length
        if (bytes > 0) {
          ++workers[i].blocks; workers[i].length += bytes;
          #if DEBUG
            pthread_mutex_lock(&io);
            fprintf(stderr, "[MAIN] Partial data for Thread %lu: %lu @ %lu B\n",
            i, workers[i].blocks, workers[i].length);
            pthread_mutex_unlock(&io);
          #endif
        }
      }
      // Set the offset of the worker and increment the counter
      workers[i].offset = counter; counter += workers[i].blocks;
      // Signal the thread to begin processing data (if available)
      if (workers[i].blocks > 0) {
        #if DEBUG
          pthread_mutex_lock(&io);
          fprintf(stderr, "[MAIN] Signaling input for Thread %lu ...\n", i);
          pthread_mutex_unlock(&io);
        #endif
        workers[i].vi = 1; pthread_cond_signal(&workers[i].ci);
      }
      #if DEBUG
        pthread_mutex_lock(&io);
        fprintf(stderr, "[MAIN] Done loading data (%lu blocks / %lu B) for Thread %lu ...\n",
          workers[i].blocks, workers[i].length, i);
        pthread_mutex_unlock(&io);
      #endif
      pthread_mutex_unlock(&workers[i].mi);
    }
    // Flush each thread's data to disk after it is finished processing
    for (size_t i = 0, stop = 0; !stop && workers[i].blocks > 0 && !ferror(ofp) && i < threads; ++i) {
      // Wait for this thread to finish processing data
      pthread_mutex_lock(&workers[i].mo);
      #if DEBUG
        pthread_mutex_lock(&io);
        fprintf(stderr, "[MAIN] Writing data for Thread %lu ...\n", i);
        pthread_mutex_unlock(&io);
      #endif
      while (!workers[i].vo) pthread_cond_wait(&workers[i].co, &workers[i].mo);
      workers[i].vo = 0; pthread_cond_signal(&workers[i].co);
      // Flush this worker's data to disk
      if (workers[i].blocks > 0) {
        size_t bytes = fwrite(workers[i].state, 1, workers[i].length, ofp);
        stop = bytes < workers[i].length;
      }
      // Release the mutex to allow further processing of data
      #if DEBUG
        pthread_mutex_lock(&io);
        fprintf(stderr, "[MAIN] Done writing data for Thread %lu ...\n", i);
        pthread_mutex_unlock(&io);
      #endif
      pthread_mutex_unlock(&workers[i].mo);
    }
    #if DEBUG
      pthread_mutex_lock(&io);
      fprintf(stderr, "[MAIN] Loop end.\n");
      pthread_mutex_unlock(&io);
    #endif
  }
  #if DEBUG
    pthread_mutex_lock(&io);
    fprintf(stderr, "[MAIN] Stopping all threads ...\n");
    pthread_mutex_unlock(&io);
  #endif
  // Send a cancellation request to each thread and wait for it to exit
  for (size_t i = 0; i < threads; ++i) {
    pthread_mutex_lock(&workers[i].mi);
    workers[i].stop = 1; pthread_cond_signal(&workers[i].ci);
    pthread_mutex_unlock(&workers[i].mi);
    pthread_join(workers[i].thread, NULL);
  }
  // Fetch the current position of the output stream and close both streams
  size_t pos = ftell(ofp); fclose(ifp); fclose(ofp);
  return pos;
}

void* aes128ctr_pthread_target(void* arg) {
  // Allow this thread to be cancelled at any time
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,       NULL);
  pthread_setcancelstate(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
  // Create a pointer to this worker's information structure
  aes128ctr_worker_t* worker = (aes128ctr_worker_t*)arg;
  for (;;) {
    // Wait for the signal to begin processing data
    pthread_mutex_lock(&worker->mi);
    #if DEBUG
      pthread_mutex_lock(&io);
      fprintf(stderr, "[Thread %lu] Waiting for data ...\n", worker->tid);
      pthread_mutex_unlock(&io);
    #endif
    while (!worker->stop && !worker->vi)
      pthread_cond_wait(&worker->ci, &worker->mi);
    #if DEBUG
      pthread_mutex_lock(&io);
      fprintf(stderr, "[Thread %lu] Stop: %d\n", worker->tid, worker->stop);
      pthread_mutex_unlock(&io);
    #endif
    if (worker->stop) pthread_exit(NULL);
    worker->vi = 0; pthread_cond_signal(&worker->ci);
    pthread_mutex_unlock(&worker->mi);
    // Iterate over each block and encrypt it
    for (size_t i = 0; i < worker->blocks; ++i)
      aes128ctr_crypt(worker->nonce, worker->key,
        &worker->state[i], worker->offset + i);
    // Signal the main thread that we're done processing data
    pthread_mutex_lock(&worker->mo);
    #if DEBUG
      pthread_mutex_lock(&io);
      fprintf(stderr, "[Thread %lu] Processing complete.\n", worker->tid);
      pthread_mutex_unlock(&io);
    #endif
    worker->vo = 1; pthread_cond_signal(&worker->co);
    pthread_mutex_unlock(&worker->mo);
  } return NULL;
}

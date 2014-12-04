#ifndef SERVICE_SOFTBLOCK_H
#define SERVICE_SOFTBLOCK_H

#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "util/locks.h"
#include "util/random.h"

#define BF_BLOCKSIZE 64

struct bloomfilter {
  char *key; /* 16bytes long */

  size_t k;
  size_t size;
  uint8_t *field[2];

  time_t start;
  int interval;

  time_t *lastupdate[2];
  time_t timebase[2];

  lock_quick_t lock;

  int on;

};

void bf_destroy(struct bloomfilter *bf);
struct bloomfilter *bf_create(size_t size, size_t k, struct ub_randstate *rnd,
                              time_t now, int interval);

void softblock_learn(struct bloomfilter *bf, uint8_t *name, size_t namelen,
                        time_t now);

int softblock_check(struct bloomfilter *bf, uint8_t *name, size_t namelen,
                    time_t now);

#endif

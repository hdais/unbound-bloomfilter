#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "util/data/dname.h"
#include "util/log.h"
#include "util/locks.h"
#include "ldns/str2wire.h"
#include "ldns/wire2str.h"
#include "services/softblock.h"
#include "cache/dns.h"

uint64_t siphash24(const void *, unsigned long, const char[]);

struct bloomfilter *bf_create(size_t size, size_t k, char *key,
			      time_t now, int interval) {

  struct bloomfilter *bf;
  unsigned int i, j;

  bf = malloc(sizeof(struct bloomfilter));
  if(!bf)return NULL;
  if(size > 0) {
        log_info("softblock enabled size=%u", size);
	bf->on = 1;
  } else {
	bf->on = 0;
        log_info("softblock disabled");
        return bf;
  }

  /* round up to multiple of BF_BLOCKSIZE */
  size = size + BF_BLOCKSIZE - size % BF_BLOCKSIZE;

  bf->key = NULL;
  bf->field[0] = NULL;
  bf->lastupdate[0] = NULL;

  bf->size = size;
  bf->k = k;

  bf->key = malloc(16);
  if(!bf->key) {
    bf_destroy(bf);
    return NULL;
  }
  memcpy(bf->key, key, 16);

  bf->field[0] = malloc(size * 2);
  if(!bf->field[0]) {
    bf_destroy(bf);
    return NULL;
  }
  bf->field[1] = bf->field[0] + size;

  bf->lastupdate[0] = calloc(size / BF_BLOCKSIZE * 2, sizeof(time_t));
  if(!bf->lastupdate[0]) {
    bf_destroy(bf);
    return NULL;
  }
  bf->lastupdate[1] = bf->lastupdate[0] + size / BF_BLOCKSIZE;

  /*
  bf->lock[0] = calloc(size / BF_BLOCKSIZE * 2, sizeof(lock_quick_t));
  if(!bf->lock[0]) {
    bf_destroy(bf);
    return NULL;
  }

  for(i=0;i<size / BF_BLOCKSIZE * 2;i++) {
      lock_quick_init(&bf->lock[0][i]);
  }
  bf->lock[1] = bf->lock[0] + size / BF_BLOCKSIZE;
  */
  bf->start = now;
  bf->interval = interval;
  bf->timebase[0] = bf->timebase[1] = 0;
  lock_quick_init(&bf->lock);
  return bf;
}

void bf_destroy(struct bloomfilter *bf) {
  if(bf->on) {
    if(bf->key) free(bf->key);
    if(bf->field[0]) free(bf->field[0]);
    if(bf->lastupdate[0]) free(bf->lastupdate[0]);
    lock_quick_destroy(&bf->lock);
  }
  free(bf);
}

uint64_t bf_hash(struct bloomfilter *bf, int k,
		 uint8_t *name, size_t namelen) {
  char key[16];
  memcpy(key, bf->key, 16);
  key[0] ^= k & 0xff;
  key[1] ^= (k >> 8) & 0xff;
  return siphash24(name, namelen, key);
}

void bf_set(struct bloomfilter *bf, uint8_t *name,
	    size_t namelen, time_t now) {

  unsigned int i, index, luindex, byteindex;
  uint8_t *lname;
  uint8_t *field;
  time_t  curbase;
  time_t *lastupdate;
  uint64_t h;

  if(bf->start > now) return;

  lname = malloc(namelen);
  if(!lname)return;
  memcpy(lname, name, namelen);
  query_dname_tolower(lname);

  index = (now - bf->start) / bf->interval % 2;


  lock_quick_lock(&bf->lock);

  field = bf->field[index];
  lastupdate = bf->lastupdate[index];
  curbase =
    ((now - bf->start) / bf->interval) * bf->interval
    + bf->start;
  bf->timebase[index] = curbase;
  lock_quick_unlock(&bf->lock);

  for(i=0;i<bf->k; i++) {
    h = bf_hash(bf, i, lname, namelen) % ((uint64_t)bf->size << 3);
    byteindex = h >> 3;
    luindex = byteindex / BF_BLOCKSIZE;
    // log_info("bf_set: h = %llu, byteindex = %d", h, byteindex);

    /* clear this block if dirty */
    lock_quick_lock(&bf->lock);
    if(lastupdate[luindex] < curbase) {
      memset(field + (byteindex / BF_BLOCKSIZE) * BF_BLOCKSIZE,
	     0, BF_BLOCKSIZE);
    }
    field[byteindex] |= (1 << (h & 0x7));
    lastupdate[luindex] = now;
    lock_quick_unlock(&bf->lock);
  }

  free(lname);
}

int bf_check(struct bloomfilter *bf, uint8_t *name, size_t namelen,
	     time_t now) {
  
  unsigned int i, index, luindex, byteindex, match[2];
  uint8_t *lname;
  uint64_t h;

  if(bf->start > now) return 1;

  lname = malloc(namelen);
  if(!lname)return 0;
  memcpy(lname, name, namelen);
  query_dname_tolower(lname);

  match[0] = match[1] = 1;

  for(i = 0; i < bf->k; i++) {
    h = bf_hash(bf, i, lname, namelen) % ((uint64_t)bf->size << 3);
    byteindex = h >> 3;
    luindex = byteindex / BF_BLOCKSIZE;

    for(index = 0; index < 2; index++) {
	/*
	if(bf->timebase[index] == 0 ||
		bf->lastupdate[index][luindex] < bf->timebase[index] ) {
		match[index] = 0;
	}
	match[index] &=((bf->field[index][byteindex] & ( 1 << ( h & 0x7)))?0:1);
	*/
      if(match[index] == 0) continue;

      lock_quick_lock(&bf->lock);

      if(now - bf->lastupdate[index][luindex] > bf->interval * 2) {
	match[index] = 0;
	lock_quick_unlock(&bf->lock);
	continue;
      }
      if(bf->field[index][byteindex] & ( 1 << ( h & 0x7))) {
	match[index] = 1;
      } else {
	match[index] = 0;
      }

      lock_quick_unlock(&bf->lock);

    }
  }
  
  free(lname);
  return match[0] | match[1];
}

void softblock_learn(struct bloomfilter *bf, uint8_t *name, size_t namelen,
			time_t now)
{
  if(bf->on)
     bf_set(bf, name, namelen, now);
}

int softblock_check(struct bloomfilter *bf, uint8_t *name, size_t namelen,
		    time_t now)
{
  if(bf->on) {
     return bf_check(bf, name, namelen, now);
  }
  return 1;
}

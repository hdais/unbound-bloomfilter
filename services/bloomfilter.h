#ifndef SERVICE_BLOOMFILTER_H
#define SERVICE_BLOOMFILTER_H

#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "util/locks.h"
#include "util/random.h"
#include "services/mesh.h"

#define BF_BLOCKSIZE 64

#define BF_BLOCKLIST_UPDATE_INTERVAL 5

#define SIPHASH_KEYSIZE 16

struct psrule {
  uint8_t *name;
  size_t namelen;
  size_t namelabs;
  int wildcard;
  int thisname;
  uint32_t hash;
  struct psrule *next;
};

struct psl {
  struct psrule **rule;
  struct psrule **exception_rule;
  size_t bucketsize_rule;
  size_t bucketsize_exception_rule;
  size_t max_namelabs;
};


struct bloomfilter {
  char *key; /* 16bytes long */

  size_t k;
  size_t size;
  uint8_t *field[2];

  time_t start;
  int interval;

  time_t *lastupdate[2];
  time_t timebase[2];

  struct psl *psl;

  lock_quick_t lock;

  int on;
  size_t threshold;
  uint64_t *validrtype;
  size_t ratelimit;
};


struct domain {
  uint8_t *name;
  size_t namelen;
  size_t count;
  uint64_t hash;
  time_t laststatechanged;
  int state;
  struct domain *next;
};

struct bf_blocklist {
  char *key; /* 16 bytes long */
  size_t bucketsize;
  struct domain **bd;
  struct timeval lifetime_threshold;
  time_t lastupdate;
};


struct rlcount {
  uint64_t count;
  struct timeval lastupdate;
};

struct bf_rlbucket {
  char *key[2];
  size_t bucketsize;
  struct rlcount *bucket[2];
};



struct psl *psl_create(size_t);
void psl_destroy(struct psl *);
struct psrule *psl_insert(struct psl *, char *);
uint8_t *psl_registrabledomain(struct psl *, uint8_t *,
         size_t, size_t *);

void bf_destroy(struct bloomfilter *);
struct bloomfilter *bf_create(size_t, size_t, struct ub_randstate *,
                              time_t, int, int, int);

void bloomfilter_learn(struct bloomfilter *, uint8_t *, size_t,
                        time_t);

int bloomfilter_check(struct bloomfilter *, struct query_info* qinfo,
                    time_t);

void log_requestlist(struct mesh_area*);

struct bf_blocklist *bf_blocklist_create(size_t, struct ub_randstate *);
void bf_blocklist_destroy(struct bf_blocklist *);
int bf_blocked_domain(struct mesh_area*, struct query_info* );
void domainlist_destroy(struct domain**, size_t);
int bf_ratelimit(struct mesh_area* ,struct query_info* );
struct bf_rlbucket *bf_rlbucket_create(size_t, struct ub_randstate *);
void bf_rlbucket_destroy(struct bf_rlbucket *);

#endif

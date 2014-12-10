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
#include "util/random.h"
#include "ldns/str2wire.h"
#include "ldns/wire2str.h"
#include "services/softblock.h"
#include "cache/dns.h"
#include "services/mesh.h"
#include "services/publicsuffix.h"
#include "daemon/daemon.h"
#include "daemon/worker.h"

uint64_t siphash24(const void *, unsigned long, const char[]);

uint32_t fnv1a(uint8_t *p, size_t len) {
  uint32_t h = 2166136261;
  while(len > 0) {
    h = h ^ (*p);
    h = h * 16777619;
    p ++;
    len --;
  }
  return h;
}

struct psl *psl_create(size_t bucketsize) {

  struct psl *psl;
  int i;

  psl = malloc(sizeof(struct psl));
  if(!psl) return NULL;
  
  psl->rule = malloc(bucketsize * sizeof(struct rule *));
  if (!psl->rule) {
    free(psl);
    return NULL;
  }
  
  psl->exception_rule = malloc(bucketsize * sizeof(struct rule *));
  if (!psl->exception_rule) {
    free(psl->rule);
    free(psl);
    return NULL;
  }
  psl->bucketsize_rule = bucketsize;
  psl->bucketsize_exception_rule = bucketsize;
  psl->max_namelabs = 0;
  for(i=0; i<psl->bucketsize_rule; i++)
    psl->rule[i] = NULL;
  for(i=0; i<psl->bucketsize_exception_rule; i++) 
    psl->exception_rule[i] = NULL;

  /*
   * XXX: reading PSL from publicsuffix.h
   * PSL should be specified in config file
   */

  int n;
  n = sizeof(publicsuffix) / sizeof(publicsuffix[0]);
  for(i = 0; i < n; i++) {
    if(!psl_insert(psl, publicsuffix[i]))
      log_err("can't read public suffix list rule: %s", publicsuffix[i]);
  }
  return psl;
}

void psrule_destroy(struct psrule *p) {
  free(p->name);
  free(p);
}

void psl_destroy(struct psl *psl) {

  int i;
  struct psrule *p, *q;
  
  for(i=0;i < psl->bucketsize_rule; i++) {
    p = psl->rule[i];
    while(p) {
      q = p->next; psrule_destroy(p); p = q;
    }
  }
  for(i=0;i< psl->bucketsize_exception_rule;i++) {
    p = psl->exception_rule[i];
    while(p) {
      q = p->next; psrule_destroy(p); p = q;
    }
  }
  free(psl->exception_rule);
  free(psl->rule);
  free(psl);

}

struct psrule *psl_search(struct psl *psl, uint8_t *name, size_t namelen,
                          int erule) {
  struct psrule *psr;
  struct psrule **rules;
  size_t bucketsize;

  uint32_t hash;

  rules = erule?psl->exception_rule:psl->rule;
  bucketsize = erule?psl->bucketsize_exception_rule:psl->bucketsize_rule;
  
  hash = fnv1a(name, namelen);
  int index = hash % bucketsize;
  psr = rules[index];

  while(psr) {
    if(hash != psr->hash) {
      psr= psr->next;
      continue;
    }
    if(query_dname_compare(psr->name, name) == 0) {
      break;
    }
    psr = psr->next;
  }

  return psr;
}

struct psrule *psl_insert(struct psl *psl, char *rule) {
  char *l, *p, *q;
  int exception_rule = 0;
  int wildcard = 0;
  
  uint8_t *dname;
  size_t dname_len;
  size_t namelabs = 0;

  l = rule;
  while(isspace(*l)) l++;       /* ignore leading space */
  if(!*l) return NULL;  /* skip empty line */
  if(l[0] == '/' && l[1] == '/')
    return NULL;        /* skip comments */
  
  q = strdup(l);
  p = q;
  
  /* delete trailing space */
  l = p;
  while(*l && !isspace(*l)) l++;
  *l = 0;

  /* is exception_rule? */
  if(p[0] == '!') {
    if(p[1] == '\0') {
      free(q);
      return NULL;
    }
    p++; /* skip '!' */
    exception_rule = 1;
  }

  /* is this wildcard rule? */
  if(p[0] == '*' && p[1] == 0) {
    /* rule == '*' */
    p = ".";
    wildcard = 1;
  } else if (p[0] == '*' && p[1] == '.') {
    wildcard = 1;
    if(p[2] == 0) {
      /* rule == "*." */
      p = ".";
    } else {
      /* rule == "*.anything" */
      p += 2; /* skip "*." */
    }
  }

  dname = sldns_str2wire_dname(p, &dname_len);
  free(q);
  if(!dname) {
    return NULL;
  }
  query_dname_tolower(dname);
  namelabs = dname_count_labels(dname);

  struct psrule *psr;

  psr = psl_search(psl, dname, dname_len, exception_rule);

  struct psrule *newrule;

  if(!psr) {
    size_t bucketsize;
    uint32_t hash;
    int index;
    struct psrule **rules;
    rules = exception_rule?psl->exception_rule:psl->rule;
    bucketsize = exception_rule?psl->bucketsize_exception_rule:psl->bucketsize_rule;
    hash = fnv1a(dname, dname_len);
    index = hash % bucketsize;

    newrule = malloc(sizeof(struct psrule));
    if(!newrule) { free(dname); return NULL; }
    newrule->name = dname;
    newrule->namelabs = namelabs;
    newrule->namelen = dname_len;
    newrule->next = rules[index];
    rules[index] = newrule;
    newrule->wildcard = wildcard?1:0;
    newrule->thisname = wildcard?0:1;
    newrule->hash = hash;
    if(psl->max_namelabs < namelabs) psl->max_namelabs = namelabs;
  } else {
    newrule = psr;
    newrule->wildcard = wildcard?1:newrule->wildcard;
    newrule->thisname = wildcard?newrule->thisname:1;
  }

  return newrule;
}

uint8_t *psl_registrabledomain(struct psl *psl, uint8_t *name, size_t namelen,
			 size_t *suffixlen) {

  int namelabs = dname_count_labels(name);
  uint8_t *b_name, *prev_name, *prev_prev_name, *match_name;
  size_t b_namelen, b_namelabs, prev_namelen, prev_prev_namelen;
  struct psrule *psr, *epsr;

  while(namelabs > psl->max_namelabs + 2) {
    dname_remove_label(&name, &namelen);
    namelabs --;
  }

  /* reserve name, namelen, namelabs */
  b_name = name; b_namelen = namelen;
  b_namelabs = namelabs;

  /* search exception rule first */
  prev_name = NULL;
  prev_prev_name = NULL;
  match_name = NULL;
  prev_namelen = -1;
  prev_prev_namelen = -1;
  while(namelabs > 0) {
    psr = psl_search(psl, name, namelen, 1);
    if(psr) {
      if(psr->wildcard && prev_name) {
	match_name = prev_name;
	break;
      }
      if(psr->thisname) {
	match_name = name;
	break;
      }
    }

    prev_prev_name = prev_name;
    prev_name = name;       
    prev_prev_namelen = namelen;
    prev_namelen = namelen;

    dname_remove_label(&name, &namelen);
    namelabs --;
  }

  if(match_name) {
    *suffixlen = namelen;
    return match_name;
  }

  prev_name = NULL;
  prev_prev_name = NULL;
  match_name = NULL;
  prev_namelen = -1;
  prev_prev_namelen = -1;
  namelabs = b_namelabs;
  name = b_name;
  namelen = b_namelen;

  while(namelabs > 0) {
    psr = psl_search(psl, name, namelen, 0);
    if(psr) {

      if(psr->wildcard && prev_name) {
	match_name = prev_prev_name;
	break;
      }
      if (psr->thisname) {
	match_name = prev_name;
	break;
      }
    }
    prev_prev_name = prev_name;
    prev_name = name;
       
    prev_prev_namelen = namelen;
    prev_namelen = namelen;
    dname_remove_label(&name, &namelen);
    namelabs --;
  }
  if(match_name) {
    *suffixlen = namelen;
    return match_name;
  }
  return NULL;
}

struct bloomfilter *bf_create(size_t size, size_t k, struct ub_randstate *rnd,
			      time_t now, int interval) {

  struct bloomfilter *bf;
  unsigned int i, j;

  bf = malloc(sizeof(struct bloomfilter));
  if(!bf)return NULL;
  if(size > 0) {
        log_info("softblock enabled size=%zu", size);
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
  bf->psl = NULL;

  bf->size = size;
  bf->k = k;
  lock_quick_init(&bf->lock);

  bf->psl = psl_create(65536);
  if(!bf->psl) {
    bf_destroy(bf);
    return NULL;
  }

  bf->key = malloc(16);
  if(!bf->key) {
    bf_destroy(bf);
    return NULL;
  }
  for(i=0;i<16;i++) {
    bf->key[i] = ub_random_max(rnd, 256);
  }

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

  return bf;
}

void bf_destroy(struct bloomfilter *bf) {
  if(bf->on) {
    if(bf->key) free(bf->key);
    if(bf->field[0]) free(bf->field[0]);
    if(bf->lastupdate[0]) free(bf->lastupdate[0]);
    if(bf->psl) psl_destroy(bf->psl);
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

struct suffix {
  uint8_t *name;
  size_t namelen;
  size_t namelabs;
  size_t count;
};




void log_requestlist(struct mesh_area* mesh) {
  char buf[257];
  uint8_t *qname, *d;
  size_t qname_len, suffix_len;
  struct psl *psl;
  struct mesh_state *m;

  if(!mesh) return;

  psl = mesh->env->worker->daemon->bf_softblock->psl;

  RBTREE_FOR(m, struct mesh_state*, &mesh->all) {
    qname_len = m->s.qinfo.qname_len;
    qname = malloc(qname_len);
    memcpy(qname, m->s.qinfo.qname, qname_len);
    query_dname_tolower(qname);

    if(qname) {
      if(m->reply_list) {
	d = psl_registrabledomain(psl, qname, qname_len, &suffix_len);
      }
      free(qname);
    }

  }
}

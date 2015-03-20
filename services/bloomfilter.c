#include "config.h"
#include "services/mesh.h"
#include "util/data/dname.h"
#include "util/log.h"
#include "util/locks.h"
#include "util/random.h"
#include "ldns/str2wire.h"
#include "ldns/wire2str.h"
#include "services/bloomfilter.h"
#include "cache/dns.h"
#include "services/publicsuffix.h"
#include "services/bloomfilter_validrtype.h"
#include "daemon/daemon.h"
#include "daemon/worker.h"

#include <ctype.h>
#include <string.h>

uint64_t siphash24(const void *, unsigned long, const char[]);

uint32_t fnv1a(uint8_t *p, size_t len) {
  uint32_t h = 2166136261ULL;
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
  unsigned int i, n;

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

  unsigned int i;
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
  int index;

  rules = erule?psl->exception_rule:psl->rule;
  bucketsize = erule?psl->bucketsize_exception_rule:psl->bucketsize_rule;
  
  hash = fnv1a(name, namelen);
  index = hash % bucketsize;
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
  struct psrule *psr;
  struct psrule *newrule;


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

  psr = psl_search(psl, dname, dname_len, exception_rule);

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

  unsigned int namelabs = dname_count_labels(name);
  uint8_t *b_name, *prev_name, *prev_prev_name, *match_name;
  int b_namelen, b_namelabs, prev_namelen, prev_prev_namelen, match_namelen;
  struct psrule *psr;

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
  match_namelen = -1;
  prev_namelen = -1;
  prev_prev_namelen = -1;
  while(namelabs > 0) {
    psr = psl_search(psl, name, namelen, 1);
    if(psr) {
      if(psr->wildcard && prev_name) {
	match_name = prev_name;
	match_namelen = prev_namelen;
	break;
      }
      if(psr->thisname) {
	match_name = name;
	match_namelen = namelen;
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
  match_namelen = -1;
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
	match_namelen = prev_prev_namelen;
	break;
      }
      if (psr->thisname) {
	match_name = prev_name;
	match_namelen = prev_namelen;
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
    *suffixlen = match_namelen;
    return match_name;
  }
  return NULL;
}

struct bloomfilter *bf_create(size_t size, size_t k, struct ub_randstate *rnd,
			      time_t now, int interval, int threshold) {

  struct bloomfilter *bf;
  unsigned int i;

  bf = malloc(sizeof(struct bloomfilter));
  if(!bf)return NULL;
  if(size > 0) {
        log_info("bloomfilter enabled size=%zu", size);
	bf->on = 1;
  } else {
	bf->on = 0;
        log_info("bloomfilter disabled");
        return bf;
  }

  /* round up to multiple of BF_BLOCKSIZE */
  size = size + BF_BLOCKSIZE - size % BF_BLOCKSIZE;

  bf->key = NULL;
  bf->field[0] = NULL;
  bf->lastupdate[0] = NULL;
  bf->psl = NULL;
  bf->threshold = threshold;
  bf->size = size;
  bf->k = k;
  lock_quick_init(&bf->lock);

  bf->psl = psl_create(65536);
  if(!bf->psl) {
    bf_destroy(bf);
    return NULL;
  }

  bf->key = malloc(k * SIPHASH_KEYSIZE);
  if(!bf->key) {
    bf_destroy(bf);
    return NULL;
  }
  for(i=0;i<k*SIPHASH_KEYSIZE;i++) {
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
  return siphash24(name, namelen, bf->key+(k*SIPHASH_KEYSIZE));
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
    if(!match[0] && !match[1])break;
    h = bf_hash(bf, i, lname, namelen) % ((uint64_t)bf->size << 3);
    byteindex = h >> 3;
    luindex = byteindex / BF_BLOCKSIZE;

    for(index = 0; index < 2; index++) {
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
  return match[0] || match[1];
}

void bloomfilter_learn(struct bloomfilter *bf, uint8_t *name, size_t namelen,
			time_t now)
{
  if(bf->on) {
     bf_set(bf, name, namelen, now);
  };
}


int rtypecmp(const void *p, const void *q) {
  return *((uint16_t *)p) - *((uint16_t *)q);
}

int allowed_qtype_qclass(struct query_info *q) {

  if(q->qclass == 1 &&
     bsearch(&q->qtype, validrtype, sizeof(validrtype)/sizeof(validrtype[0]),
	     sizeof(validrtype[0]), rtypecmp)) {
    return 1;
  }

  return 0;

}

int bloomfilter_check(struct bloomfilter *bf, struct query_info* qinfo,
		    time_t now)
{
  if(bf->on) {
     return bf_check(bf, qinfo->qname, qinfo->qname_len, now)
       && allowed_qtype_qclass(qinfo);
  }
  return 1;
}

void bf_blocklist_destroy(struct bf_blocklist *bl) {
  unsigned int i;
  struct domain *p, *q;
  if(!bl) return;
  if(bl->key) free(bl->key);
  if(bl->bd) domainlist_destroy(bl->bd, bl->bucketsize); 
  free(bl);
  log_info("bf_blocklist deleted");
}

struct bf_blocklist *bf_blocklist_create(size_t bucketsize,
					 struct ub_randstate *rnd) {

  struct bf_blocklist *bl;
  unsigned int i;
  log_info("bf_blocklist created");
  bl = malloc(sizeof(struct bf_blocklist));
  if(!bl) return NULL;
  bl->key = NULL;
  bl->bd = NULL;
  bl->bucketsize = bucketsize;
  bl->lastupdate = 0;

  bl->key = malloc(SIPHASH_KEYSIZE);
  if(!bl->key) {
    bf_blocklist_destroy(bl);
    return NULL;
  }
  for(i=0;i<SIPHASH_KEYSIZE;i++) {
    bl->key[i] = ub_random_max(rnd, 256);
  }

  bl->bd = malloc(bucketsize * sizeof(struct domain *));
  if(!bl->bd) {
    bf_blocklist_destroy(bl);
    return NULL;
  }
  for(i=0;i<bucketsize;i++) {
    bl->bd[i] = NULL;
  }

  return bl;
}

void domain_destroy(struct domain *d) {
  if(!d)return;
  if(d->name)free(d->name);
  free(d);
}

struct domain *domain_create(uint8_t *name, size_t namelen) {
  struct domain *d;

  d = malloc(sizeof(struct domain));
  if(!d) return NULL;
  d->name = NULL;
  d->count = 0;

  d->name = malloc(namelen);
  if(!d->name) {
    domain_destroy(d);
    return NULL;
  }
  memcpy(d->name, name, namelen);
  d->namelen = namelen;
  return d;
}

struct domain *domain_search(struct domain **d, size_t bucketsize, char *key,
			     uint8_t *name, size_t namelen, int insert) {

  int index;
  uint64_t h;
  struct domain *p;
  h = siphash24(name, namelen, key);
  index = h % bucketsize;
  p = d[index];
  while(p) {
    if(p->hash == h && query_dname_compare(p->name, name)==0)break;
    p = p->next;
  }
  
  if(p || !insert) return p;

  p = domain_create(name, namelen);
  if(!p) return NULL;
  p->hash = h;
  p->next = d[index];
  d[index] = p;
  return p;
}

void domainlist_destroy(struct domain **d, size_t bucketsize) {
  unsigned int i;
  struct domain *p;

  if(!d)return;

  for(i=0;i<bucketsize;i++) {
    while(d[i]) {
      p = d[i]->next;
      domain_destroy(d[i]);
      d[i] = p;
    }
  }
  free(d);

}

void bf_blocklist_cleanup(struct domain **domainlist, size_t bucketsize) {

  unsigned int i;
  struct domain *p, *q;

  /* clean up blockeddomain whose count < 10 */
  for(i=0; i<bucketsize; i++) {
    p = domainlist[i];
    q = NULL;
    while(p) {
      if(p->count < 10) {
	if(q) {
	  q->next = p->next;
	} else {
	  domainlist[i] = p->next;
	}
	domain_destroy(p);
      }
      q = p;
      p = p -> next;
    }
  }

}

uint8_t *psl_tld(uint8_t *name, size_t namelen) {
  size_t namelabs;
  namelabs = dname_count_labels(name);
  if(namelabs < 1)return NULL;
  while(namelabs > 1) {
    dname_remove_label(&name, &namelen);
    namelabs --;
  }
  return name;
}

void log_requestlist(struct mesh_area* mesh) {
  char buf[257], *key;
  uint8_t *qname, *d;
  size_t qname_len, suffix_len;
  struct psl *psl;
  struct mesh_state *m;
  unsigned int i, j, bucketsize, allcount;
  time_t now;

  struct domain *p, *q, **domainlist;
  struct bf_blocklist *blocklist;
  struct bloomfilter *bloomfilter;

  if(!mesh) return;

  now = mesh->env->now_tv->tv_sec;
  blocklist = mesh->env->worker->bf_blocklist;
  bloomfilter = mesh->env->worker->daemon->bloomfilter;

  if(bloomfilter->threshold < 1)return;
  if(now - blocklist->lastupdate < BF_BLOCKLIST_UPDATE_INTERVAL)return;
  blocklist->lastupdate = now;

  psl = mesh->env->worker->daemon->bloomfilter->psl;
  key = blocklist->key;

  bucketsize = (mesh->all.count+1) * 8;

  domainlist = malloc(sizeof(struct domain *) * bucketsize);
  if(!domainlist) return;
  for(i=0;i<bucketsize;i++) domainlist[i] = NULL;

  allcount = 0;
  RBTREE_FOR(m, struct mesh_state*, &mesh->all) {
    if(m->reply_list) {
      struct mesh_reply *r = m->reply_list;
      while( r && r->next) {
	r = r->next;
      }
#ifndef S_SPLINT_S
      if ( now - r->start_time.tv_sec >= 2 ) {
	qname_len = m->s.qinfo.qname_len;
	qname = malloc(qname_len);
	if(qname) {
	  memcpy(qname, m->s.qinfo.qname, qname_len);
	  query_dname_tolower(qname);
	  d = psl_registrabledomain(psl, qname, qname_len, &suffix_len);
	  if(d) {
	    p = domain_search(domainlist, bucketsize, key, d, suffix_len, 1);
	    if(p) {
	      p->count++;
	    }
	  }
	  free(qname);
	}
      }
#endif
    }
  }


  for(i=0;i < bucketsize; i++) {
    p = domainlist[i];
    while(p) {
      q = domain_search(blocklist->bd, blocklist->bucketsize, key,
			p->name, p->namelen, 1);
      if(q) {
	if(q->count == 0) { /* newly created */
	  q->laststatechanged = now;
	  q->state = 0;
	  q->count = p->count;
	} else {
	  q->count = p->count;
	}
      }
      p = p->next;
    }
  }

  int c = 0;
  for(i=0; i<blocklist->bucketsize; i++) {
    struct domain *s = NULL;
    p = blocklist->bd[i];
    while(p) {

      q = domain_search(domainlist, bucketsize, key, p->name, p->namelen, 0);
      if(!q) p->count = 0;

      if((p->state == 0 && p->count < bloomfilter->threshold)
	 || now - p->laststatechanged > 90 + ub_random_max(mesh->env->worker->rndstate, 180)) {
	if(p->state != 0) {
	  dname_str(p->name, buf);
	  log_info("reqlist protection: deleted filtered domain: %s", buf);
	}
	if(s) {
	  s->next = p->next;
	} else {
	  blocklist->bd[i] = p->next;
	}
	q = p->next;
	domain_destroy(p);
	p = q;
      } else {
	if(p->state == 0 && p->count >= bloomfilter->threshold) {
	  dname_str(p->name, buf);
	  log_info("reqlist protection: added bloomfiltered domain: %s numreq=%zu", buf, p->count);
	  p->state = 1;
	  p->laststatechanged = now;
	}
	if(p->state == 1 && p->count >= bloomfilter->threshold * 2
		 && now - p->laststatechanged > 60) {
	  dname_str(p->name, buf);
	  log_info("reqlist protection: added all-filtered domain: %s numreq=%zu", buf, p->count);
	  p->state = 2;
	  p->laststatechanged = now;
	}
	s = p;
	p = p -> next;
      }

    }
  }
  domainlist_destroy(domainlist, bucketsize);

}

int bf_blocked_domain(struct mesh_area* mesh, struct query_info* qinfo) {

  size_t namelabs;
  uint8_t *lname, *lname_backup;
  struct domain *p;
  size_t namelen; 
  int result = 0;
  struct bf_blocklist *blocklist;
  struct bloomfilter *bf;
  time_t now;

  if(!mesh || !qinfo)return 0;

  blocklist = mesh->env->worker->bf_blocklist;
  bf = mesh->env->worker->daemon->bloomfilter;
  now = mesh->env->now_tv->tv_sec;

  if(bf->threshold < 1)return 0;

  namelen = qinfo->qname_len;
  lname = malloc(namelen);
  lname_backup = lname;
  if(!lname) return 0;
  memcpy(lname, qinfo->qname, qinfo->qname_len);
  query_dname_tolower(lname);
  namelabs = dname_count_labels(lname);

  if(namelabs < 1) {
    return 0;
  }

  do {
    p = domain_search(blocklist->bd,
		      blocklist->bucketsize,
		      blocklist->key,
		      lname, namelen, 0);
    if(p) {
      switch(p->state) {
      case 0:
	result = 0;
	break;
      case 1:
	if(bloomfilter_check(bf, qinfo, now)) {
	  result = 0;
	} else {
	  result = 1;
	}
	break;
      case 2:
	result = 1;
	break;
      }
      break;
    }
    dname_remove_label(&lname, &namelen);
    namelabs --;
  } while(namelabs > 1);
  
  free(lname_backup);

  return result;

}

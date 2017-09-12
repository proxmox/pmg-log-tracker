/*

 (C) 2007-2017 Proxmox Server Solutions GmbH, All Rights Reserved

 Proxmox Mail Tracker

 See http://www.proxmox.com for more information

*/

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <glib.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <zlib.h>
#include <fnmatch.h>

/*
  We assume the syslog files belong to one host, i.e. we do not 
  consider the hostname at all
*/

/*
  REGEX: we do not use posix regular expressions (libc implementation
  is too slow). fnmatch() is also slow.
  Future versions may use our own implementation of a DFA. But currently we
  just use strstr (no regex support at all)
*/

//#define STRMATCH(pattern, string) (fnmatch (pattern, string, FNM_CASEFOLD) == 0)
#define STRMATCH(pattern, string) (strcasestr (string, pattern) != NULL)


//#define EPOOL_BLOCK_SIZE 512
//#define EPOOL_MAX_SIZE 128
#define EPOOL_BLOCK_SIZE 2048
#define EPOOL_MAX_SIZE 128
#define MAX_LOGFILES 31
//#define EPOOL_DEBUG 
//#define DEBUG

typedef struct _SList SList;
struct _SList {
  gpointer data;
  SList *next;
};

typedef struct _NQList NQList;
struct _NQList {
  char *from;
  char *to;
  char dstatus;
  time_t ltime;
  NQList *next;
};

typedef struct _TOList TOList;
struct _TOList {
  char *to;
  char *relay;
  char dstatus;
  time_t ltime;
  TOList *next;
};

#ifdef DEBUG
  GHashTable *smtpd_debug_alloc;
  GHashTable *qmgr_debug_alloc;
  GHashTable *filter_debug_alloc;
  GHashTable *smtpd_debug_free;
  GHashTable *qmgr_debug_free;
  GHashTable *filter_debug_free;
#endif

// EPool: Entry related memory pools

GMemChunk *mem_chunk_epool;

#ifdef EPOOL_DEBUG
int ep_allocated;
int ep_maxalloc;
#endif

typedef struct _EPool EPool;
struct _EPool {
  SList *blocks;     // allocated usiing mem_chunk_epool
  SList *mblocks;    // allocated use g_malloc
  int cpos;
#ifdef EPOOL_DEBUG
  int allocated;
#endif
};

typedef struct {
  EPool ep;
  GHashTable *smtpd_h;
  GHashTable *qmgr_h;
  GHashTable *filter_h;
  //GHashTable *track_h;
  gzFile *stream[MAX_LOGFILES];
  char *from;
  char *to;
  time_t year[MAX_LOGFILES];
  time_t start;
  time_t end;
  time_t ctime;
  char *server;
  char *msgid;
  char *qid;
  char *strmatch;
  unsigned long limit;
  unsigned long count;
  int verbose;
  unsigned int exclude_greylist:1;
  unsigned int exclude_ndrs:1;
} LParser;

typedef struct _SEntry SEntry;
typedef struct _QEntry QEntry;
typedef struct _FEntry FEntry;

typedef struct _LogEntry LogEntry;
typedef struct _LogList LogList;

struct _LogEntry {
  const char *text;
  LogEntry *next;
};

struct _LogList {
  LogEntry *log;
  LogEntry *logs_last; // pointer to last log (speedup add log)
};
 
// SEntry: Store SMTPD related logs

struct _SEntry {

  EPool ep;
  LogList loglist;

  int pid;

  SList *refs;

  NQList *nqlist;

  char *connect;

  //unsigned int external:1;        // not from local host
  unsigned int disconnect:1;
  unsigned int strmatch:1;

};

// QEntry: Store Queue (qmgr, smtp, lmtp) related logs

struct _QEntry {

  EPool ep;
  LogList loglist;

  char *qid;

  SEntry *smtpd;
  FEntry *filter;

  TOList *tolist;

  unsigned int size;
  char *from;
  char *client;
  char *msgid;

  unsigned int cleanup:1;
  unsigned int removed:1;
  unsigned int filtered:1; // set when passed via lmtp to filter
  unsigned int strmatch:1;
};

// FEntry: Store filter (proxprox) related logs
 
struct _FEntry {

  EPool ep;
  LogList loglist;

  char *logid; // proxprox log id

  TOList *tolist;

  float ptime;

  unsigned int finished:1;
  unsigned int strmatch:1;
};

// Prototypes
void      debug_error (char *msg, const char *line);
SList    *slist_remove (SList *list, gpointer data);

EPool    *epool_init (EPool *ep);
void      epool_free (EPool *ep);
gpointer  epool_alloc (EPool *ep, int size);
char     *epool_strndup (EPool *ep, const char *s, int len);
char     *epool_strndup0 (EPool *ep, const char *s, int len);
char     *epool_strdup (EPool *ep, const char *s);

void      loglist_print (LogList *loglist);
void      loglist_add (EPool *ep, LogList *loglist, const char *text, int len);

SEntry   *sentry_new (int pid);
SEntry   *sentry_get (LParser *parser, int pid);
void      sentry_ref_add (SEntry *sentry, QEntry *qentry);
int       sentry_ref_del (SEntry *sentry, QEntry *qentry);
void      sentry_ref_finalize (LParser *parser, SEntry *sentry);
int       sentry_ref_rem_unneeded (LParser *parser, SEntry *sentry);
void      sentry_nqlist_add (SEntry *sentry, time_t ltime, const char *from, int from_len, 
			     const char *to, int to_len, char dstatus);
void      sentry_print (LParser *parser, SEntry *sentry);
void      sentry_set_connect (SEntry *sentry, const char *connect, int len);
void      sentry_free_noremove (SEntry *sentry);
void      sentry_free (LParser *parser, SEntry *sentry);
void      sentry_cleanup_hash (gpointer key, gpointer value, gpointer user_data);


QEntry   *qentry_new (const char *qid);
QEntry   *qentry_get (LParser *parser, const char *qid); 
void      qentry_tolist_add (QEntry *qentry, time_t ltime, char dstatus, const char *to, 
			     int to_len, const char *relay, int relay_len);
void      qentry_set_from (QEntry *qentry, const char *from, int len);
void      qentry_set_msgid (QEntry *qentry, const char *msgid, int len);
void      qentry_set_client (QEntry *qentry, const char *client, int len);
void      qentry_print (LParser *parser, QEntry *qentry);
void      qentry_finalize (LParser *parser, QEntry *qentry);
void      qentry_free_noremove (LParser *parser, QEntry *qentry);
void      qentry_free (LParser *parser, QEntry *qentry);
void      qentry_cleanup_hash (gpointer key, gpointer value, gpointer user_data);


FEntry   *fentry_new (const char *logid);
FEntry   *fentry_get (LParser *parser, const char *logid);
void      fentry_tolist_add (FEntry *fentry, char dstatus, const char *to,
			     int to_len, const char *qid, int qid_len);
void      fentry_free_noremove (LParser *parser, FEntry *fentry);
void      fentry_free (LParser *parser, FEntry *fentry);
void      fentry_cleanup_hash (gpointer key, gpointer value, gpointer user_data);

LParser  *parser_new ();
void      parser_free (LParser *parser);

//char     *parser_track (LParser *parser, const char *qid, gboolean insert);

// Implementations

//#define LOGPATH "./log/"
#define LOGPATH "/var/log/"
//#define LOGPATH "/var/log5/"

static const char *logfiles[] = {
  LOGPATH "syslog",
  LOGPATH "syslog.1",
  LOGPATH "syslog.2.gz",
  LOGPATH "syslog.3.gz",
  LOGPATH "syslog.4.gz",
  LOGPATH "syslog.5.gz",
  LOGPATH "syslog.6.gz",
  LOGPATH "syslog.7.gz",
  LOGPATH "syslog.8.gz",
  LOGPATH "syslog.9.gz",
  LOGPATH "syslog.10.gz",
  LOGPATH "syslog.11.gz",
  LOGPATH "syslog.12.gz",
  LOGPATH "syslog.13.gz",
  LOGPATH "syslog.14.gz",
  LOGPATH "syslog.15.gz",
  LOGPATH "syslog.16.gz",
  LOGPATH "syslog.17.gz",
  LOGPATH "syslog.18.gz",
  LOGPATH "syslog.19.gz",
  LOGPATH "syslog.20.gz",
  LOGPATH "syslog.21.gz",
  LOGPATH "syslog.22.gz",
  LOGPATH "syslog.23.gz",
  LOGPATH "syslog.24.gz",
  LOGPATH "syslog.25.gz",
  LOGPATH "syslog.26.gz",
  LOGPATH "syslog.27.gz",
  LOGPATH "syslog.28.gz",
  LOGPATH "syslog.29.gz",
  LOGPATH "syslog.30.gz",
  LOGPATH "syslog.31.gz",
};

void
debug_error (char *msg, const char *line)
{
#ifdef DEBUG
  fprintf (stderr, "ERROR: %s\n", msg); 
  if (line) fprintf (stderr, "LINE: %s\n", line); 

  G_BREAKPOINT();

  exit (-1);
#endif
}

SList *
slist_remove (SList *list, gpointer data)
{
  SList *p = NULL;
  SList *l = list;

  while (l) {
    if (l->data == data) {
      if (p)
	p->next = l->next;
      if (list == l)
	list = list->next;

      l->next = NULL;

      break;
    }

    p = l;
    l = l->next;
  }

  return list;
}

EPool *
epool_init (EPool *ep)
{
  gpointer data;
  SList *blocks;

  data = g_mem_chunk_alloc0 (mem_chunk_epool);
  blocks = (SList *)data;

#ifdef EPOOL_DEBUG
  ep->allocated += EPOOL_BLOCK_SIZE;
  ep_allocated += EPOOL_BLOCK_SIZE;
  ep_maxalloc = (ep_allocated > ep_maxalloc) ? ep_allocated : ep_maxalloc;
#endif


  blocks->data = data;
  blocks->next = NULL;

  ep->blocks = blocks;
  ep->cpos = sizeof (SList);

  return ep;
}

void
epool_free (EPool *ep) 
{
  SList *l;
  gpointer data;

#ifdef EPOOL_DEBUG
  ep_allocated -= ep->allocated;
  printf ("MEM: %d\n", ep_allocated);
#endif

#ifdef DEBUG
  return;
#endif
  
  l = ep->mblocks;
  while (l) {
    data = l->data;
    l = l->next;
    g_free (data);
  }

  l = ep->blocks;
  while (l) {
    data = l->data;
    l = l->next;
    g_mem_chunk_free (mem_chunk_epool, data);
  }
}

gpointer
epool_alloc (EPool *ep, int size)
{
  int rs = (size + 3) & ~3;
  int space = EPOOL_BLOCK_SIZE - sizeof (SList) - ep->cpos;
  gpointer data;

  if (size > EPOOL_MAX_SIZE) {
    SList *blocks;
    if (space >= sizeof (SList)) {
      blocks = ep->blocks->data + ep->cpos;
      ep->cpos += sizeof (SList);
    } else {
      blocks = (SList *)epool_alloc (ep, sizeof (SList));
    }

    data = g_malloc (size);
#ifdef EPOOL_DEBUG
    ep->allocated += size;
    ep_allocated += size;
    ep_maxalloc = (ep_allocated > ep_maxalloc) ? ep_allocated : ep_maxalloc;
#endif
    blocks->data = data;
    blocks->next = ep->mblocks;

    ep->mblocks = blocks;
    
    return data;

  } else if (space >= rs) {
    data = ep->blocks->data + ep->cpos;
    ep->cpos += rs;

    return data;

  } else {
    SList *blocks = ep->blocks->data + ep->cpos;

    data = g_mem_chunk_alloc0 (mem_chunk_epool);
    blocks->data = data;
    blocks->next = ep->blocks;

    ep->blocks = blocks;
    ep->cpos = rs;

#ifdef EPOOL_DEBUG
    ep->allocated += EPOOL_BLOCK_SIZE;
    ep_allocated += EPOOL_BLOCK_SIZE;
    ep_maxalloc = (ep_allocated > ep_maxalloc) ? ep_allocated : ep_maxalloc;
#endif

    return data;
  } 
}

char *
epool_strndup (EPool *ep, const char *s, int len) 
{
  int l = len + 1;
  char *res = epool_alloc (ep, l);
  strncpy (res, s, l);
  return res;
}

char *
epool_strndup0 (EPool *ep, const char *s, int len) 
{
  char *res = epool_alloc (ep, len + 1);
  strncpy (res, s, len);
  res[len] = 0;

  return res;
}

char *
epool_strdup (EPool *ep, const char *s) 
{
  int l = strlen (s) + 1;
  char *res = epool_alloc (ep, l);
  strncpy (res, s, l);
  return res;
}

void
loglist_print (LogList *loglist)
{
  LogEntry *log = loglist->log;
  while (log) {
    printf ("%s", log->text);
    log = log->next;
  }
}


void
loglist_add (EPool *ep, LogList *loglist, const char *text, int len)
{
  LogEntry *log;

#ifdef DEBUG
  if (len != strlen (text)) {
    debug_error ("string with wrong len", NULL);    
  }
#endif
  if (text[len] != 0) {
    debug_error ("string is not null terminated", NULL);    
    return;
  }

  log = epool_alloc (ep, sizeof (LogEntry));

  log->text = epool_strndup (ep, text, len);
  log->next = NULL;

  if (loglist->logs_last) {
    loglist->logs_last->next = log;
    loglist->logs_last = log;
  } else {
    loglist->log = log;
    loglist->logs_last = log;
  }

  return;
}

SEntry*
sentry_new (int pid)
{
  SEntry *sentry;
  SList *blocks;
  int cpos;

  sentry = (SEntry *)g_mem_chunk_alloc0 (mem_chunk_epool);
  sentry->pid = pid;

#ifdef EPOOL_DEBUG
  sentry->ep.allocated += EPOOL_BLOCK_SIZE;
  ep_allocated += EPOOL_BLOCK_SIZE;
  ep_maxalloc = (ep_allocated > ep_maxalloc) ? ep_allocated : ep_maxalloc;
#endif

#ifdef DEBUG
  {
    SEntry *se;
    if ((se = g_hash_table_lookup (smtpd_debug_alloc, sentry))) {
      debug_error ("SEntry already alloced", NULL);
    } else {
      g_hash_table_insert (smtpd_debug_alloc, sentry, sentry);
    }
  }
#endif

  cpos = sizeof (SEntry);

  blocks = (SList *)((char *)sentry + cpos);

  cpos += sizeof (SList);
  
  blocks->data = sentry;
  blocks->next = NULL;

  sentry->ep.blocks = blocks;
  sentry->ep.cpos = cpos;

  return sentry;
}

SEntry *
sentry_get (LParser *parser, int pid) 
{
  SEntry *sentry;

  if ((sentry = g_hash_table_lookup (parser->smtpd_h, &pid))) {
    return sentry;
  } else {

    if ((sentry = sentry_new (pid))) {
      g_hash_table_insert (parser->smtpd_h, &sentry->pid, sentry);
    }

    return sentry;
  }
}

void
sentry_ref_add (SEntry *sentry, QEntry *qentry) 
{
  SList *l;

  if (qentry->smtpd) {
    if (qentry->smtpd != sentry) {
      debug_error ("qentry ref already set", NULL);    
    }
    return;
  }

  l = sentry->refs;
  while (l) {
    if (l->data == qentry) return;
    l = l->next;
  }

  l = epool_alloc (&sentry->ep, sizeof (SList));

  qentry->smtpd = sentry;

  l->data = qentry;
  l->next = sentry->refs;

  sentry->refs = l;
}

int
sentry_ref_del (SEntry *sentry, QEntry *qentry) 
{
  SList *l = sentry->refs;
  int count = 0;

  if (!qentry->smtpd) {
    debug_error ("qentry does not hav a qentry ref", NULL);    
    return 0;
  }

  l = sentry->refs;

  while (l) {
    QEntry *qe = (QEntry *)l->data;
    if (qe == qentry) {
      l->data = NULL;
    } else {
      if (qe && qe->cleanup) count++;
    }
    l = l->next;
  }

  return count;
}

void
sentry_ref_finalize (LParser *parser, SEntry *sentry) 
{
  SList *l = sentry->refs;

  int count = 0;

  while (l) {
    SList *cl = l;
    QEntry *qe = l->data;

    l = l->next;

    if (!qe) continue;

    count++;

    if (!qe->removed) continue;

    FEntry *fe = qe->filter;

    if (fe && !fe->finished) continue;

    count--;

    qentry_print (parser, qe);

    cl->data = NULL;
    qe->smtpd = NULL;

    qentry_free (parser, qe);
 
    if (fe) fentry_free (parser, fe);
   
  }

  if (!count) sentry_free_noremove (sentry);
}

int
sentry_ref_rem_unneeded (LParser *parser, SEntry *sentry) 
{
  SList *l = sentry->refs;
  int count = 0;

  while (l) {
    QEntry *qe = (QEntry *)l->data;

    if (qe) {
      if (!qe->cleanup) {
	qe->smtpd = NULL;
	qentry_free (parser, qe);
	l->data = NULL;
      } else {
	count++;
      }
    }

    l = l->next;
  }

  return count;
}

void
sentry_nqlist_add (SEntry *sentry, time_t ltime, const char *from, int from_len, 
		   const char *to, int to_len, char dstatus)
{
  NQList *nq = (NQList *)epool_alloc (&sentry->ep, sizeof (NQList));

  nq->from = epool_strndup0 (&sentry->ep, from, from_len);
  nq->to = epool_strndup0 (&sentry->ep, to, to_len);
  nq->dstatus = dstatus;

  nq->next = sentry->nqlist;
  nq->ltime = ltime;
  sentry->nqlist = nq;
}

void
sentry_print (LParser *parser, SEntry *sentry)
{
  NQList *nq;

  if (parser->msgid || parser->qid) return;

  if (parser->server) {
    if (!sentry->connect) return;
    if (!strcasestr (sentry->connect, parser->server)) return;
  }

  if (parser->from || parser->to || 
      parser->exclude_greylist || parser->exclude_ndrs) {
    nq = sentry->nqlist;
    int found = 0;
    while (nq) {
      if (parser->from) {
	if (!*(parser->from)) {
	  if (*(nq->from)) nq->dstatus = 0;
	} else if (!STRMATCH(parser->from, nq->from)) {
	  nq->dstatus = 0;
	}
      }

      if (parser->exclude_greylist && nq->dstatus == 'G') nq->dstatus = 0;

      if (parser->exclude_ndrs && nq->from && !*nq->from) nq->dstatus = 0;

      if (parser->to && nq->to && !STRMATCH(parser->to, nq->to)) {
	nq->dstatus = 0;
      }

      if (nq->dstatus != 0) found = 1;

      nq = nq->next;
    }
    if (!found) return;
  }

  if (parser->strmatch && !sentry->strmatch) return;

  if (parser->verbose) {

    printf ("SMTPD:\n");

    printf ("CTIME: %08lX\n", parser->ctime);

    if (sentry->connect) { printf ("CONNECT: %s\n", sentry->connect); }
    //printf ("EXTERNAL: %d\n", sentry->external);

  }

  nq = sentry->nqlist;
  while (nq) {
    if (nq->from && nq->to && nq->dstatus) {
      printf ("TO:%08lX:00000000000:%c: from <%s> to <%s>\n", nq->ltime, nq->dstatus, nq->from, nq->to);
      parser->count++;
    }
    nq = nq->next;
  }

  if (parser->verbose) {
    printf ("LOGS:\n");
    loglist_print (&sentry->loglist);
    printf ("\n");
  }

  fflush (stdout);
}

void
sentry_set_connect (SEntry *sentry, const char *connect, int len)
{
  if (sentry->connect) {
#ifdef DEBUG
    if (strncmp (sentry->connect, connect, len)) {
      debug_error ("duplicate connect", NULL);
    }
#endif
  } else {
    sentry->connect = epool_strndup0 (&sentry->ep, connect, len);
  }
}

void
sentry_free_noremove (SEntry *sentry) 
{
  SList *l;
  gpointer data;
  
#ifdef EPOOL_DEBUG
  ep_allocated -= sentry->ep.allocated;
  printf ("MEM: %d\n", ep_allocated);
#endif
  
#ifdef DEBUG
  {
    SEntry *se;
    if ((se = g_hash_table_lookup (smtpd_debug_free, sentry))) {
      debug_error ("SEntry already freed", NULL);
    } else {
      g_hash_table_insert (smtpd_debug_free, sentry, sentry);
    }
  }
  return;
#endif

  l = sentry->ep.mblocks;
  while (l) {
    data = l->data;
    l = l->next;
    g_free (data);
  }

  l = sentry->ep.blocks;
  while (l) {
    data = l->data;
    l = l->next;
    g_mem_chunk_free (mem_chunk_epool, data);
  }
}

void
sentry_free (LParser *parser, SEntry *sentry) 
{
  g_hash_table_remove (parser->smtpd_h, &sentry->pid);

  sentry_free_noremove (sentry);
}

void
sentry_cleanup_hash (gpointer key,
		     gpointer value,
		     gpointer user_data)
{
  SEntry *se = value;
  LParser *parser = (LParser *)user_data;

  sentry_print (parser, se);
  sentry_free_noremove (se);
}

#ifdef DEBUG
void
sentry_debug_alloc (gpointer key,
		    gpointer value,
		    gpointer user_data)
{
  LParser *parser = (LParser *)user_data;
  SEntry *se = value;
  SEntry *fe;

  if ((fe = g_hash_table_lookup (smtpd_debug_free, se))) {
    return;
  }

  printf ("FOUND ALLOCATED SENTRY:\n");
  sentry_print (parser, se);
	  
  exit (-1);
}
#endif

// QEntry

QEntry*
qentry_new (const char *qid)
{
  QEntry *qentry;
  SList *blocks;
  int cpos;
  char *qid_cp;

  qentry = (QEntry *)g_mem_chunk_alloc0 (mem_chunk_epool);

#ifdef EPOOL_DEBUG
  qentry->ep.allocated += EPOOL_BLOCK_SIZE;
  ep_allocated += EPOOL_BLOCK_SIZE;
  ep_maxalloc = (ep_allocated > ep_maxalloc) ? ep_allocated : ep_maxalloc;
#endif

#ifdef DEBUG
  {
    QEntry *qe;
    if ((qe = g_hash_table_lookup (qmgr_debug_alloc, qentry))) {
      debug_error ("QEntry already alloced", NULL);
    } else {
      g_hash_table_insert (qmgr_debug_alloc, qentry, qentry);
    }
  }
#endif

  cpos = sizeof (QEntry);

  blocks = (SList *)((char *)qentry + cpos);

  cpos += sizeof (SList);
  
  blocks->data = qentry;
  blocks->next = NULL;

  qentry->qid = qid_cp = (char *)qentry + cpos;
  while ((*qid_cp++ = *qid++)) cpos++;

  cpos = (cpos + 4) & ~3;

  qentry->ep.blocks = blocks;
  qentry->ep.cpos = cpos;;

  return qentry;
}

void
qentry_tolist_add (QEntry *qentry, time_t ltime, char dstatus, const char *to, int to_len,
		   const char *relay, int relay_len)
{
  TOList *tl = (TOList *)epool_alloc (&qentry->ep, sizeof (TOList));

  tl->to = epool_strndup0 (&qentry->ep, to, to_len);
  tl->relay = epool_strndup0 (&qentry->ep, relay, relay_len);
  tl->dstatus = dstatus;
  tl->ltime = ltime;
  tl->next = qentry->tolist;
  
  qentry->tolist = tl;
}

void
qentry_set_from (QEntry *qentry, const char *from, int len)
{
  if (qentry->from) {
#ifdef DEBUG
    if (strncmp (qentry->from, from, len)) {
      debug_error ("duplicate from", NULL);
    }
#endif
  } else {
    qentry->from = epool_strndup0 (&qentry->ep, from, len);
  }
}

void
qentry_set_msgid (QEntry *qentry, const char *msgid, int len)
{
  if (qentry->msgid) {
#ifdef DEBUG
    if (strncmp (qentry->msgid, msgid, len)) {
      debug_error ("duplicate msgid", NULL);
    }
#endif
  } else {
    qentry->msgid = epool_strndup0 (&qentry->ep, msgid, len);
  }
}

void
qentry_set_client (QEntry *qentry, const char *client, int len)
{
  if (qentry->client) {
#ifdef DEBUG
    if (strncmp (qentry->client, client, len)) {
      debug_error ("duplicate client", NULL);
    }
#endif
  } else {
    qentry->client = epool_strndup0 (&qentry->ep, client, len);
  }
}

void
qentry_print (LParser *parser, QEntry *qentry) 
{
  TOList *tl, *fl;
  SEntry *se = qentry->smtpd;
  FEntry *fe = qentry->filter;

  if (parser->msgid) {
    if (!qentry->msgid) return;
    if (strcasecmp (parser->msgid, qentry->msgid)) return;
  }

  if (parser->qid) {
    int found = 0;
    if (fe && !strcmp (fe->logid, parser->qid)) found = 1;
    if (!strcmp (qentry->qid, parser->qid)) found = 1;

    if (!found) return;    
  }

  if (parser->server) {
    int found = 0;
    if (se && se->connect && strcasestr (se->connect, parser->server)) found = 1;
    if (qentry->client && strcasestr (qentry->client, parser->server)) found = 1;

    if (!found) return;    
  }

  if (parser->from) {
    if (!qentry->from) return;
    if (!*(parser->from)) {
      if (*(qentry->from)) return;
    } else if (!STRMATCH(parser->from, qentry->from)) {
      return;
    }
  } else {
    if (parser->exclude_ndrs && qentry->from && !*qentry->from) return;
  }

  if (parser->to) {
    tl = qentry->tolist;
    int found = 0;
    while (tl) {
      if (parser->to && !STRMATCH(parser->to, tl->to)) {
	tl->to = NULL;
      } else {
	found = 1;
      }
      tl = tl->next;
    }
    if (!found) return;    
  }

  if (parser->strmatch && 
      !(qentry->strmatch || (se && se->strmatch) || (fe && fe->strmatch)))
    return;


  if (parser->verbose) {

    printf ("QENTRY: %s\n", qentry->qid);
 
    printf ("CTIME: %08lX\n", parser->ctime);
    printf ("SIZE: %u\n", qentry->size);

    if (qentry->client) { printf ("CLIENT: %s\n", qentry->client); }

    if (qentry->msgid) { printf ("MSGID: %s\n", qentry->msgid); }

  }

  tl = qentry->tolist;
  while (tl) {
    if (tl->to) {
      fl = NULL;
      if (fe && tl->dstatus == '2') {
	fl = fe->tolist;
	while (fl) {
	  if (fl->to && !strcmp (tl->to, fl->to)) {
	    break;
	  }
	  fl = fl->next;
	}
      }
      char *to;
      char dstatus;
      char *relay;
      
      if (fl) {
	to = fl->to;
	dstatus = fl->dstatus;
	relay = fl->relay;
      } else {
	to = tl->to;
	dstatus = tl->dstatus;
	relay = tl->relay;
      }

      printf ("TO:%08lX:%s:%c: from <%s> to <%s> (%s)\n", tl->ltime, qentry->qid, dstatus, qentry->from ? qentry->from : "", to ? to : "", relay ? relay : "none");

      parser->count++;
    }
    tl = tl->next;
  }


  if (!parser->verbose)  { fflush (stdout); return; }

  if (se) {

    if (se->loglist.log) {
      printf ("SMTP:\n");
      loglist_print (&se->loglist);
    }
  }

  if (fe) {
    if (fe->loglist.log) {
       printf ("FILTER: %s\n", fe->logid);
       loglist_print (&fe->loglist);
     }
  }

  if (qentry->loglist.log) {
    printf ("QMGR:\n");
    loglist_print (&qentry->loglist);
  }

  printf ("\n");

  fflush (stdout);

  //sleep (1);
}

QEntry *
qentry_get (LParser *parser, const char *qid) 
{
  QEntry *qentry;

  if ((qentry = g_hash_table_lookup (parser->qmgr_h, qid))) {
    return qentry;
  } else {
    if ((qentry = qentry_new (qid))) {
      g_hash_table_insert (parser->qmgr_h, qentry->qid, qentry);
    }

    return qentry;
  }
}

void
qentry_free_noremove (LParser *parser, QEntry *qentry) 
{
  SList *l;
  gpointer data;
  SEntry *se;

  if ((se = qentry->smtpd)) {
    if (sentry_ref_del (se, qentry) == 0) {
      if (se->disconnect) { 
	sentry_free_noremove (se);
      }
    }
  }

#ifdef EPOOL_DEBUG
  ep_allocated -= qentry->ep.allocated;
  printf ("MEM: %d\n", ep_allocated);
#endif

#ifdef DEBUG
  {
    QEntry *qe;
    if ((qe = g_hash_table_lookup (qmgr_debug_free, qentry))) {
      debug_error ("QEntry already freed", NULL);
    } else {
      g_hash_table_insert (qmgr_debug_free, qentry, qentry);
    }
  }
  return;
#endif
  
  l = qentry->ep.mblocks;
  while (l) {
    data = l->data;
    l = l->next;
    g_free (data);
  }

  l = qentry->ep.blocks;
  while (l) {
    data = l->data;
    l = l->next;
    g_mem_chunk_free (mem_chunk_epool, data);
  }
}

void
qentry_free (LParser *parser, QEntry *qentry) 
{
  g_hash_table_remove (parser->qmgr_h, qentry->qid);

  qentry_free_noremove (parser, qentry);
}

void
qentry_cleanup_hash (gpointer key,
		     gpointer value,
		     gpointer user_data)
{
  QEntry *qe = value;
  LParser *parser = (LParser *)user_data;

  qentry_print (parser, qe);
  qentry_free_noremove (parser, qe);
}

void
qentry_finalize (LParser *parser, QEntry *qentry)
{
  if (qentry && qentry->removed) {
    SEntry *se = qentry->smtpd;

    if (se && !se->disconnect) return;

    FEntry *fe = qentry->filter;

    if (fe && !fe->finished) return;

    qentry_print (parser, qentry);
    qentry_free (parser, qentry);

    if (fe) fentry_free (parser, fe);
  }
}

// FEntry

FEntry*
fentry_new (const char *logid)
{
  FEntry *fentry;
  SList *blocks;
  int cpos;
  char *logid_cp;

  fentry = (FEntry *)g_mem_chunk_alloc0 (mem_chunk_epool);

#ifdef EPOOL_DEBUG
  fentry->ep.allocated += EPOOL_BLOCK_SIZE;
  ep_allocated += EPOOL_BLOCK_SIZE;
  ep_maxalloc = (ep_allocated > ep_maxalloc) ? ep_allocated : ep_maxalloc;
#endif

#ifdef DEBUG
  {
    FEntry *fe;
    if ((fe = g_hash_table_lookup (filter_debug_alloc, fentry))) {
      debug_error ("FEntry already alloced", NULL);
    } else {
      g_hash_table_insert (filter_debug_alloc, fentry, fentry);
    }
  }
#endif

  cpos = sizeof (FEntry);

  blocks = (SList *)((char *)fentry + cpos);

  cpos += sizeof (SList);
  
  blocks->data = fentry;
  blocks->next = NULL;

  fentry->logid = logid_cp = (char *)fentry + cpos;
  while ((*logid_cp++ = *logid++)) cpos++;  
  cpos = (cpos + 4) & ~3;

  fentry->ep.blocks = blocks;
  fentry->ep.cpos = cpos;;

  return fentry;
}

FEntry *
fentry_get (LParser *parser, const char *logid) 
{
  FEntry *fentry;

  if ((fentry = g_hash_table_lookup (parser->filter_h, logid))) {
    return fentry;
  } else {
    if ((fentry = fentry_new (logid))) {
      g_hash_table_insert (parser->filter_h, fentry->logid, fentry);
    }

    return fentry;
  }
}

void
fentry_tolist_add (FEntry *fentry, char dstatus, const char *to, int to_len,
		   const char *qid, int qid_len)
{
  TOList *tl = (TOList *)epool_alloc (&fentry->ep, sizeof (TOList));

  tl->to = epool_strndup0 (&fentry->ep, to, to_len);

  if (qid) {
    tl->relay = epool_strndup0 (&fentry->ep, qid, qid_len);
  } else {
    tl->relay = NULL;
  }
  tl->dstatus = dstatus;
  tl->next = fentry->tolist;
  
  fentry->tolist = tl;
}

void
fentry_free_noremove (LParser *parser, FEntry *fentry) 
{
  SList *l;
  gpointer data;

#ifdef EPOOL_DEBUG
  ep_allocated -= fentry->ep.allocated;
  printf ("MEM: %d\n", ep_allocated);
#endif

#ifdef DEBUG
  {
    FEntry *fe;
    if ((fe = g_hash_table_lookup (filter_debug_free, fentry))) {
      debug_error ("FEntry already freed", NULL);
    } else {
      g_hash_table_insert (filter_debug_free, fentry, fentry);
    }
  }
  return;
#endif
  
  l = fentry->ep.mblocks;
  while (l) {
    data = l->data;
    l = l->next;
    g_free (data);
  }

  l = fentry->ep.blocks;
  while (l) {
    data = l->data;
    l = l->next;
    g_mem_chunk_free (mem_chunk_epool, data);
  }
}

void
fentry_free (LParser *parser, FEntry *fentry) 
{
  g_hash_table_remove (parser->filter_h, fentry->logid);

  fentry_free_noremove (parser, fentry);
}

void
fentry_cleanup_hash (gpointer key,
		     gpointer value,
		     gpointer user_data)
{
  FEntry *fe = value;
  LParser *parser = (LParser *)user_data;

  fentry_free_noremove (parser, fe);
}

// Parser

LParser*
parser_new ()
{
  LParser *parser = g_malloc0 (sizeof (LParser));
  struct timeval tv;
  struct tm *ltime;
  int i;

  epool_init (&parser->ep);

  if (!(parser->smtpd_h = g_hash_table_new (g_int_hash, g_int_equal))) {
    return NULL;
  }

  if (!(parser->qmgr_h = g_hash_table_new (g_str_hash, g_str_equal))) {
    return NULL;
  }

  if (!(parser->filter_h = g_hash_table_new (g_str_hash, g_str_equal))) {
    return NULL;
  }

  //if (!(parser->track_h = g_hash_table_new (g_str_hash, g_str_equal))) {
  //return NULL;
  //}

  for (i = 0; i <= MAX_LOGFILES; i++) {
    gettimeofday(&tv, NULL);
    tv.tv_sec -= 3600*24*i;
    ltime = localtime (&tv.tv_sec);
    parser->year[i] = ltime->tm_year + 1900;
  }

  return parser;
}

void
parser_free (LParser *parser)
{
  int i;

  for (i = 0; i < MAX_LOGFILES; i++) {
    if (parser->stream[i]) gzclose (parser->stream[i]);
  }

  epool_free (&parser->ep);

  g_hash_table_destroy (parser->smtpd_h);
  g_hash_table_destroy (parser->qmgr_h);
  g_hash_table_destroy (parser->filter_h);
  //g_hash_table_destroy (parser->track_h);

  g_free (parser);
}

#if 0
char *
parser_track (LParser *parser, const char *qid, gboolean insert) 
{
  char *res;

  if ((res = g_hash_table_lookup (parser->track_h, qid))) {
    return res;
  } else {
    if (insert && (res = epool_strdup (&parser->ep, qid))) {
      g_hash_table_insert (parser->track_h, res, res);
      return res;
    }
  }
  return NULL;
}
#endif

static const int linebufsize = 8192;
static int cur_year;
static int cur_month = 0;
static int cal_mtod[12] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};

static time_t
mkgmtime (struct tm *tm)
{
  time_t res;

  int year = tm->tm_year + 1900;
  int mon = tm->tm_mon;

  res = (year - 1970) * 365 + cal_mtod[mon];

  // leap year corrections (gregorian calendar)
  if (mon <= 1) year -= 1;
  res += (year - 1968) / 4;
  res -= (year - 1900) / 100;
  res += (year - 1600) / 400;

  res += tm->tm_mday - 1;
  res = res*24 + tm->tm_hour;
  res = res*60 + tm->tm_min;
  res = res*60 + tm->tm_sec;

  return res;
}

time_t
parse_time (const char **text, int len)
{
  time_t ltime = 0;

  int year = cur_year;

  int mon = 0;
  int mday = 0;
  int hour = 0;
  int min = 0;
  int sec = 0;
  int found;

  const char *line = *text;

  if (len == (linebufsize - 1)) {
    debug_error ("skipping long line data", line);
    return 0;
  }
    
  if (len < 15) {
    debug_error ("skipping short line data", line);
    return 0;
  }

  // parse month
  int csum = (line[0]<<16) + (line[1]<<8) + line[2];
      
  switch (csum) {
  case 4874606: mon = 0; break;
  case 4613474: mon = 1; break;
  case 5071218: mon = 2; break;
  case 4288626: mon = 3; break;
  case 5071225: mon = 4; break;
  case 4879726: mon = 5; break;
  case 4879724: mon = 6; break;
  case 4289895: mon = 7; break;
  case 5465456: mon = 8; break;
  case 5202804: mon = 9; break;
  case 5140342: mon = 10; break;
  case 4482403: mon = 11; break;
  default: 
    debug_error ("unable to parse month", line);
    return 0;    
  }

  // year change heuristik
  if (cur_month == 11 && mon == 0) { 
    year++;
  }
  if (mon > cur_month) cur_month = mon;

  ltime = (year - 1970)*365 + cal_mtod[mon];

  // leap year corrections (gregorian calendar)
  if (mon <= 1) year -= 1;
  ltime += (year - 1968) / 4;
  ltime -= (year - 1900) / 100;
  ltime += (year - 1600) / 400;

  const char *cpos = line + 3;

  found = 0; while (isspace (*cpos)) { cpos++; found = 1; }
  if (!found) {
    debug_error ("missing spaces after month", line);
    return 0;
  }

  found = 0; while (isdigit (*cpos)) { mday = mday*10 + *cpos - 48; cpos++; found++; }
  if (found < 1 || found > 2) {
    debug_error ("unable to parse day of month", line);
    return 0;
  }

  ltime += mday - 1;

  found = 0; while (isspace (*cpos)) { cpos++; found++; }
  if (!found) {
    debug_error ("missing spaces after day of month", line);
    return 0;
  }

  found = 0; while (isdigit (*cpos)) { hour = hour*10 + *cpos - 48; cpos++; found++; }
  if (found < 1 || found > 2) {
    debug_error ("unable to parse hour", line);
    return 0;
  }

  ltime *= 24;
  ltime += hour;

  if (*cpos != ':') {
    debug_error ("missing collon after hour", line);
    return 0;
  }
  cpos++;

  found = 0; while (isdigit (*cpos)) { min = min*10 + *cpos - 48; cpos++; found++; }
  if (found < 1 || found > 2) {
    debug_error ("unable to parse minute", line);
    return 0;
  }

  ltime *= 60;
  ltime += min;

  if (*cpos != ':') {
    debug_error ("missing collon after minute", line);
    return 0;
  }
  cpos++;

  found = 0; while (isdigit (*cpos)) { sec = sec*10 + *cpos - 48; cpos++; found++; }
  if (found < 1 || found > 2) {
    debug_error ("unable to parse second", line);
    return 0;
  }

  ltime *= 60;
  ltime += sec;

  found = 0; while (isspace (*cpos)) { cpos++; found = 1; }
  if (!found) {
    debug_error ("missing spaces after time", line);
    return 0;
  }

  *text = cpos;

  return ltime;
}


int
parser_count_files (LParser *parser) 
{
  int i;
  time_t start = parser->start;
  char linebuf[linebufsize];
  const char *line;
  gzFile *stream;

  for (i = 0; i < MAX_LOGFILES; i++) {
    cur_year = parser->year[i];
    cur_month = 0;

    if ((stream = gzopen (logfiles[i], "r"))) {
      if ((line = gzgets (stream, linebuf, linebufsize))) {
	if (parse_time (&line, strlen (line)) < start) {
	  break;
	}
      } else {
	return i;
      }
      gzclose (stream);
    } else {
      return i;
    }
  }
  
  return i + 1;
}

static char *
parse_qid (const char **text, char *out, char delim, int maxlen) 
{
  const char *idx;
  char *copy = out;

  int found = 0;
  idx = *text;
  while (isxdigit (*idx)) { *copy++ = *idx++; found++; if (found > maxlen) break; }

  if (found > 1 && found < maxlen && 
      ((delim && (*idx == delim)) || (!delim && isspace (*idx)))) {
    *copy = 0;
    idx++;
    while (isspace (*idx)) idx++;
    *text = idx;
    return out;
  }
  return NULL;
}

void
print_usage (const char *name)
{
  fprintf (stderr, "usage: %s [OPTIONS] [OUTPUTFILENAME]\n", name);
  fprintf (stderr, "\t-f SENDER      mails from SENDER\n");
  fprintf (stderr, "\t-t RECIPIENT   mails to RECIPIENT\n");
  fprintf (stderr, "\t-h Server      Server IP or Hostname\n");
  fprintf (stderr, "\t-s START       start time (YYYY-MM-DD HH:MM:SS)\n");
  fprintf (stderr, "\t               or seconds since epoch\n");
  fprintf (stderr, "\t-e END         end time (YYYY-MM-DD HH:MM:SS)\n");
  fprintf (stderr, "\t               or seconds since epoch\n");
  fprintf (stderr, "\t-m MSGID       message ID (exact match)\n");
  fprintf (stderr, "\t-q QID         queue ID (exact match)\n");
  fprintf (stderr, "\t-x STRING      search for strings\n");
  fprintf (stderr, "\t-l LIMIT       print max limit entries\n");
  fprintf (stderr, "\t-v             verbose output\n");
}


// gzgets is ways too slow, so we do it our own way

static int
mygzgetc (gzFile stream)
{
  int br;
  static char readbuf[16384];
  static char *readend = readbuf + sizeof (readbuf);
  static char *readpos = readbuf + sizeof (readbuf);

  if (readpos < readend) return *readpos++;

  if ((br = gzread (stream, readbuf, sizeof (readbuf))) <= 0) {
    return -1;
  } else {
    readpos = readbuf;
    readend = readbuf + br;

    return *readpos++;
  }
}

static char *
mygzgets (gzFile stream, char *line, int bufsize)
{
  int c=0;
  char *cpos;

  cpos = line;
  while (--bufsize > 0 && (c = mygzgetc(stream)) != -1) {
    *cpos++ = c;
    if (c == '\n')
      break;
  }
  if (c == -1 && cpos == line)
    return NULL;
  *cpos++ = '\0';
  return line;
}


extern char *optarg;
extern int optind, opterr, optopt;

int 
main (int argc, char * const argv[])
{
  char linebuf[linebufsize];
  char *line;
  char *uniqueid = NULL;

  const char *text;
  const char *prog;
  const char *idx1;
  const char *idx2;
  const char *cpos;
  int found = 0;
  int csum_prog;
  int lines = 0;
  char qidbuf[30];
  int i;

  struct tm *ltime;
  struct timeval tv;
  time_t ctime, start, end;

  LParser *parser;
  int opt;

#ifdef DEBUG
  smtpd_debug_alloc = g_hash_table_new (g_direct_hash, g_direct_equal);
  qmgr_debug_alloc = g_hash_table_new (g_direct_hash, g_direct_equal);
  filter_debug_alloc = g_hash_table_new (g_direct_hash, g_direct_equal);
  smtpd_debug_free = g_hash_table_new (g_direct_hash, g_direct_equal);
  qmgr_debug_free = g_hash_table_new (g_direct_hash, g_direct_equal);
  filter_debug_free = g_hash_table_new (g_direct_hash, g_direct_equal);
#endif

  if (!(mem_chunk_epool = g_mem_chunk_new ("EPOOL", EPOOL_BLOCK_SIZE, 
					   1000*EPOOL_BLOCK_SIZE, 
					   G_ALLOC_AND_FREE))) {
    fprintf (stderr, "unable to initialize epool\n");
    exit (-1);    
  }

  if (!(parser = parser_new ())) {
    fprintf (stderr, "unable to alloc parser structure\n");
    exit (-1);
  }

  while ((opt = getopt (argc, argv, "f:t:s:e:h:m:q:x:l:I:vgn")) != -1) {
    if (opt == 'f') {
      parser->from = epool_strdup (&parser->ep, optarg);
    } else if (opt == 't') {
      parser->to = epool_strdup (&parser->ep, optarg);
    } else if (opt == 'v') {
      parser->verbose = 1;
    } else if (opt == 'g') {
      parser->exclude_greylist = 1;
    } else if (opt == 'n') {
      parser->exclude_ndrs = 1;
    } else if (opt == 'I') {
      uniqueid = optarg;
    } else if (opt == 'h') {
      parser->server = epool_strdup (&parser->ep, optarg);
    } else if (opt == 'm') {
      parser->msgid = epool_strdup (&parser->ep, optarg);
    } else if (opt == 'q') {
      parser->qid = epool_strdup (&parser->ep, optarg);
    } else if (opt == 'x') {
      parser->strmatch = epool_strdup (&parser->ep, optarg);
    } else if (opt == 'l') {
      char *l;
      parser->limit = strtoul (optarg, &l, 0);
      if (!*optarg || *l) {
	fprintf (stderr, "unable to parse limit '%s'\n", optarg);
	exit (-1);
      }
    } else if (opt == 's') {
      // use strptime to convert time
      struct tm tm;
      char *res;
      if ((!(res = strptime (optarg, "%F %T", &tm)) &&
	   !(res = strptime (optarg, "%s", &tm))) || *res) {
	fprintf (stderr, "unable to parse start time\n");
	exit (-1);
      } else {
	parser->start = mkgmtime (&tm);
      }
    } else if (opt == 'e') {
      struct tm tm;
      char *res;
      if ((!(res = strptime (optarg, "%F %T", &tm)) &&
	   !(res = strptime (optarg, "%s", &tm))) || *res) {
	fprintf (stderr, "unable to parse end time\n");
	exit (-1);
      } else {
	parser->end = mkgmtime (&tm);
      }
    } else {
      print_usage (argv[0]);
      exit (-1);
    }
  }

  if (optind < argc) {

    if ((argc - optind) > 1) {
      print_usage (argv[0]);
      exit (-1);
    }

    char *tmpfn = g_strdup_printf ("/tmp/.proxtrack-%08X.txt", getpid ());

    if ((stdout = freopen (tmpfn, "w", stdout)) == NULL) {
      perror ("unable to open output file");
      exit (-1);
    }
    if (rename (tmpfn, argv[optind]) != 0) {
      perror ("unable to open output file");
      unlink (tmpfn);
      exit (-1);
    }
  }

  // we use gmtime exerywhere to speedup things, this can cause problems
  // when daylight saving time changes

  gettimeofday(&tv, NULL);
  ltime = localtime (&tv.tv_sec);

  if (!parser->start) {
    ltime->tm_sec = 0;
    ltime->tm_min = 0;
    ltime->tm_hour = 0;
    parser->start = mkgmtime (ltime);
  }

  ltime = localtime (&tv.tv_sec);

  if (!parser->end) {
    parser->end = mkgmtime (ltime);
  }

  if (parser->end < parser->start) {
    fprintf (stderr, "end time before start time\n");
    exit (-1);
  }

  int filecount;
  if ((filecount = parser_count_files (parser)) <= 0) {
    fprintf (stderr, "unable to access log files\n");
    exit (-1);
  }

  if (uniqueid) {
    printf ("# LogReader: %d %s\n", getpid(), uniqueid);
  } else {
    printf ("# LogReader: %d\n", getpid());
  }

  printf ("# Query options\n");
  if (parser->from) printf ("# Sender:    %s\n", parser->from);
  if (parser->to) printf ("# Recipient: %s\n", parser->to);
  if (parser->server) printf ("# Server:    %s\n", parser->server);
  if (parser->msgid) printf ("# MsgID:     %s\n", parser->msgid);
  if (parser->qid) printf ("# QID:       %s\n", parser->qid);
  if (parser->strmatch) printf ("# Match:     %s\n", parser->strmatch);

  strftime (linebuf, 256, "%F %T", gmtime (&parser->start));
  printf ("# Start:     %s (%lu)\n", linebuf, parser->start); 
  strftime (linebuf, 256, "%F %T", gmtime (&parser->end));
  printf ("# END:       %s (%lu)\n", linebuf, parser->end); 
  printf ("# End Query Options\n\n");

  fflush (stdout);

  start = parser->start;
  end = parser->end;
  ctime = 0;

  for (i = filecount - 1; i >= 0; i--) {
    gpointer stream;

    // syslog files does not conain years, so we must compute then
    // cur_year is the assumed start year

    cur_month = 0;
    cur_year = parser->year[i];

    if (i <= 1) {
      if (!(stream = (gpointer) fopen (logfiles[i], "r"))) continue;
    } else {
      if (!(stream = (gpointer) gzopen (logfiles[i], "r"))) continue;
    }

    while (1) {

      if (parser->limit && (parser->count >= parser->limit)) {
	printf ("STATUS: aborted by limit (too many hits)\n");
	exit (0);
      }

      if (i <= 1) {
 	line = fgets (linebuf, linebufsize, (FILE *)stream);
      } else {
	line = mygzgets ((gzFile)stream, linebuf, linebufsize);
      }

      if (!line) break;

      int len = strlen (line);
      int pid = 0;

      cpos = line;
      if (!(ctime = parse_time (&cpos, len))) {
	continue;
      } 

      if (ctime < start) continue;
      if (ctime > end) break;

      lines++;

      found = 0; while (!isspace (*cpos)) { cpos++; found = 1; }
      if (!found) {
	debug_error ("missing hostname", line);
	continue;
      }

      found = 0; while (isspace (*cpos)) { cpos++; found = 1; }
      if (!found) {
	debug_error ("missing spaces after host", line);
	continue;
      }

      if ((*cpos == 'l') && !strncmp (cpos, "last message repeated", 21)) {
	continue;
      }

      //printf ("LINE: %s\n", line);

      prog = cpos;

      csum_prog = 0;
      found = 0; while (*cpos && (*cpos != ':') && (*cpos != '[')) { 
	csum_prog = (csum_prog <<8) + *cpos;
	cpos++; 
	found++; 
      }

      //idx1 = g_strndup (prog, found);
      //printf ("TEST:%s:%08X\n", idx1, csum_prog);
      //g_free (idx1);

      if (*cpos == '[') {
	cpos++;
	found = 0; while (isdigit (*cpos)) { 
	  pid = pid*10 + *cpos - 48; 
	  cpos++; 
	  found++; 
	}
	if (found < 1 || found > 15 || *cpos != ']') {
	  debug_error ("unable to parse pid", line);
	  continue;
	}
	cpos++;
      }
    
      if (*cpos++ != ':') {
	debug_error ("missing collon", line);
	continue;
      }


      if (!isspace (*cpos++)) {
	debug_error ("missing space after collon", line);
	continue;
      }

      text = cpos;

      parser->ctime = ctime;

      int strmatch = 0;

      if (parser->strmatch && STRMATCH(parser->strmatch, text)) {
	strmatch = 1;
      }

      if (csum_prog == 0x70726F78) { // proxprox

	if ((idx1 = parse_qid (&cpos, qidbuf, ':', 25))) {

	  FEntry *fe;

	  if (!(fe = fentry_get (parser, idx1))) {
	    continue;
	  }

	  loglist_add (&fe->ep, &fe->loglist, line, len);

	  if (strmatch) fe->strmatch = 1;

	  //fixme: BCC, Notify?
	  //fixme: parse virus info
	  //fixme: parse spam score

	  if ((*cpos == 'a') && !strncmp (cpos, "accept mail to <", 16)) {
	  
	    const char *to_s, *to_e;

	    to_s = cpos = cpos + 16;
	
	    while (*cpos && (*cpos != '>')) { cpos++; }
	  
	    if (*cpos != '>') continue;

	    to_e = cpos;

	    cpos++;

	    if ((*cpos++ != ' ') || (*cpos++ != '(')) continue;
	  
	    if (!(idx1 = parse_qid (&cpos, qidbuf, ')', 15))) continue;

	    // parser_track (parser, idx1, 1);

	    fentry_tolist_add (fe, 'A', to_s, to_e - to_s, idx1, strlen (idx1));

	  } else if ((*cpos == 'm') && !strncmp (cpos, "moved mail for <", 16)) {
	    const char *to_s, *to_e;

	    to_s = cpos = cpos + 16;
	
	    while (*cpos && (*cpos != '>')) { cpos++; }
	  
	    to_e = cpos;

	    if (strncmp (cpos, "> to ", 5)) continue;
	    cpos += 5;

	    if (!strncmp (cpos, "spam", 4)) {
	      cpos += 4;
	    } else if (!strncmp (cpos, "virus", 5)) {
	      cpos += 5;
	    } else {
	      continue;
	    }

	    if (strncmp (cpos, " quarantine - ", 14)) continue;
	    cpos += 14;

	    if (!(idx1 = parse_qid (&cpos, qidbuf, 0, 25))) continue;
	  
	    fentry_tolist_add (fe, 'Q', to_s, to_e - to_s, idx1, strlen (idx1));

	  } else if ((*cpos == 'b') && !strncmp (cpos, "block mail to <", 15)) {
	  
	    const char *to_s;

	    to_s = cpos = cpos + 15;
	
	    while (*cpos && (*cpos != '>')) { cpos++; }
	  
	    if (*cpos != '>') continue;

	    fentry_tolist_add (fe, 'B', to_s, cpos - to_s, NULL, 0);

	  } else if ((*cpos == 'p') && !strncmp (cpos, "processing time: ", 17)) {
	    cpos += 17;

	    sscanf (cpos, "%f", &fe->ptime);

	    fe->finished = 1;
	  }

	}

      } else if (csum_prog == 0x7265656E) { // postfix/postscreen

	      SEntry *se;

	      if (!pid) {
		      debug_error ("no pid for postscreen", line);
		      continue;
	      }


	      if ((*text == 'N') && !strncmp (text, "NOQUEUE: reject: RCPT from ", 27)) {

		      cpos = text + 27;

		      if (!(idx1 = strstr (cpos, "; client ["))) continue;

		      const char *client = cpos = idx1 + 10;

		      while (*cpos && (*cpos != ']')) { cpos++; }

		      const char *client_end = cpos;

		      if (!(idx1 = strstr (cpos, "; from=<"))) continue;

		      const char *from = cpos = idx1 + 8;

		      while (*cpos && (*cpos != '>')) { cpos++; }
		      idx1 = cpos;

		      if ((*cpos == '>') && strncmp (cpos, ">, to=<", 7)) continue;

		      const char *to = cpos = cpos + 7;

		      while (*cpos && (*cpos != '>')) { cpos++; }
	  
		      if (*cpos != '>') continue;

		      if (!(se = sentry_get (parser, pid))) {
			      continue;
		      }

		      if (strmatch) se->strmatch = 1;

		      loglist_add (&se->ep, &se->loglist, line, len);

		      sentry_nqlist_add (se, ctime, from, idx1 - from, to, cpos - to, 'N');

		      sentry_set_connect (se, client, client_end - client);

		      g_hash_table_remove (parser->smtpd_h, &se->pid);

		      se->disconnect = 1;

		      sentry_print (parser, se);
		      sentry_free (parser, se);
	      }
	      
      } else if (csum_prog == 0x716D6772) { // postfix/qmgr

	if ((idx2 = text) && (idx1 = parse_qid (&idx2, qidbuf, ':', 15))) {

	  QEntry *qe;

	  if (!(qe = qentry_get (parser, idx1))) {
	    continue;
	  }

	  if (strmatch) qe->strmatch = 1;

	  qe->cleanup = 1;	

	  loglist_add (&qe->ep, &qe->loglist, line, len);
	
	  if ((*idx2 == 'f') && !strncmp (idx2, "from=<", 6)) {

	    cpos = idx2 = idx2 + 6;
	    while (*cpos && (*cpos != '>')) { cpos++; }

	    if (*cpos != '>') {
	      debug_error ("unable to parse 'from' address", line);
	      continue;
	    }

	    qentry_set_from (qe, idx2, cpos - idx2);

	    cpos++;

	    if ((*cpos == ',') && !strncmp (cpos, ", size=", 7)) {
	      int size = 0;
	      cpos += 7;

	      while (isdigit (*cpos)) { size = size*10 + *cpos++ - 48; }

	      qe->size = size;
	    }
	  
	  } else if ((*idx2 == 'r') && !strncmp (idx2, "removed\n", 8)) {

	    qe->removed = 1;

	    qentry_finalize (parser, qe);
	  }
	}

      } else if ((csum_prog == 0x736D7470) || //postfix/smtp
		 (csum_prog == 0x6C6D7470)) {  //postfix/lmtp

	int lmtp = (csum_prog == 0x6C6D7470);

	if ((cpos = text) && (idx1 = parse_qid (&cpos, qidbuf, ':', 15))) {

	  QEntry *qe;

	  if (!(qe = qentry_get (parser, idx1))) {
	    continue;
	  }

	  if (strmatch) qe->strmatch = 1;

	  qe->cleanup = 1;	

	  loglist_add (&qe->ep, &qe->loglist, line, len);

	  if (strncmp (cpos, "to=<", 4)) continue;
	  cpos += 4;

	  const char *to_s, *to_e;

	  to_s = cpos;
	
	  while (*cpos && (*cpos != '>')) { cpos++; }
	  
	  if (*cpos != '>') continue;

	  to_e = cpos;

	  cpos ++;
	  
	  if (!(cpos = strstr (cpos, ", relay="))) continue;
	  cpos += 8;

	  const char *relay_s, *relay_e;

	  relay_s = cpos;

	  while (*cpos && (*cpos != ',')) { cpos++; }
	  
	  if (*cpos != ',') continue;

	  relay_e = cpos;

	  if (!(idx1 = strstr (cpos + 1, ", dsn="))) continue;

	  cpos = idx1 + 6;

	  if (!isdigit (*cpos)) continue;

	  char dstatus = *cpos;

	  qentry_tolist_add (qe, ctime, dstatus, to_s, to_e - to_s, 
			     relay_s, relay_e - relay_s);

	  if (!lmtp) continue; // filter always uses lmtp

	  if (!(idx1 = strstr (cpos + 1, "status=sent (250 2.")))
	    continue;

	  cpos = idx1 = idx1 + 19;

	  if (*cpos == '5' && (idx1 = strstr (cpos, "5.0 OK ("))) {
	    cpos = idx1 = idx1 + 8;
	  } else if (*cpos == '7' && (idx1 = strstr (cpos, "7.0 BLOCKED ("))) {
	    cpos = idx1 = idx1 + 13;
	  } else {
	    continue;
	  }
	    
	  if (!(idx1 = parse_qid (&cpos, qidbuf, ')', 25)))
	    continue;

	  FEntry *fe;

	  qe->filtered = 1;

	  if ((fe = g_hash_table_lookup (parser->filter_h, idx1))) {
	    qe->filter = fe;	  
	  }
	}

      } else if (csum_prog == 0x6D747064) { // postfix/smtpd
	SEntry *se;

	if (!pid) {
	  debug_error ("no pid for smtpd", line);
	  continue;
	}

	if (!(se = sentry_get (parser, pid))) {
	  continue;
	}

	if (strmatch) se->strmatch = 1;

	loglist_add (&se->ep, &se->loglist, line, len);

	if ((*text == 'c') && !strncmp (text, "connect from ", 13)) {
	
	  cpos = idx1 = text + 13;

	  while (*idx1 && !isspace (*idx1)) { idx1++; }

	  sentry_set_connect (se, cpos, idx1 - cpos);

	  // fixme: do we need this?
	  //if (strcmp (se->connect, "localhost[127.0.0.1]")) {
	  //  se->external = 1;
	  //}

	} else if ((*text == 'd') && !strncmp (text, "disconnect from", 15)) {

	  // unlink
	  g_hash_table_remove (parser->smtpd_h, &se->pid);

	  se->disconnect = 1;

	  if (sentry_ref_rem_unneeded (parser, se) == 0) {
	    sentry_print (parser, se);
	    sentry_free (parser, se);
	  } else {
	    sentry_ref_finalize (parser, se);
	  }
	
	} else if ((*text == 'N') && !strncmp (text, "NOQUEUE:", 8)) {

	  cpos = text + 8;

	  // parse 'whatsup' (reject:)
	  while (*cpos && (*cpos != ':')) { cpos++; }
	  if (*cpos != ':') continue;
	  cpos++;

	  // parse '%s from %s:'
	  while (*cpos && (*cpos != ':')) { cpos++; }
	  if (*cpos != ':') continue;
	  idx1 = cpos++;

	  // parse '%s;'
	  while (*cpos && (*cpos != ';')) { cpos++; }
	  if (*cpos != ';') continue;

	  // greylisting test
	  char dstatus = 'N';
	  *(char *)cpos = 0; // dangerous hack: delimit string
	  if (strstr (idx1, ": Recipient address rejected: Service is unavailable (try later)")) {
	    dstatus = 'G';
	  }
	  *(char *)cpos = ';'; // dangerous hack: restore line

	  if (!(idx1 = strstr (cpos, "; from=<"))) continue;

	  const char *from = cpos = idx1 + 8;

	  while (*cpos && (*cpos != '>')) { cpos++; }
	  idx1 = cpos;

	  if ((*cpos == '>') && strncmp (cpos, "> to=<", 6)) continue;

	  const char *to = cpos = cpos + 6;

	  while (*cpos && (*cpos != '>')) { cpos++; }
	  
	  if (*cpos != '>') continue;

	  sentry_nqlist_add (se, ctime, from, idx1 - from, to, cpos - to, dstatus);

	} else if ((idx2 = text) && (idx1 = parse_qid (&idx2, qidbuf, ':', 15))) {

	  QEntry *qe;

	  if ((qe = qentry_get (parser, idx1))) {

	    if (strmatch) qe->strmatch = 1;

	    sentry_ref_add (se, qe);

	    if ((*idx2 == 'c') && !strncmp (idx2, "client=", 7)) {
	      cpos = idx2 = idx2 + 7;

	      while (*cpos && !isspace (*cpos)) { cpos++; }

	      qentry_set_client (qe, idx2, cpos - idx2);
	    }
	  }

	}
 
      } else if (csum_prog == 0x616E7570) { // postfix/cleanup

	QEntry *qe;

	idx2 = text;
	if ((idx1 = parse_qid (&idx2, qidbuf, ':', 15))) {
	  if ((qe = qentry_get (parser, idx1))) {

	    if (strmatch) qe->strmatch = 1;

	    loglist_add (&qe->ep, &qe->loglist, line, len);

	    if ((*idx2 == 'm') && !strncmp (idx2, "message-id=", 11)) {

	      cpos = idx2 = idx2 + 11;

	      while (*cpos && !isspace(*cpos)) { cpos++; }

	      qentry_set_msgid (qe, idx2, cpos - idx2);

	      qe->cleanup = 1;
	    }
	  } 
	}
      }
    }

    if (i <= 1) {
      fclose ((FILE *)stream);
    } else {
      gzclose ((gzFile)stream);
    }

    if (ctime > end) break;
  }


#ifdef DEBUG
  printf ("LINES: %d\n", lines);
  printf ("MEM SMTPD  entries: %d\n", g_hash_table_size (parser->smtpd_h));
  printf ("MEM QMGR   entries: %d\n", g_hash_table_size (parser->qmgr_h));
  printf ("MEM FILTER entries: %d\n", g_hash_table_size (parser->filter_h));

  printf ("MEMDEB SMTPD entries: %d %d\n", 
	  g_hash_table_size (smtpd_debug_alloc),
	  g_hash_table_size (smtpd_debug_free));
  printf ("MEMDEB QMGR  entries: %d %d\n", 
	  g_hash_table_size (qmgr_debug_alloc),
	  g_hash_table_size (qmgr_debug_free));
  printf ("MEMDEB FILTER  entries: %d %d\n", 
	  g_hash_table_size (filter_debug_alloc),
	  g_hash_table_size (filter_debug_free));
#endif

  g_hash_table_foreach (parser->qmgr_h, qentry_cleanup_hash, parser); 
  g_hash_table_foreach (parser->smtpd_h, sentry_cleanup_hash, parser); 
  g_hash_table_foreach (parser->filter_h, fentry_cleanup_hash, parser); 

#ifdef DEBUG
  printf ("MEMDEB SMTPD entries: %d %d\n", 
	  g_hash_table_size (smtpd_debug_alloc),
	  g_hash_table_size (smtpd_debug_free));
  printf ("MEMDEB QMGR  entries: %d %d\n", 
	  g_hash_table_size (qmgr_debug_alloc),
	  g_hash_table_size (qmgr_debug_free));
  printf ("MEMDEB FILTER  entries: %d %d\n", 
	  g_hash_table_size (filter_debug_alloc),
	  g_hash_table_size (filter_debug_free));

  g_hash_table_foreach (smtpd_debug_alloc, sentry_debug_alloc, parser); 

#endif


#ifdef EPOOL_DEBUG
  printf ("MEMMAX %d\n", ep_maxalloc); 
#endif

  parser_free (parser);
  
  fclose (stdout);

  exit (0);
}

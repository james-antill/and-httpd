/*
 *  Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007  James Antill
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  email: james@and.org
 */
/* controller channel for servers, also has code for multiple procs. at once */

#include "cntl.h"
#include "opt_serv.h"
#include <unistd.h>

#include <poll.h>
#include <socket_poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>

#define EX_UTILS_NO_FUNCS  1
#include "ex_utils.h"

#include "mk.h"

#include "bag.h"

struct Cntl_child
{
 struct Evnt evnt[1];
 pid_t pid;

 Bag *waiters; /* list of struct Cntl_con */

 struct Cntl_child *next; /* list of all childs... */
 struct Cntl_child *prev;
};

struct Cntl_con
{
 struct Evnt evnt[1];

 unsigned int num_child_waiting_procs; /* waiting for X child procs. */

 struct Cntl_con *next; /* list of all cntl cons... */
 struct Cntl_con *prev;
};

/* for simplicity */
#define VEQ(vstr, p, l, cstr) vstr_cmp_cstr_eq(vstr, p, l, cstr)

static Vlg *vlg = NULL;
static struct Evnt *acpt_cntl_evnt = NULL;
static struct Evnt *acpt_pipe_evnt = NULL;

static struct Cntl_child *cntl_childs_beg = NULL;
static struct Cntl_con *cntl_cons_beg = NULL;

#if COMPILE_DEBUG
static unsigned int cntl__childs_waiting_num(void)
{
  struct Cntl_child *scan = cntl_childs_beg;
  unsigned int ret = 0;
  
  while (scan)
  {
    Bag_iter iter[1];
    const Bag_obj *obj = bag_iter_beg(scan->waiters, iter);
    
    ASSERT(!scan->next || (scan->next->prev == scan));
    ASSERT((scan == cntl_childs_beg) ||
           (scan->prev && (scan->prev->next == scan)));
    
    while (obj)
    {
      if (obj->val)
        ++ret;
      obj = bag_iter_nxt(iter);
    }

    scan = scan->next;
  }

  return (ret);
}

static unsigned int cntl__cons_waiting_num(void)
{
  struct Cntl_con *scan = cntl_cons_beg;
  unsigned int ret = 0;
  
  while (scan)
  {
    ASSERT(!scan->next || (scan->next->prev == scan));
    ASSERT((scan == cntl_cons_beg) ||
           (scan->prev && (scan->prev->next == scan)));

    ret += scan->num_child_waiting_procs;

    scan = scan->next;
  }

  return (ret);
}
#endif

static void cntl__fin(Vstr_base *out)
{
  size_t ns1 = 0;
  size_t ns2 = 0;

  if (!(ns1 = vstr_add_netstr_beg(out, out->len)))
    return;
  if (!(ns2 = vstr_add_netstr_beg(out, out->len)))
    return;
  vstr_add_netstr_end(out, ns2, out->len);
  vstr_add_netstr_end(out, ns1, out->len);
}

static const Bag_obj *cntl_waiter_get_first(struct Cntl_child *child)
{
  Bag_iter iter[1];
  const Bag_obj *obj = bag_iter_beg(child->waiters, iter);

  if (obj)
    return (obj);

  return (NULL);
}

static int cntl_waiter_add(struct Cntl_con *con, size_t pos, size_t len)
{
  struct Evnt *evnt = con->evnt;
  struct Cntl_child *scan = cntl_childs_beg;
  
  if (!scan)
  {
    cntl__fin(evnt->io_w);
    return (TRUE);
  }

  ASSERT(cntl__childs_waiting_num() == cntl__cons_waiting_num());
  while (scan)
  {
    Bag *tmp = NULL;
    Vstr_base *out = NULL;
    
    if (!(tmp = bag_add_obj(scan->waiters, "", con)))
      VLG_WARNNOMEM_RET(FALSE, (vlg, "%s: %m\n", "cntl waiters"));
    scan->waiters = tmp;
    
    ++con->num_child_waiting_procs;

    out = scan->evnt->io_w;
    if (!vstr_add_vstr(out, out->len, evnt->io_r, pos, len, VSTR_TYPE_ADD_DEF))
    {
      out->conf->malloc_bad = FALSE;
      return (FALSE);
    }
    
    if (!evnt_send_add(scan->evnt, FALSE, 32))
    {
      evnt_close(scan->evnt);
      return (FALSE);
    }
    
    evnt_put_pkt(scan->evnt);
    
    scan = scan->next;
  }
  ASSERT(cntl__childs_waiting_num() == cntl__cons_waiting_num());

  evnt_poll->wait_cntl_del(evnt, POLLIN);
  
  return (TRUE);
}

static void cntl_waiter_del(struct Cntl_child *child,
                            struct Cntl_con *con)
{
  evnt_got_pkt(child->evnt);

  ASSERT(cntl_waiter_get_first(child) &&
         (cntl_waiter_get_first(child)->val == con));
  
  ASSERT(cntl__childs_waiting_num() == cntl__cons_waiting_num());
  if (con && !--con->num_child_waiting_procs)
  {
    cntl__fin(con->evnt->io_w);
    if (!evnt_send_add(con->evnt, FALSE, 32))
      evnt_close(con->evnt);
    else
      evnt_poll->wait_cntl_add(con->evnt, POLLIN);
  }
  bag_del(child->waiters, 1);
  ASSERT(cntl__childs_waiting_num() == cntl__cons_waiting_num());
}

static void cntl__ns_out_cstr_ptr(Vstr_base *out, const char *ptr)
{
  size_t ns = 0;

  if (!(ns = vstr_add_netstr_beg(out, out->len)))
    return;
  
  vstr_add_cstr_ptr(out, out->len, ptr);
  
  vstr_add_netstr_end(out, ns, out->len);
}

static void cntl__ns_out_fmt(Vstr_base *out, const char *fmt, ...)
   COMPILE_ATTR_FMT(2, 3);
static void cntl__ns_out_fmt(Vstr_base *out, const char *fmt, ...)
{
  va_list ap;
  size_t ns = 0;

  if (!(ns = vstr_add_netstr_beg(out, out->len)))
    return;

  va_start(ap, fmt);
  vstr_add_vfmt(out, out->len, fmt, ap);
  va_end(ap);

  vstr_add_netstr_end(out, ns, out->len);
}

static void cntl__close(Vstr_base *out)
{
  struct Evnt *evnt = evnt_queue("accept");

  if (!evnt)
    return;
  
  while (evnt)
  {
    size_t ns1 = 0;
    
    if (!(ns1 = vstr_add_netstr_beg(out, out->len)))
      return;

    cntl__ns_out_cstr_ptr(out, "CLOSE");
    cntl__ns_out_fmt(out, "from[$<sa:%p>]", EVNT_SA(evnt));
    cntl__ns_out_fmt(out, "ctime[%lu:%lu]",
                     (unsigned long)evnt->ctime.tv_sec,
                     (unsigned long)evnt->ctime.tv_usec);
    cntl__ns_out_fmt(out, "pid[%lu]", (unsigned long)getpid());
    
    vstr_add_netstr_end(out, ns1, out->len);

    vlg_dbg2(vlg, "evnt_close acpt %p\n", evnt);
    evnt_close(evnt);

    evnt = evnt->next;
  }

  if (evnt_is_child())
    evnt_shutdown_r(acpt_cntl_evnt, FALSE);
}

static void cntl__scan_events(Vstr_base *out, const char *tag, struct Evnt *beg)
{
  struct Evnt *ev = beg;
  
  while (ev)
  {
    size_t ns = 0;

    if (!(ns = vstr_add_netstr_beg(out, out->len)))
      return;

    cntl__ns_out_fmt(out, "EVNT %s", tag);
    cntl__ns_out_fmt(out, "from[$<sa:%p>]", EVNT_SA(ev));
    if (EVNT_ACPT_EXISTS(ev))
      cntl__ns_out_fmt(out, "acpt[$<sa:%p>]", EVNT_ACPT_SA(ev));
    cntl__ns_out_fmt(out, "ctime[%lu:%lu]",
                     (unsigned long)ev->ctime.tv_sec,
                     (unsigned long)ev->ctime.tv_usec);
    cntl__ns_out_fmt(out, "mtime[%lu:%lu]",
                     (unsigned long)ev->mtime.tv_sec,
                     (unsigned long)ev->mtime.tv_usec);
    cntl__ns_out_fmt(out, "pid[%lu]", (unsigned long)getpid());
    cntl__ns_out_fmt(out, "req_got[%'ju:%ju]",
                     ev->acct.req_got, ev->acct.req_got);
    cntl__ns_out_fmt(out, "req_put[%'ju:%ju]",
                     ev->acct.req_put, ev->acct.req_put);
    cntl__ns_out_fmt(out, "recv[${BKMG.ju:%ju}:%ju]",
                     ev->acct.bytes_r, ev->acct.bytes_r);
    cntl__ns_out_fmt(out, "send[${BKMG.ju:%ju}:%ju]",
                     ev->acct.bytes_w, ev->acct.bytes_w);

    vstr_add_netstr_end(out, ns, out->len);
    
    ev = ev->next;
  }
}

static void cntl__status(Vstr_base *out)
{
  struct Evnt *evnt = evnt_queue("accept");
  
  while (evnt)
  {
    size_t ns1 = 0;
    
    if (!(ns1 = vstr_add_netstr_beg(out, out->len)))
      return;

    cntl__ns_out_cstr_ptr(out, "STATUS");
    cntl__ns_out_fmt(out, "from[$<sa:%p>]", EVNT_SA(evnt));
    cntl__ns_out_fmt(out, "ctime[%lu:%lu]",
                     (unsigned long)evnt->ctime.tv_sec,
                     (unsigned long)evnt->ctime.tv_usec);
  
    cntl__ns_out_fmt(out, "pid[%lu]", (unsigned long)getpid());
  
    vstr_add_netstr_end(out, ns1, out->len);
    
    evnt = evnt->next;
  }
}

static void cntl__dbg(Vstr_base *out)
{
  size_t ns1 = 0;
  
  if (!(ns1 = vstr_add_netstr_beg(out, out->len)))
    return;

  cntl__ns_out_cstr_ptr(out, "DBG");
  cntl__ns_out_fmt(out, "pid[%lu]", (unsigned long)getpid());
  cntl__ns_out_fmt(out, "dbg[%u]", (unsigned)vlg->out_dbg);
  vstr_add_netstr_end(out, ns1, out->len);
}

/* if we have no connections, and no way to get new connections then close
 * the coms channel with the children. */
static void cntl__check_child_shutdown(void)
{
  if (!acpt_cntl_evnt && !cntl_cons_beg)
  {
    struct Cntl_child *scan = cntl_childs_beg;
    
    while (scan)
    {
      evnt_close(scan->evnt);
      scan = scan->next;
    }
  }
}

static void cntl__cb_func_free(struct Evnt *evnt)
{
  struct Cntl_con *con = (struct Cntl_con *)evnt;
  struct Cntl_child *scan = cntl_childs_beg;
  
  opt_serv_sc_free_beg(evnt, "CNTL FREE");

  ASSERT(cntl__childs_waiting_num() == cntl__cons_waiting_num());
  while (con->num_child_waiting_procs && scan)
  {
    size_t num = bag_sc_srch_num_eq(scan->waiters,
                                    bag_cb_srch_eq_val_ptr, evnt);
    
    if (num)
    {
      bag_set_obj(scan->waiters, num, "", NULL);
      --con->num_child_waiting_procs;
    }
    
    scan = scan->next;
  }
  ASSERT(cntl__childs_waiting_num() == cntl__cons_waiting_num());
  
  if (con->prev)
    con->prev->next = con->next;
  else
    cntl_cons_beg = con->next;
  if (con->next)
    con->next->prev = con->prev;

  cntl__check_child_shutdown();
  
  F(evnt);
}

static int cntl__cb_func_recv(struct Evnt *evnt)
{
  struct Cntl_con *con = (struct Cntl_con *)evnt;
  
  if (!evnt_cb_func_recv(evnt))
    goto malloc_bad;

  vlg_dbg2(vlg, "CNTL recv() io_r->len=%zu\n", evnt->io_r->len);

  while (evnt->io_r->len && !con->num_child_waiting_procs)
  {
    size_t pos  = 0;
    size_t len  = 0;
    size_t ns1  = 0;
    size_t cpos = 0;
    size_t clen = 0;
    size_t ns2  = 0;
    
    if (!(ns1 = vstr_parse_netstr(evnt->io_r, 1, evnt->io_r->len, &pos, &len)))
    {
      if (!(SOCKET_POLL_INDICATOR(evnt->ind)->events & POLLIN))
        return (FALSE);
      return (TRUE);
    }
    if ((ns2 = vstr_parse_netstr(evnt->io_r, pos, len, &cpos, &clen)))
    { /* double netstr ... might have arguments... */
      SWAP_TYPE(pos, cpos, size_t);
      SWAP_TYPE(len, clen, size_t);
    }
    
    evnt_got_pkt(evnt);

    if (0){ }
    else if (VEQ(evnt->io_r, pos, len, "CLOSE"))
    { /* FIXME: if arg. ns2  ... search for that and close */
      cntl__close(evnt->io_w);
      
      if (!cntl_waiter_add(con, 1, ns1))
        goto malloc_bad;
    }
    else if (VEQ(evnt->io_r, pos, len, "DBG"))
    {
      vlg_debug(vlg);
      cntl__dbg(evnt->io_w);

      if (!cntl_waiter_add(con, 1, ns1))
        goto malloc_bad;
    }
    else if (VEQ(evnt->io_r, pos, len, "UNDBG"))
    {
      vlg_undbg(vlg);
      cntl__dbg(evnt->io_w);

      if (!cntl_waiter_add(con, 1, ns1))
        goto malloc_bad;
    }
    else if (VEQ(evnt->io_r, pos, len, "LIST"))
    {
      cntl__scan_events(evnt->io_w, "CONNECT",   evnt_queue("connect"));
      cntl__scan_events(evnt->io_w, "ACCEPT",    evnt_queue("accept"));
      cntl__scan_events(evnt->io_w, "SEND/RECV", evnt_queue("send_recv"));
      cntl__scan_events(evnt->io_w, "RECV",      evnt_queue("recv"));
      cntl__scan_events(evnt->io_w, "NONE",      evnt_queue("none"));
      cntl__scan_events(evnt->io_w, "SEND_NOW",  evnt_queue("send_now"));
      
      if (!cntl_waiter_add(con, 1, ns1))
        goto malloc_bad;
    }
    else if (VEQ(evnt->io_r, pos, len, "STATUS"))
    {
      cntl__status(evnt->io_w);

      if (!cntl_waiter_add(con, 1, ns1))
        goto malloc_bad;
    }
    else
      return (FALSE);
  
    if (evnt->io_w->conf->malloc_bad)
      goto malloc_bad;
    
    evnt_put_pkt(evnt);
    if (!evnt_send_add(evnt, FALSE, 32))
      return (FALSE);
  
    vstr_del(evnt->io_r, 1, ns1);
  }
  
  return (TRUE);
  
 malloc_bad:
  evnt->io_r->conf->malloc_bad = FALSE;
  evnt->io_w->conf->malloc_bad = FALSE;
  return (FALSE);
}

static const struct Evnt_cbs cntl__evnt_cbs =
{
 evnt_cb_func_accept,    /* def */
 evnt_cb_func_connect,   /* def */

 cntl__cb_func_recv,
 evnt_cb_func_send,      /* def */

 cntl__cb_func_free,
 evnt_cb_func_shutdown_r /* def */
};

static void cntl__cb_func_acpt_free(struct Evnt *evnt)
{
  Acpt_cntl_listener *acpt_listener = (Acpt_cntl_listener *)evnt;
  Acpt_data *acpt_data = acpt_listener->s->ref->ptr;
  Vstr_base *fname = acpt_listener->fname;
  const char *fname_cstr = NULL;
  
  evnt_vlg_stats_info(evnt, "ACCEPT CNTL FREE");
  
  ASSERT(acpt_cntl_evnt == evnt);
  acpt_cntl_evnt = NULL;

  ASSERT(acpt_listener->fname);
  
  acpt_data->evnt = NULL;
  vstr_ref_del(acpt_listener->s->ref);
  F(acpt_listener);
  
  if (!(fname_cstr = vstr_export_cstr_ptr(fname, 1, fname->len)))
    vlg_warn(vlg, "export cntl file($<vstr.all:%p>): %m\n", fname);
  else if (unlink(fname_cstr) == -1)
    vlg_warn(vlg, "unlink cntl file($<vstr.all:%p>): %m\n", fname);
  vstr_free_base(fname);
  
  evnt_acpt_close_all();

  cntl__check_child_shutdown();
}

static struct Evnt *cntl__cb_func_accept(struct Evnt *from_evnt, int fd,
                                         struct sockaddr *sa, socklen_t len)
{
  Acpt_listener *acpt_listener = (Acpt_listener *)from_evnt;
  struct Cntl_con *con = NULL;
  struct Evnt *evnt = NULL;
  
  ASSERT(acpt_cntl_evnt);
  ASSERT(acpt_cntl_evnt == from_evnt);
  ASSERT(from_evnt->sa_ref);
  ASSERT(len >= 2);
  
  if (sa->sa_family != AF_LOCAL)
    goto valid_family_fail;
  
  if (!(con = MK(sizeof(struct Cntl_con))))
    goto mk_acpt_fail;
  evnt = con->evnt;
  
  con->prev = NULL;
  if ((con->next = cntl_cons_beg))
    con->next->prev = con;
  cntl_cons_beg = con;

  ((struct Cntl_con *)evnt)->num_child_waiting_procs = 0;
  
  if (!evnt_make_acpt_ref(evnt, fd, from_evnt->sa_ref))
    goto make_acpt_fail;

  assert(EVNT_SA_UN(evnt));

  vlg_info(vlg, "CNTL CONNECT from[$<sa:%p>]\n", EVNT_SA(evnt));

  evnt->cbs = &cntl__evnt_cbs;

  evnt->acpt_sa_ref = vstr_ref_add(acpt_listener->ref);
  
  return (evnt);
  
 make_acpt_fail:
  F(evnt);
  VLG_WARNNOMEM_RET(NULL, (vlg, "%s: %m\n", "accept"));
 mk_acpt_fail:
 valid_family_fail:
  VLG_WARN_RET(NULL, (vlg, "%s: %m\n", "accept"));
}

static void cntl__sc_serv_make_acpt_data_cb(Vstr_ref *ref)
{ /* FIXME: same as evnt__sc_serv_make_acpt_data_cb */
  struct Acpt_data *ptr = NULL;
  
  if (!ref)
    return;

  ptr = ref->ptr;
  vstr_ref_del(ptr->sa);
  F(ptr);
  free(ref);
}

static const struct Evnt_cbs cntl__acpt_evnt_cbs =
{
 cntl__cb_func_accept,
 evnt_cb_func_connect,   /* def */

 evnt_cb_func_recv,      /* def */
 evnt_cb_func_send,      /* def */

 cntl__cb_func_acpt_free,
 evnt_cb_func_shutdown_r /* def */
};

void cntl_make_file(Vlg *passed_vlg, const Vstr_base *fname)
{
  Acpt_listener *acpt_listener = NULL;
  Acpt_cntl_listener *acpt_cntl_listener = NULL;
  Acpt_data *acpt_data = NULL;
  struct Evnt *evnt = NULL;
  Vstr_ref *ref = NULL;
  unsigned int q_listen_len = 8;
  const char *fname_cstr = NULL;
  
  ASSERT(!vlg && passed_vlg);

  vlg = passed_vlg;
  
  ASSERT(fname);
  ASSERT(!acpt_cntl_evnt);
    
  if (!(fname_cstr = vstr_export_cstr_ptr(fname, 1, fname->len)))
    vlg_err(vlg, EXIT_FAILURE, "cntl file($<vstr.all:%p>): %m\n", fname);

  if (!(acpt_cntl_listener = MK(sizeof(Acpt_cntl_listener))))
    VLG_ERRNOMEM((vlg, EXIT_FAILURE, "cntl file(%s): %m\n", fname_cstr));
  acpt_cntl_listener->fname = NULL;
  acpt_listener = acpt_cntl_listener->s;
  acpt_listener->max_connections = 0;
  acpt_listener->def_policy = NULL;
  evnt = acpt_listener->evnt;
  
  if (!(acpt_cntl_listener->fname = vstr_dup_vstr(fname->conf,
                                                  fname, 1, fname->len,
                                                  VSTR_TYPE_ADD_DEF)))
    VLG_ERRNOMEM((vlg, EXIT_FAILURE, "cntl file(%s): %m\n", fname_cstr));
  
  if (!(acpt_data = MK(sizeof(Acpt_data))))
    VLG_ERRNOMEM((vlg, EXIT_FAILURE, "cntl file(%s): %m\n", fname_cstr));
  acpt_data->evnt = NULL;
  acpt_data->sa   = NULL;
  
  if (!(ref = vstr_ref_make_ptr(acpt_data, cntl__sc_serv_make_acpt_data_cb)))
    VLG_ERRNOMEM((vlg, EXIT_FAILURE, "make_bind(%s): %m\n", fname_cstr));
  acpt_listener->ref = ref;

  /* cp vstr for name */
  if (!evnt_make_bind_local(evnt, fname_cstr, q_listen_len, 0600))
    vlg_err(vlg, EXIT_FAILURE, "cntl file(%s): %m\n", fname_cstr);
  acpt_data->evnt = evnt;
  acpt_data->sa   = vstr_ref_add(evnt->sa_ref);

  evnt->cbs = &cntl__acpt_evnt_cbs;

  acpt_cntl_evnt = evnt;
}

static void cntl__cb_func_cntl_acpt_free(struct Evnt *evnt)
{
  Acpt_cntl_listener *acpt_listener = (Acpt_cntl_listener *)evnt;
  Acpt_data *acpt_data = acpt_listener->s->ref->ptr;

  evnt_vlg_stats_info(evnt, "CHILD CNTL FREE");
  
  ASSERT(acpt_cntl_evnt == evnt);
  acpt_cntl_evnt = NULL;
  
  ASSERT(!acpt_listener->fname);
  
  acpt_data->evnt = NULL;
  vstr_ref_del(acpt_listener->s->ref);
  vstr_ref_del(acpt_listener->s->def_policy);
  F(acpt_listener);
  
  evnt_acpt_close_all();
}

static void cntl__cb_func_pipe_acpt_free(struct Evnt *evnt)
{
  evnt_vlg_stats_info(evnt, "CHILD PIPE FREE");
  
  ASSERT(acpt_pipe_evnt == evnt);
  acpt_pipe_evnt = NULL;

  F(evnt);
  
  evnt_acpt_close_all();
}

static const struct Evnt_cbs cntl__acpt_cntl_evnt_cbs =
{
 evnt_cb_func_accept,    /* def */
 evnt_cb_func_connect,   /* def */

 cntl__cb_func_recv,
 evnt_cb_func_send,      /* def */

 cntl__cb_func_cntl_acpt_free,
 evnt_cb_func_shutdown_r /* def */
};

static const struct Evnt_cbs cntl__acpt_pipe_evnt_cbs =
{
 evnt_cb_func_accept,    /* def */
 evnt_cb_func_connect,   /* def */

 evnt_cb_func_recv,      /* def */
 evnt_cb_func_send,      /* def */

 cntl__cb_func_pipe_acpt_free,
 evnt_cb_func_shutdown_r /* def */
};

/* used to get death sig or pass through cntl data */
static void cntl_pipe_acpt_fds(Vlg *passed_vlg, int fd, int allow_pdeathsig)
{
  ASSERT(fd != -1);

  if (acpt_cntl_evnt)
  {
    int old_fd = SOCKET_POLL_INDICATOR(acpt_cntl_evnt->ind)->fd;
    Acpt_cntl_listener *acpt_listener = (Acpt_cntl_listener *)acpt_cntl_evnt;
    
    ASSERT(vlg       == passed_vlg);

    if (!evnt_poll->swap_accept_read(acpt_cntl_evnt, fd))
      vlg_abort(vlg, "%s: %m\n", "swap_acpt");

    close(old_fd);
    
    acpt_cntl_evnt->cbs = &cntl__acpt_cntl_evnt_cbs;

    vstr_free_base(acpt_listener->fname);
    acpt_listener->fname = NULL;
    
    if (allow_pdeathsig && (PROC_CNTL_PDEATHSIG(SIGCHLD) == -1))
      vlg_warn(vlg, "prctl(%s, %s): %m\n", "PR_SET_PDEATHSIG", "SIGCHLD");
  }
  else
  {
    if (!vlg)
      vlg = passed_vlg;
    ASSERT(vlg       == passed_vlg);

    if (allow_pdeathsig)
    {
      if (PROC_CNTL_PDEATHSIG(SIGCHLD) == -1)
        vlg_warn(vlg, "prctl(%s, %s): %m\n", "PR_SET_PDEATHSIG", "SIGCHLD");
      else
      {
        close(fd);
        return;
      }
    }
    
    if (!(acpt_pipe_evnt = MK(sizeof(struct Evnt))))
      VLG_ERRNOMEM((vlg, EXIT_FAILURE, "%s: %m\n", "pipe evnt"));
    
    if (!evnt_make_custom(acpt_pipe_evnt, fd, 0, 0))
      vlg_err(vlg, EXIT_FAILURE, "%s: %m\n", "pipe evnt");

    acpt_cntl_evnt->cbs = &cntl__acpt_pipe_evnt_cbs;
  }
}

void cntl_child_free(void)
{ /* close all Child events... */
  struct Cntl_child *scan = cntl_childs_beg;
  
  while (scan)
  {
    evnt_close(scan->evnt);
    scan = scan->next;
  }
}

static int cntl__cb_func_child_recv(struct Evnt *evnt)
{
  struct Cntl_child *child = (struct Cntl_child *)evnt;
  struct Cntl_con *con = NULL;
  int ret = -1;

  ret = evnt_cb_func_recv(evnt);
  if (!ret && evnt->io_r_shutdown)
    return (FALSE); /* we're probably going all the way down now */

  if (!ret)
    goto malloc_bad;

  while (evnt->io_r->len)
  {
    size_t ns1  = 0;
    size_t pos  = 0;
    size_t len  = 0;
    size_t vpos = 0;
    size_t vlen = 0;
    size_t nse2 = 0;
    int done = FALSE;
    const Bag_obj *bobj = cntl_waiter_get_first(child);
    
    ASSERT(bobj);

    con = bobj->val;
  
    if (!(ns1 = vstr_parse_netstr(evnt->io_r, 1, evnt->io_r->len, &pos, &len)))
    {
      if (!(SOCKET_POLL_INDICATOR(evnt->ind)->events & POLLIN))
        return (FALSE);
      return (TRUE);
    }
    
    while ((nse2 = vstr_parse_netstr(evnt->io_r, pos, len, &vpos, &vlen)))
    {
      if (!done && !vlen && (nse2 == len))
      {
        cntl_waiter_del(child, con);
        vstr_del(evnt->io_r, 1, ns1);
        break;
      }
      
      done = TRUE;
      len -= nse2; pos += nse2;
    }
    if (nse2)
      continue;

    if (len)
      VLG_WARN_RET(FALSE, (vlg, "invalid entry\n"));

    if (!con)
      vstr_del(evnt->io_r, 1, ns1);
    else
    {
      struct Evnt *out = con->evnt;
      
      if (!vstr_mov(out->io_w, out->io_w->len, evnt->io_r, 1, ns1))
        goto malloc_bad;
    }
  }

  return (TRUE);
  
 malloc_bad:
  if (con) /* if a con is available cascade the error down to it */
    evnt_close(con->evnt);
  evnt->io_r->conf->malloc_bad = FALSE;
  evnt->io_w->conf->malloc_bad = FALSE;
  return (TRUE); /* this is "true" because the app. dies if we kill the child */
}

static void cntl__cb_func_child_free(struct Evnt *evnt)
{
  struct Cntl_child *child = (struct Cntl_child *)evnt;
  const Bag_obj *scan = NULL;
  
  ASSERT(cntl__childs_waiting_num() == cntl__cons_waiting_num());
  while ((scan = cntl_waiter_get_first(child)))
  {
    struct Cntl_con *con = scan->val;
    
    bag_del(child->waiters, 1);

    if (con)
    {
      --con->num_child_waiting_procs;
      evnt_poll->wait_cntl_add(con->evnt, POLLIN);
    }
  }
  ASSERT(!child->waiters->num);
  ASSERT(cntl__childs_waiting_num() == cntl__cons_waiting_num());

  if (child->prev)
    child->prev->next = child->next;
  else
    cntl_childs_beg = child->next;
  if (child->next)
    child->next->prev = child->prev;
  
  bag_free(child->waiters);
  F(evnt);
}

static const struct Evnt_cbs cntl__child_evnt_cbs =
{
 evnt_cb_func_accept,    /* def */
 evnt_cb_func_connect,   /* def */

 cntl__cb_func_child_recv,
 evnt_cb_func_send,      /* def */

 cntl__cb_func_child_free,
 evnt_cb_func_shutdown_r /* def */
};

void cntl_child_pid(pid_t pid, int use_cntl, int fd)
{
  struct Cntl_child *child = NULL;

  ASSERT(acpt_cntl_evnt);
    
  if (!(child = MK(sizeof(struct Cntl_child))))
    VLG_ERRNOMEM((vlg, EXIT_FAILURE, "%s: %m\n", "cntl children"));

  child->pid = pid;
  child->waiters = NULL;

  child->prev = NULL;
  if ((child->next = cntl_childs_beg))
    child->next->prev = child;
  cntl_childs_beg = child;
  
  if (use_cntl &&
      !(child->waiters = bag_make(4,
                                  bag_cb_free_nothing, bag_cb_free_nothing)))
    VLG_ERRNOMEM((vlg, EXIT_FAILURE, "%s: %m\n", "cntl children"));
    
  if (!evnt_make_custom(child->evnt, fd, 0, POLLIN))
    vlg_err(vlg, EXIT_FAILURE, "%s: %m\n", "cntl children");

  child->evnt->cbs = &cntl__child_evnt_cbs;
}

/* Here we fork multiple procs. however:
 *
 *  If we have a cntl connection we keep two way communication open with the
 * children.
 *
 *  If not we "leak" the writable side of the pipe() fd in the parent,
 * which will cause an error on all the children's fd when the parent dies.
 *
 *  The children also kill themselves if the parent fd has an error.
 */
void cntl_sc_multiproc(Vlg *passed_vlg, 
                       unsigned int num, int use_cntl, int allow_pdeathsig)
{
  int pfds[2] = {-1, -1};
  
  if (!vlg)
    vlg = passed_vlg;

  ASSERT(vlg == passed_vlg);
  
  vlg_pid_set(vlg, TRUE);
  
  if (!use_cntl && (pipe(pfds) == -1))
    vlg_err(vlg, EXIT_FAILURE, "pipe(): %m\n");
  
  while (--num)
  {
    pid_t cpid = -1;
      
    if (use_cntl && (socketpair(PF_LOCAL, SOCK_STREAM, 0, pfds) == -1))
      vlg_err(vlg, EXIT_FAILURE, "socketpair(): %m\n");

    if ((cpid = evnt_make_child()) == -1)
      vlg_err(vlg, EXIT_FAILURE, "fork(): %m\n");

    if (use_cntl && cpid) /* parent */
    {
      close(pfds[0]);
      cntl_child_pid(cpid, use_cntl, pfds[1]);
    }
    else if (!cpid)
    { /* child */
      close(pfds[1]);
      cntl_child_free();
      cntl_pipe_acpt_fds(vlg, pfds[0], allow_pdeathsig);
      
      evnt_scan_q_close();
      return;
    }
  }

  if (!use_cntl)
    close(pfds[0]); /* close child pipe() */
  
  evnt_scan_q_close();
}


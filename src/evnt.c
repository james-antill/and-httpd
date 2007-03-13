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
/* IO events, and some help with timed events */
#include <vstr.h>

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <netdb.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>

#include <socket_poll.h>
#include <timer_q.h>

#include <sys/sendfile.h>

#ifndef TCP_CONGESTION
# ifdef __linux__
#  define TCP_CONGESTION 13
# else
#  define TCP_CONGESTION 0
# endif
#endif

/* FIXME: Should do better autoconf checks... */
#if defined(__linux__)
/* Linux doesn't let TCP_NODELAY be config., like Solaris ... and maybe *BSD?
 * and doesn't inherit socket flags from accept() like *BSD */
# define HAVE_TCP_NODELAY_CONFIG FALSE
#else
# define HAVE_TCP_NODELAY_CONFIG TRUE
#endif

#if defined(__BSD__)
/* Linux doesn't inherit socket flags from accept() like *BSD ...
 * and maybe Solaris? */
# define HAVE_SOCK_FLAGS_INHERIT TRUE
#else
# define HAVE_SOCK_FLAGS_INHERIT FALSE
#endif

#define CONF_GETTIMEOFDAY_TIME TRUE /* does tv_sec contain time(NULL) */

#ifdef CONF_FULL_STATIC
# define EVNT__RESOLVE_NAME(saddr, x) do {                     \
   if ((saddr->sin_addr.s_addr = inet_addr(x)) == INADDR_NONE) \
     saddr->sin_addr.s_addr = htonl(INADDR_ANY);               \
 } while (FALSE)
#else
# include <netdb.h>
# define EVNT__RESOLVE_NAME(saddr, x) do {                              \
   if ((saddr->sin_addr.s_addr = inet_addr(x)) == INADDR_NONE)          \
   {                                                                    \
     struct hostent *h = gethostbyname(x);                              \
                                                                        \
     saddr->sin_addr.s_addr = htonl(INADDR_ANY);                        \
     if (h)                                                             \
       memcpy(&saddr->sin_addr.s_addr,                                  \
              h->h_addr_list[0],                                        \
              sizeof(saddr->sin_addr.s_addr));                          \
   }                                                                    \
 } while (FALSE)
#endif

#if !defined(SO_DETACH_FILTER) || !defined(SO_ATTACH_FILTER)
# define CONF_USE_SOCKET_FILTERS FALSE
struct sock_fprog { int dummy; };
# define SO_DETACH_FILTER 0
# define SO_ATTACH_FILTER 0
#else
# define CONF_USE_SOCKET_FILTERS TRUE

/* not in glibc... hope it's not in *BSD etc. */
struct sock_filter
{
 uint16_t   code;   /* Actual filter code */
 uint8_t    jt;     /* Jump true */
 uint8_t    jf;     /* Jump false */
 uint32_t   k;      /* Generic multiuse field */
};

struct sock_fprog
{
 unsigned short len;    /* Number of filter blocks */
 struct sock_filter *filter;
};
#endif

#include "vlg.h"

#define EX_UTILS_NO_USE_INIT  1
#define EX_UTILS_NO_USE_EXIT  1
#define EX_UTILS_NO_USE_LIMIT 1
#define EX_UTILS_NO_USE_BLOCK 1
#define EX_UTILS_NO_USE_PUT   1
#define EX_UTILS_NO_USE_OPEN  1
#define EX_UTILS_NO_USE_IO_FD 1
#define EX_UTILS_RET_FAIL     1
#include "ex_utils.h"

#ifdef HAVE_TCP_CORK
# define USE_TCP_CORK TRUE
#else
# define USE_TCP_CORK FALSE
# define TCP_CORK 0
#endif

#include "evnt.h"

#include "mk.h"

volatile sig_atomic_t evnt_signal_child_exited = FALSE;
volatile sig_atomic_t evnt_signal_term = FALSE;

int evnt_opt_nagle = EVNT_CONF_NAGLE;

static struct Evnt *q_send_now = NULL;  /* Try a send "now" */
static struct Evnt *q_closed   = NULL;  /* Close when fin. */

static struct Evnt *q_none      = NULL; /* nothing */
static struct Evnt *q_accept    = NULL; /* connections - recv */
static struct Evnt *q_connect   = NULL; /* connections - send */
static struct Evnt *q_recv      = NULL; /* recv */
static struct Evnt *q_send_recv = NULL; /* recv + send */

static Vlg *vlg = NULL;

static unsigned int evnt__num = 0;

/* things can move from recv -> send_recv with a timeout,
 * so they look like the end of events NULL */
static unsigned int evnt__scan_ready_moved_send_zero_fds = 0;

/* this should be more configurable... */
static unsigned int evnt__accept_limit = 4;

static struct timeval evnt__tv[1];

static int evnt__is_child = FALSE;

#define EVNT__UPDATE_TV() gettimeofday(evnt__tv, NULL)
#define EVNT__COPY_TV(x)  memcpy(x, evnt__tv, sizeof(struct timeval))

void evnt_logger(Vlg *passed_vlg)
{
  vlg = passed_vlg;
  evnt_poll_logger(vlg);
}

void evnt_fd__set_nonblock(int fd, int val)
{
  int flags = 0;

  ASSERT(val == !!val);
  
  if ((flags = fcntl(fd, F_GETFL)) == -1)
    vlg_err(vlg, EXIT_FAILURE, "%s: %m\n", __func__);

  if (!!(flags & O_NONBLOCK) == val)
    return;

  if (val)
    flags |=  O_NONBLOCK;
  else
    flags &= ~O_NONBLOCK;
  
  if (fcntl(fd, F_SETFL, flags) == -1)
    vlg_err(vlg, EXIT_FAILURE, "%s: %m\n", __func__);
}

static void evnt_fd__set_coe(int fd, int val)
{ /* close on exec */
  ASSERT(val == !!val);

  if (fcntl(fd, F_SETFD, val) == -1)
    vlg_err(vlg, EXIT_FAILURE, "%s: %m\n", __func__);
}

static int evnt_fd__set_nodelay(int fd, int val)
{
  return (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val)) != -1);
}

static int evnt_fd__set_cork(int fd, int val)
{
  return (setsockopt(fd, IPPROTO_TCP, TCP_CORK, &val, sizeof(val)) != -1);
}

static int evnt_fd__set_reuse(int fd, int val)
{
  return (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) != -1);
}

#define CLEN_SZ(x) (strlen(x) + 1)
static int evnt_fd__set_congestion(int fd, const char *val)
{
  if (!TCP_CONGESTION)
    return (errno = ENOPROTOOPT, FALSE);
  
  return (setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, val, CLEN_SZ(val)) != -1);
}

static void evnt_add(struct Evnt **que, struct Evnt *node)
{
  assert(node != *que);
  
  if ((node->next = *que))
    node->next->prev = node;
  
  node->prev = NULL;
  *que = node;
}

static void evnt_del(struct Evnt **que, struct Evnt *node)
{
  if (node->prev)
    node->prev->next = node->next;
  else
  {
    assert(*que == node);
    *que = node->next;
  }

  if (node->next)
    node->next->prev = node->prev;
}

static void evnt__del_whatever(struct Evnt *evnt)
{
  if (0) { }
  else if (evnt->flag_q_accept)
    evnt_del(&q_accept, evnt);
  else if (evnt->flag_q_connect)
    evnt_del(&q_connect, evnt);
  else if (evnt->flag_q_recv)
    evnt_del(&q_recv, evnt);
  else if (evnt->flag_q_send_recv)
    evnt_del(&q_send_recv, evnt);
  else if (evnt->flag_q_none)
    evnt_del(&q_none, evnt);
  else
    ASSERT_NOT_REACHED();
}

static void COMPILE_ATTR_USED() evnt__add_whatever(struct Evnt *evnt)
{
  if (0) { }
  else if (evnt->flag_q_accept)
    evnt_add(&q_accept, evnt);
  else if (evnt->flag_q_connect)
    evnt_add(&q_connect, evnt);
  else if (evnt->flag_q_recv)
    evnt_add(&q_recv, evnt);
  else if (evnt->flag_q_send_recv)
    evnt_add(&q_send_recv, evnt);
  else if (evnt->flag_q_none)
    evnt_add(&q_none, evnt);
  else
    ASSERT_NOT_REACHED();
}

static unsigned int evnt__debug_num_1(struct Evnt *scan)
{
  unsigned int num = 0;
  
  while (scan)
  {
    struct Evnt *scan_next = scan->next;
    
    ++num;
    
    scan = scan_next;
  }

  return (num);
}

#if COMPILE_DEBUG
static struct Evnt **evnt__srch(struct Evnt **que, struct Evnt *evnt)
{
  struct Evnt **ret = que;

  while (*ret)
  {
    if (*ret == evnt)
      return (ret);
    
    ret = &(*ret)->next;
  }
  
  return (NULL);
}

static int evnt__valid(struct Evnt *evnt)
{
  int ret = 0;

  ASSERT(evnt_num_all());
  
  ASSERT((evnt->flag_q_connect + evnt->flag_q_accept + evnt->flag_q_recv +
          evnt->flag_q_send_recv + evnt->flag_q_none) == 1);

  if (evnt->flag_q_send_now)
  {
    struct Evnt **scan = &q_send_now;
    
    while (*scan && (*scan != evnt))
      scan = &(*scan)->s_next;
    ASSERT(*scan);
  }
  else
  {
    struct Evnt **scan = &q_send_now;
    
    while (*scan && (*scan != evnt))
      scan = &(*scan)->s_next;
    ASSERT(!*scan);
  }
  
  if (evnt->flag_q_closed)
  {
    struct Evnt **scan = &q_closed;
    
    while (*scan && (*scan != evnt))
      scan = &(*scan)->c_next;
    ASSERT(*scan);
  }
  else
  {
    struct Evnt **scan = &q_closed;
    
    while (*scan && (*scan != evnt))
      scan = &(*scan)->c_next;
    ASSERT(!*scan);
  }

  if (0) { }
  else   if (evnt->flag_q_accept)
  {
    ret = !!evnt__srch(&q_accept, evnt);
    assert(!(SOCKET_POLL_INDICATOR(evnt->ind)->events  & POLLOUT));
    assert(!(SOCKET_POLL_INDICATOR(evnt->ind)->revents & POLLOUT));
    ASSERT(!evnt->io_r && !evnt->io_w);
  }
  else   if (evnt->flag_q_connect)
  {
    ret = !!evnt__srch(&q_connect, evnt);
    assert(!(SOCKET_POLL_INDICATOR(evnt->ind)->events  & POLLIN));
    assert( (SOCKET_POLL_INDICATOR(evnt->ind)->events  & POLLOUT) ||
            evnt->tm_l_w);
    assert(!(SOCKET_POLL_INDICATOR(evnt->ind)->revents & POLLIN));
  }
  else   if (evnt->flag_q_send_recv)
  {
    ret = !!evnt__srch(&q_send_recv, evnt);
    assert( (SOCKET_POLL_INDICATOR(evnt->ind)->events  & POLLOUT) ||
            evnt->tm_l_w);
  }
  else   if (evnt->flag_q_recv)
  {
    ret = !!evnt__srch(&q_recv, evnt);
    assert(!(SOCKET_POLL_INDICATOR(evnt->ind)->events  & POLLOUT));
    assert(!(SOCKET_POLL_INDICATOR(evnt->ind)->revents & POLLOUT));
  }
  else   if (evnt->flag_q_none)
  {
    ret = !!evnt__srch(&q_none, evnt);
    assert(!(SOCKET_POLL_INDICATOR(evnt->ind)->events  & POLLIN));
    assert(!(SOCKET_POLL_INDICATOR(evnt->ind)->events  & POLLOUT));
    assert(!(SOCKET_POLL_INDICATOR(evnt->ind)->revents & POLLIN));
    assert(!(SOCKET_POLL_INDICATOR(evnt->ind)->revents & POLLOUT));
  }
  else
    ASSERT_NOT_REACHED();
  
  return (ret);
}

static unsigned int evnt__debug_num_all(void)
{
  unsigned int num = 0;
  
  num += evnt__debug_num_1(q_connect);
  num += evnt__debug_num_1(q_accept);  
  num += evnt__debug_num_1(q_recv);  
  num += evnt__debug_num_1(q_send_recv);  
  num += evnt__debug_num_1(q_none);  

  return (num);
}
#endif

int evnt_fd(struct Evnt *evnt)
{
  ASSERT(evnt__valid(evnt));
  return (SOCKET_POLL_INDICATOR(evnt->ind)->fd);
}

int evnt_cb_func_connect(struct Evnt *COMPILE_ATTR_UNUSED(evnt))
{
  return (TRUE);
}

struct Evnt *evnt_cb_func_accept(struct Evnt *COMPILE_ATTR_UNUSED(evnt),
                                 int COMPILE_ATTR_UNUSED(fd),
                                 struct sockaddr *COMPILE_ATTR_UNUSED(sa),
                                 socklen_t COMPILE_ATTR_UNUSED(len))
{
  return (NULL);
}

int evnt_cb_func_recv(struct Evnt *evnt)
{
  unsigned int ern = 0;
  int ret = evnt_recv(evnt, &ern);

  if (ret)
    return (TRUE);

  if ((ern == VSTR_TYPE_SC_READ_FD_ERR_EOF) && evnt->io_w->len)
    return (evnt_shutdown_r(evnt, TRUE));
  
  return (FALSE);
}

int evnt_cb_func_send(struct Evnt *evnt)
{
  int ret = -1;

  evnt_fd_set_cork(evnt, TRUE);
  ret = evnt_send(evnt);
  if (!evnt->io_w->len)
    evnt_fd_set_cork(evnt, FALSE);
  
  return (ret);
}

void evnt_cb_func_free(struct Evnt *evnt)
{
  MALLOC_CHECK_SCRUB_PTR(evnt, sizeof(struct Evnt));
  free(evnt);
}

void evnt_cb_func_F(struct Evnt *evnt)
{
  F(evnt);
}

int evnt_cb_func_shutdown_r(struct Evnt *evnt)
{
  vlg_dbg2(vlg, "SHUTDOWN CB from[$<sa:%p>]\n", EVNT_SA(evnt));
  
  if (!evnt_shutdown_r(evnt, FALSE))
    return (FALSE);

  /* called from outside read, and read'll never get called again ...
   * so quit if we have nothing to send */
  return (!!evnt->io_w->len);
}

static const struct Evnt_cbs evnt__evnt_cbs =
{
 evnt_cb_func_accept,    /* def */
 evnt_cb_func_connect,   /* def */

 evnt_cb_func_recv,      /* def */
 evnt_cb_func_send,      /* def */

 evnt_cb_func_F,         /* def */
 evnt_cb_func_shutdown_r /* def */
};

static int evnt_init(struct Evnt *evnt, int fd, Vstr_ref *ref,
                     struct Evnt *from_evnt)
{
  ASSERT(ref);
  
  evnt->flag_q_accept     = FALSE;
  evnt->flag_q_connect    = FALSE;
  evnt->flag_q_recv       = FALSE;
  evnt->flag_q_send_recv  = FALSE;
  evnt->flag_q_none       = FALSE;
  
  evnt->flag_q_send_now   = FALSE;
  evnt->flag_q_closed     = FALSE;

  evnt->flag_q_pkt_move   = FALSE;

  evnt->flag_io_nagle     = FALSE;
  evnt->flag_io_cork      = FALSE;

  evnt->flag_io_filter    = FALSE;
  
  evnt->flag_fully_acpt   = FALSE;
  
  evnt->flag_insta_close  = FALSE;
  
  evnt->io_r_shutdown     = FALSE;
  evnt->io_w_shutdown     = FALSE;
  
  evnt->flag_io_r_limited = FALSE;
  evnt->flag_io_w_limited = FALSE;
  
  evnt->flag_io_wonly_tm  = FALSE;
  
  evnt->prev_bytes_r     = 0;
  
  evnt->acct.req_put     = 0;
  evnt->acct.req_got     = 0;
  evnt->acct.bytes_r     = 0;
  evnt->acct.bytes_w     = 0;

  evnt->cbs              = &evnt__evnt_cbs;
  
  if (!(evnt->io_r = vstr_make_base(NULL)))
    goto make_vstr_fail;
  
  if (!(evnt->io_w = vstr_make_base(NULL)))
    goto make_vstr_fail;
  
  evnt->tm_o   = NULL;

  evnt->tm_l_r = NULL;
  evnt->tm_l_w = NULL;
  evnt->lims    = NULL;
  evnt->lim_num = 0;
  
  EVNT__COPY_TV(&evnt->ctime);
  EVNT__COPY_TV(&evnt->mtime);

  evnt->msecs_tm_mtime = 0;

  evnt_fd__set_coe(fd, TRUE);

  evnt->sa_ref = vstr_ref_add(ref);
  evnt->acpt_sa_ref = NULL;

  if (!(evnt->ind = evnt_poll->add(evnt, fd)))
    goto poll_add_fail;

  /* FIXME: need group settings */
  if (HAVE_SOCK_FLAGS_INHERIT && from_evnt &&
      (from_evnt->flag_io_nagle == evnt_opt_nagle))
    evnt->flag_io_nagle = evnt_opt_nagle;
  else if (HAVE_TCP_NODELAY_CONFIG || !evnt_opt_nagle)
  {
    evnt_fd__set_nodelay(fd, !evnt->flag_io_nagle);
    evnt->flag_io_nagle = evnt_opt_nagle;
  }

  if (!HAVE_SOCK_FLAGS_INHERIT || !from_evnt)
    evnt_fd__set_nonblock(fd, TRUE);

  return (TRUE);

 poll_add_fail:
  vstr_ref_del(evnt->sa_ref); evnt->sa_ref = NULL;
  vstr_free_base(evnt->io_w);
 make_vstr_fail:
  vstr_free_base(evnt->io_r);

  errno = ENOMEM;
  return (FALSE);
}

static void evnt__free1(struct Evnt *evnt)
{
  evnt_send_del(evnt);

  if (evnt->io_r && evnt->io_r->len)
    vlg_dbg2(vlg, "evnt__free1($<sa:%p>) io_r len = %zu\n",
             EVNT_SA(evnt), evnt->io_r->len);
  if (evnt->io_w && evnt->io_w->len)
    vlg_dbg2(vlg, "evnt__free1($<sa:%p>) io_w len = %zu\n",
             EVNT_SA(evnt), evnt->io_w->len);
  
  vstr_free_base(evnt->io_w); evnt->io_w = NULL;
  vstr_free_base(evnt->io_r); evnt->io_r = NULL;
  
  evnt_poll->del(evnt);
  evnt_limit_free(evnt);
}

static void evnt__free_tq(Timer_q_node *tm)
{
  if (tm)
  {
    timer_q_cntl_node(tm, TIMER_Q_CNTL_NODE_SET_DATA, NULL);
    timer_q_quick_del_node(tm);
  }
}

static void evnt__free2(Vstr_ref *sa, Vstr_ref *acpt_sa,
                        Timer_q_node *tm_o,
                        Timer_q_node *tm_l_r, Timer_q_node *tm_l_w)
{ /* post callbacks, evnt no longer exists */
  vstr_ref_del(sa);
  vstr_ref_del(acpt_sa);

  evnt__free_tq(tm_o);
  evnt__free_tq(tm_l_r);
  evnt__free_tq(tm_l_w);
}

static void evnt__free(struct Evnt *evnt)
{
  if (evnt)
  {
    Vstr_ref *sa = evnt->sa_ref;
    Vstr_ref *acpt_sa = evnt->acpt_sa_ref;
    Timer_q_node *tm_o  = evnt->tm_o;
    Timer_q_node *tm_l_r  = evnt->tm_l_r;
    Timer_q_node *tm_l_w  = evnt->tm_l_w;

    evnt__free1(evnt);

    ASSERT(evnt__num >= 1); /* in case they come back in via. the cb */
    --evnt__num;
    ASSERT(evnt__num == evnt__debug_num_all());

    evnt->cbs->cb_func_free(evnt);
    evnt__free2(sa, acpt_sa, tm_o, tm_l_r, tm_l_w);
  }
}

void evnt_free(struct Evnt *evnt)
{
  if (evnt)
  {
    evnt__del_whatever(evnt);
    evnt__free(evnt);
  }
}

static void evnt__close_now(struct Evnt *evnt)
{
  if (evnt->flag_q_closed)
    return;
  
  evnt_free(evnt);
}

static void evnt__uninit(struct Evnt *evnt)
{
  ASSERT((evnt->flag_q_connect + evnt->flag_q_accept + evnt->flag_q_recv +
          evnt->flag_q_send_recv + evnt->flag_q_none) == 0);

  evnt__free1(evnt);
  evnt__free2(evnt->sa_ref, evnt->acpt_sa_ref,
              evnt->tm_o, evnt->tm_l_r, evnt->tm_l_w);
}

static void evnt__fd_close_noerrno(int fd)
{
  int saved_errno = errno;
  close(fd);
  errno = saved_errno;
}

static int evnt__make_end(struct Evnt **que, struct Evnt *evnt, int flags)
{
  evnt_add(que, evnt);
  
  ++evnt__num;

  evnt_poll->wait_cntl_add(evnt, flags);

  ASSERT(evnt__valid(evnt));

  return (TRUE);
}

int evnt_make_con_ipv4(struct Evnt *evnt, const char *ipv4_string, short port)
{
  int fd = -1;
  socklen_t alloc_len = sizeof(struct sockaddr_in);
  Vstr_ref *ref = NULL;
  struct sockaddr_in *saddr = NULL;
  
  if ((fd = socket(PF_INET, SOCK_STREAM, 0)) == -1)
    goto sock_fail;

  EVNT__UPDATE_TV();

  if (!(ref = vstr_ref_make_malloc(alloc_len)))
    goto init_fail;
  saddr = ref->ptr;
  
  saddr->sin_family = AF_INET;
  saddr->sin_port = htons(port);
  saddr->sin_addr.s_addr = inet_addr(ipv4_string);

  if (!evnt_init(evnt, fd, ref, NULL))
    goto init_fail;
  evnt->flag_q_pkt_move = TRUE;
  
  ASSERT(port && (saddr->sin_addr.s_addr != htonl(INADDR_ANY)));
  
  if (connect(fd, EVNT_SA(evnt), alloc_len) == -1)
  {
    if (errno == EINPROGRESS)
    { /* The connection needs more time....*/
      vstr_ref_del(ref);
      evnt->flag_q_connect = TRUE;
      return (evnt__make_end(&q_connect, evnt, POLLOUT));
    }

    goto connect_fail;
  }
  
  vstr_ref_del(ref);
  evnt->flag_q_none = TRUE;
  return (evnt__make_end(&q_none, evnt, 0));
  
 connect_fail:
  evnt__uninit(evnt);
 init_fail:
  vstr_ref_del(ref);
  evnt__fd_close_noerrno(fd);
 sock_fail:
  return (FALSE);
}

int evnt_make_con_local(struct Evnt *evnt, const char *fname)
{
  int fd = -1;
  size_t len = strlen(fname) + 1;
  struct sockaddr_un tmp_sun;
  struct sockaddr_un *saddr = NULL;
  socklen_t alloc_len = 0;
  Vstr_ref *ref = NULL;

  tmp_sun.sun_path[0] = 0;
  alloc_len = SUN_LEN(&tmp_sun) + len;
  
  if ((fd = socket(PF_LOCAL, SOCK_STREAM, 0)) == -1)
    goto sock_fail;
  
  EVNT__UPDATE_TV();

  if (!(ref = vstr_ref_make_malloc(alloc_len)))
    goto init_fail;
  saddr = ref->ptr;
  
  saddr->sun_family = AF_LOCAL;
  memcpy(saddr->sun_path, fname, len);
  
  if (!evnt_init(evnt, fd, ref, NULL))
    goto init_fail;
  evnt->flag_q_pkt_move = TRUE;
  
  if (connect(fd, EVNT_SA(evnt), alloc_len) == -1)
  {
    if (errno == EINPROGRESS)
    { /* The connection needs more time....*/
      vstr_ref_del(ref);
      evnt->flag_q_connect = TRUE;
      return (evnt__make_end(&q_connect, evnt, POLLOUT));
    }
    
    goto connect_fail;
  }

  vstr_ref_del(ref);
  evnt->flag_q_none = TRUE;
  return (evnt__make_end(&q_none, evnt, 0));
  
 connect_fail:
  evnt__uninit(evnt);
 init_fail:
  vstr_ref_del(ref);
  evnt__fd_close_noerrno(fd);
 sock_fail:
  return (FALSE);
}

int evnt_make_acpt_ref(struct Evnt *evnt, int fd, Vstr_ref *sa)
{
  if (!evnt_init(evnt, fd, sa, NULL))
    return (FALSE);

  evnt->flag_q_recv = TRUE;
  return (evnt__make_end(&q_recv, evnt, POLLIN));
}

int evnt_make_acpt_dup(struct Evnt *evnt, int fd,
                       struct sockaddr *sa, socklen_t len)
{
  Vstr_ref *ref = vstr_ref_make_memdup(sa, len);
  int ret = FALSE;
  
  if (!ref)
  {
    errno = ENOMEM;
    return (FALSE);
  }
  
  ret = evnt_make_acpt_ref(evnt, fd, ref);
  vstr_ref_del(ref);
  return (ret);
}

static int evnt__make_bind_end(struct Evnt *evnt)
{
  vstr_free_base(evnt->io_r); evnt->io_r = NULL;
  vstr_free_base(evnt->io_w); evnt->io_w = NULL;
  
  evnt->flag_q_accept = TRUE;
  evnt__make_end(&q_accept, evnt, POLLIN);
  SOCKET_POLL_INDICATOR(evnt->ind)->revents = 0;
  return (TRUE);
}

int evnt_make_bind_ipv4(struct Evnt *evnt,
                        const char *acpt_addr, short server_port,
                        unsigned int listen_len, const char *cong)
{
  int fd = -1;
  socklen_t alloc_len = sizeof(struct sockaddr_in);
  Vstr_ref *ref = NULL;
  struct sockaddr_in *saddr = NULL;
  
  if ((fd = socket(PF_INET, SOCK_STREAM, 0)) == -1)
    VLG_WARN_GOTO(sock_fail, (vlg, "socket(): %m\n"));
  
  EVNT__UPDATE_TV();

  if (!(ref = vstr_ref_make_malloc(alloc_len)))
    VLG_WARNNOMEM_GOTO(init_fail, (vlg, "%s(): %m\n", __func__));
  saddr = ref->ptr;
  
  saddr->sin_family = AF_INET;

  saddr->sin_addr.s_addr = htonl(INADDR_ANY);
  if (acpt_addr && *acpt_addr) /* silent error becomes <any> */
    EVNT__RESOLVE_NAME(saddr, acpt_addr);
  if (saddr->sin_addr.s_addr == htonl(INADDR_ANY))
    acpt_addr = "any";
  
  saddr->sin_port = htons(server_port);

  if (!evnt_init(evnt, fd, ref, NULL))
    VLG_WARNNOMEM_GOTO(init_fail, (vlg, "%s(): %m\n", __func__));

  if (!evnt_fd__set_reuse(fd, TRUE))
    VLG_WARNNOMEM_GOTO(reuse_fail, (vlg, "%s(): %m\n", __func__));
  
  if (cong && !evnt_fd__set_congestion(fd, cong) && (errno != ENOPROTOOPT))
    VLG_WARN_GOTO(cong_fail,
                  (vlg, "setsockopt(TCP_CONGESTION, %s): %m\n", cong));
  
  if (bind(fd, EVNT_SA(evnt), alloc_len) == -1)
    VLG_WARN_GOTO(bind_fail,
                  (vlg, "bind(%s:%hd): %m\n", acpt_addr, server_port));

  if (!server_port)
    if (getsockname(fd, EVNT_SA(evnt), &alloc_len) == -1)
      VLG_WARN_GOTO(getsockname_fail, (vlg, "getsockname(): %m\n"));
  
  if (listen(fd, listen_len) == -1)
    VLG_WARN_GOTO(listen_fail, (vlg, "listen(%d): %m\n", listen_len));

  vstr_ref_del(ref);
  return (evnt__make_bind_end(evnt));
  
 listen_fail:
 getsockname_fail:
 bind_fail:
 cong_fail:
 reuse_fail:
  evnt__uninit(evnt);
 init_fail:
  vstr_ref_del(ref);
  evnt__fd_close_noerrno(fd);
 sock_fail:
  return (FALSE);
}

int evnt_make_bind_local(struct Evnt *evnt, const char *fname,
                         unsigned int listen_len, unsigned int local_perms)
{
  int fd = -1;
  int saved_errno = 0;
  size_t len = strlen(fname) + 1;
  struct sockaddr_un tmp_sun;
  struct sockaddr_un *saddr = NULL;
  socklen_t alloc_len = 0;
  Vstr_ref *ref = NULL;
  mode_t omask = 0;
  
  tmp_sun.sun_path[0] = 0;
  alloc_len = SUN_LEN(&tmp_sun) + len;
  
  if ((fd = socket(PF_LOCAL, SOCK_STREAM, 0)) == -1)
    goto sock_fail;
  
  EVNT__UPDATE_TV();

  if (!(ref = vstr_ref_make_malloc(alloc_len)))
    goto init_fail;
  saddr = ref->ptr;

  saddr->sun_family = AF_LOCAL;
  memcpy(saddr->sun_path, fname, len);

  if (!evnt_init(evnt, fd, ref, NULL))
    goto init_fail;

  if (unlink(fname) != -1)
    vlg_warn(vlg, "HAD to unlink(%s) for bind\n", fname);

  ASSERT(!local_perms || (local_perms & 0777));
  if (FALSE && local_perms) /* NOTE: umask() does not work! */
    omask = umask(local_perms);
  if (bind(fd, EVNT_SA(evnt), alloc_len) == -1)
    goto bind_fail;
  if (FALSE && local_perms)
    umask(omask);

  local_perms &= 0777;
  if (local_perms)
    if (chmod(fname, local_perms) == -1) /* NOTE: fchmod() does not work! */
      goto chmod_fail;
  
  if (listen(fd, listen_len) == -1)
    goto listen_fail;

  vstr_ref_del(ref);
  return (evnt__make_bind_end(evnt));
  
 bind_fail:
  saved_errno = errno;
  if (local_perms)
    umask(omask);
  vlg_warn(vlg, "bind(%s): %m\n", fname);
  errno = saved_errno;
 chmod_fail:
 listen_fail:
  evnt__uninit(evnt);
 init_fail:
  vstr_ref_del(ref);
  evnt__fd_close_noerrno(fd);
 sock_fail:
  return (FALSE);
}

int evnt_make_custom(struct Evnt *evnt, int fd, Vstr_ref *sa, int flags)
{
  static Vstr_ref dummy_sa = {vstr_ref_cb_free_nothing, NULL, 1};

  if (!sa)
    sa = &dummy_sa;
  
  EVNT__UPDATE_TV();

  if (!evnt_init(evnt, fd, sa, NULL))
  {
    evnt__fd_close_noerrno(fd);
    return (FALSE);
  }
  
  if (flags & POLLIN)
  {
    evnt->flag_q_recv = TRUE;
    return (evnt__make_end(&q_recv, evnt, POLLIN));
  }
  
  evnt->flag_q_none = TRUE;
  return (evnt__make_end(&q_none, evnt, 0));
}

void evnt_close(struct Evnt *evnt)
{
  if (!evnt)
    return;

  ASSERT(evnt__valid(evnt));

  if (evnt->flag_q_closed)
    return;

  /* can't close at this point or we'll race with:
   * socket_poll_add()/socket_poll_del() when using _DIRECT mapping */
  
  /* queue for deletion ... as the bt might still be using the ptr */
  evnt->flag_q_closed = TRUE;
  evnt->c_next = q_closed;
  q_closed = evnt;
  
  ASSERT(evnt__valid(evnt));
}

int evnt_limit_add(struct Evnt *evnt, Vstr_ref *ref)
{
  Vstr_ref **refs = evnt->lims;
  unsigned int lim_num = evnt->lim_num + 1;
  struct Evnt_limit *lim = ref->ptr;

  ASSERT((!evnt->lims && (lim_num == 1)) ||
         ( evnt->lims && (lim_num >= 2)));
    
  evnt->flag_io_r_limited |= !!lim->io_r_max;
  evnt->flag_io_w_limited |= !!lim->io_w_max;
  
  if (lim_num == 1)
  {
    if (!(evnt->lims = MK(sizeof(Vstr_ref *))))
      return (FALSE);
  }
  else if (!MV(evnt->lims, refs, sizeof(Vstr_ref *) * lim_num))
    return (FALSE);
  
  evnt->lims[evnt->lim_num] = vstr_ref_add(ref);
  evnt->lim_num = lim_num;

  return (TRUE);
}

int evnt_limit_dup(struct Evnt *evnt, const struct Evnt_limit *lim)
{
  Vstr_ref *ref = vstr_ref_make_memdup(lim, sizeof(struct Evnt_limit));
  int ret = FALSE;
  
  if (!ref)
    return (FALSE);

  ret = evnt_limit_add(evnt, ref);
  vstr_ref_del(ref);
  
  return (ret);
}

void evnt_limit_chg(struct Evnt *evnt, unsigned int scan, Vstr_ref *ref)
{
  Vstr_ref *tmp = NULL;
  
  ASSERT(evnt->lim_num > scan);
  tmp = evnt->lims[scan];

  if (ref)
  {
    struct Evnt_limit *lim = ref->ptr;

    evnt->flag_io_r_limited |= !!lim->io_r_max;
    evnt->flag_io_w_limited |= !!lim->io_w_max;
  
    ref = vstr_ref_add(ref);
  }

  evnt->lims[scan] = ref;
  vstr_ref_del(tmp);
}

void evnt_limit_alt(struct Evnt *evnt, unsigned int scan,
                    const struct Evnt_limit *nlim)
{
  Vstr_ref *ref = NULL;
  struct Evnt_limit *lim = NULL;
  
  ASSERT(evnt->lim_num > scan);
  ref = evnt->lims[scan];
  ASSERT(ref);
  ASSERT(ref->ref == 1); /* should be the only owner of this data,
                          * if we are changing it */

  lim = ref->ptr;
  
  evnt->flag_io_r_limited |= !!lim->io_r_max;
  evnt->flag_io_w_limited |= !!lim->io_w_max;

  lim->io_r_max = nlim->io_r_max;
  lim->io_w_max = nlim->io_w_max;

  if (lim->io_r_cur > lim->io_r_max)
    lim->io_r_cur = lim->io_r_max;
  
  if (lim->io_w_cur > lim->io_w_max)
    lim->io_w_cur = lim->io_w_max;
}

void evnt_limit_free(struct Evnt *evnt)
{
  unsigned int scan = 0;

  while (scan < evnt->lim_num)
    vstr_ref_del(evnt->lims[scan++]);
  ASSERT(scan == evnt->lim_num);

  F(evnt->lims);
  evnt->lims    = NULL;
  evnt->lim_num = 0;
}

static void evnt__limit_tm_chk(const struct timeval *tv, struct timeval *ltv,
                               unsigned long *cur, unsigned long max)
{
  struct timeval tv_end[1];
  struct timeval tv_reset[1];

  *tv_end   = *ltv; TIMER_Q_TIMEVAL_ADD_SECS(tv_end,   1, 0);
  *tv_reset = *ltv; TIMER_Q_TIMEVAL_ADD_SECS(tv_reset, 3, 0);

  if (!ltv->tv_sec)
  {
    *cur = max;
    return;
  }

  /* if it's been more than a second ... reset */
  if (TIMER_Q_TIMEVAL_CMP(tv, tv_end) > 0)
  {
    if (TIMER_Q_TIMEVAL_CMP(tv, tv_reset) < 0)
      ++ltv->tv_sec; /* try and be nice */
    else
    { /* if it's been more than 3 seconds, just restart */
      ltv->tv_sec  = 0;
      ltv->tv_usec = 0;
    }
    
    *cur = max;
  }
}

static void evnt__limit_chk(struct Evnt *evnt)
{
  struct timeval tv[1];
  unsigned int scan = 0;
  
  EVNT__COPY_TV(tv);
  
  evnt->flag_io_r_limited = FALSE; /* blank and reset */
  evnt->flag_io_w_limited = FALSE;
  
  while (scan < evnt->lim_num)
  {
    if (evnt->lims[scan])
    {
      struct Evnt_limit *lim = evnt->lims[scan]->ptr;

      evnt->flag_io_r_limited |= !!lim->io_r_max;
      evnt->flag_io_w_limited |= !!lim->io_w_max;
  
      if (evnt->flag_io_r_limited)
      {
        vlg_dbg2(vlg, "limit chk r beg (%'lu <= %'lu) @%lu:%lu\n",
                 lim->io_r_cur, lim->io_r_max,
                 lim->io_r_tm.tv_sec, lim->io_r_tm.tv_usec);
        evnt__limit_tm_chk(tv, &lim->io_r_tm, &lim->io_r_cur, lim->io_r_max);
        vlg_dbg2(vlg, "limit chk r beg (%'lu <= %'lu) @%lu:%lu\n",
                 lim->io_r_cur, lim->io_r_max,
                 lim->io_r_tm.tv_sec, lim->io_r_tm.tv_usec);
      }
      
      if (evnt->flag_io_w_limited)
      {
        vlg_dbg2(vlg, "limit chk w beg (%'lu <= %'lu) @%lu:%lu\n",
                 lim->io_w_cur, lim->io_w_max,
                 lim->io_w_tm.tv_sec, lim->io_w_tm.tv_usec);
        evnt__limit_tm_chk(tv, &lim->io_w_tm, &lim->io_w_cur, lim->io_w_max);
        vlg_dbg2(vlg, "limit chk w end (%'lu <= %'lu) @%lu:%lu\n",
                 lim->io_w_cur, lim->io_w_max,
                 lim->io_w_tm.tv_sec, lim->io_w_tm.tv_usec);
      }
    }
    
    ++scan;
  }  
  ASSERT(scan == evnt->lim_num);
}

static struct Evnt_limit *evnt_limit_r(struct Evnt *evnt, unsigned long sz)
{
  struct Evnt_limit *ret = NULL;
  unsigned int scan = 0;
  
  if (!evnt->flag_io_r_limited)
    return (NULL);

  evnt__limit_chk(evnt);

  while (scan < evnt->lim_num)
  {
    if (evnt->lims[scan])
    {
      struct Evnt_limit *lim = evnt->lims[scan]->ptr;

      if (lim->io_r_max && (!ret || (ret->io_r_cur > lim->io_r_cur)))
        ret = lim;
    }
    
    ++scan;
  }
  ASSERT(scan == evnt->lim_num);

  if (ret)
    vlg_dbg2(vlg, "limit io_r(%'lu <= %'lu)\n", ret->io_r_cur, sz);

  if (ret && (ret->io_r_cur > sz))
    ret = NULL;

  return (ret);
}

static struct Evnt_limit *evnt_limit_w(struct Evnt *evnt, unsigned long sz)
{
  struct Evnt_limit *ret = NULL;
  unsigned int scan = 0;

  if (!evnt->flag_io_w_limited)
    return (NULL);
  
  evnt__limit_chk(evnt);

  while (scan < evnt->lim_num)
  {
    if (evnt->lims[scan])
    {
      struct Evnt_limit *lim = evnt->lims[scan]->ptr;

      if (lim->io_w_max && (!ret || (ret->io_w_cur > lim->io_w_cur)))
        ret = lim;
    }
    
    ++scan;
  }
  ASSERT(scan == evnt->lim_num);
  
  if (ret)
    vlg_dbg2(vlg, "limit io_w(%'lu <= %'lu)\n", ret->io_w_cur, sz);

  if (ret && (ret->io_w_cur > sz))
    ret = NULL;

  return (ret);
}

static Timer_q_base *evnt__timeout_lim_r_1  = NULL; /* read/recv/accept */
static Timer_q_base *evnt__timeout_lim_r_10 = NULL;
static Timer_q_base *evnt__timeout_lim_w_1  = NULL; /* write/send/connect */
static Timer_q_base *evnt__timeout_lim_w_10 = NULL;

static void evnt__timer_cb_lim_r(int type, void *data)
{
  struct Evnt *evnt = data;

  if (!evnt) /* deleted */
    return;
  
  ASSERT(evnt__valid(evnt));
  
  if (type == TIMER_Q_TYPE_CALL_RUN_ALL)
    return;

  evnt->tm_l_r = NULL;

  if (evnt->io_r_shutdown)
    return;
  
  evnt_poll->wait_cntl_add(evnt, POLLIN);
  
  if (type == TIMER_Q_TYPE_CALL_DEL)
    return;

  if (evnt->flag_q_accept)
  {
    assert(FALSE);
  }
  else if (!evnt->cbs->cb_func_recv(evnt))
    evnt_close(evnt);
}

static int evnt_limit_timeout_r(struct Evnt *evnt, struct Evnt_limit *lim)
{
  struct timeval tv[1];
  unsigned long msecs = 0;

  if (evnt->tm_l_r || !lim || lim->io_r_cur)
    return (TRUE);

  EVNT__COPY_TV(tv);
  msecs = timer_q_timeval_udiff_msecs(tv, &lim->io_r_tm);

  if (msecs < 1000)
    msecs = 1000 - msecs;
  else
    msecs = 0;
  vlg_dbg2(vlg, "timeout_r_make($<sa:%p>, %lu)\n", EVNT_SA(evnt), msecs);
  
  if (msecs <= 100)
  {
    TIMER_Q_TIMEVAL_ADD_SECS(tv, 0, 100 * 1000);
    evnt->tm_l_r = timer_q_add_node(evnt__timeout_lim_r_1, evnt, tv,
                                    TIMER_Q_FLAG_NODE_DEFAULT);
  }
  else
  {
    TIMER_Q_TIMEVAL_ADD_SECS(tv, 1,          0);
    evnt->tm_l_r = timer_q_add_node(evnt__timeout_lim_r_10, evnt, tv,
                                    TIMER_Q_FLAG_NODE_DEFAULT);
  }
    
  evnt_poll->wait_cntl_del(evnt, POLLIN);

  return (!!evnt->tm_l_r);
}

static void evnt__timer_cb_lim_w(int type, void *data)
{
  struct Evnt *evnt = data;

  if (!evnt) /* deleted */
    return;
  
  ASSERT(evnt__valid(evnt));
  
  if (type == TIMER_Q_TYPE_CALL_RUN_ALL)
    return;

  evnt->tm_l_w = NULL;

  if (evnt->io_w_shutdown)
    return;
  
  if (evnt->flag_q_send_recv)
  {
    evnt_poll->wait_cntl_add(evnt, POLLOUT);
    SOCKET_POLL_INDICATOR(evnt->ind)->revents |= POLLOUT;
  }
  
  if (type == TIMER_Q_TYPE_CALL_DEL)
    return;

  if (evnt->flag_q_connect)
  {
    assert(FALSE);
  }
  else if (!evnt->cbs->cb_func_send(evnt))
    evnt_close(evnt);
}

static int evnt_limit_timeout_w(struct Evnt *evnt, struct Evnt_limit *lim)
{
  struct timeval tv[1];
  unsigned long msecs = 0;
  
  if (evnt->tm_l_w || !lim || lim->io_w_cur)
    return (TRUE);

  EVNT__COPY_TV(tv);
  msecs = timer_q_timeval_udiff_msecs(tv, &lim->io_w_tm);

  if (msecs < 1000)
    msecs = 1000 - msecs;
  else
    msecs = 0;
  vlg_dbg2(vlg, "timeout_w_make($<sa:%p>, %lu)\n", EVNT_SA(evnt), msecs);
  
  if (msecs <= 100)
  {
    TIMER_Q_TIMEVAL_ADD_SECS(tv, 0, 100 * 1000);
    evnt->tm_l_w = timer_q_add_node(evnt__timeout_lim_w_1, evnt, tv,
                                    TIMER_Q_FLAG_NODE_DEFAULT);
  }
  else
  {
    TIMER_Q_TIMEVAL_ADD_SECS(tv, 1,          0);
    evnt->tm_l_w = timer_q_add_node(evnt__timeout_lim_w_10, evnt, tv,
                                    TIMER_Q_FLAG_NODE_DEFAULT);
  }
    
  evnt_poll->wait_cntl_del(evnt, POLLOUT);

  return (!!evnt->tm_l_w);
}

/* takes limit values into account as well */
static void evnt__acct_r(struct Evnt *evnt, size_t bytes)
{
  unsigned int scan = 0;
  
  while (scan < evnt->lim_num)
  {
    if (evnt->lims[scan])
    {
      struct Evnt_limit *lim = evnt->lims[scan]->ptr;

      if (lim->io_r_max)
      {
        if (!lim->io_r_tm.tv_sec)
        {
          EVNT__COPY_TV(&lim->io_r_tm.tv_sec);
          ASSERT(lim->io_r_cur == lim->io_r_max);
        }

        /* must be at least this small, or we screwed up limiting */
        ASSERT(lim->io_r_cur >= bytes);
        lim->io_r_cur -= bytes;
      }
    }
    
    ++scan;
  }
  ASSERT(scan == evnt->lim_num);

  evnt->acct.bytes_r += bytes;
}

static void evnt__acct_w(struct Evnt *evnt, size_t bytes)
{
  unsigned int scan = 0;
  
  while (scan < evnt->lim_num)
  {
    if (evnt->lims[scan])
    {
      struct Evnt_limit *lim = evnt->lims[scan]->ptr;
      
      if (lim->io_w_max)
      {
        if (!lim->io_w_tm.tv_sec)
        {
          EVNT__COPY_TV(&lim->io_w_tm.tv_sec);
          ASSERT(lim->io_w_cur == lim->io_w_max);
        }

        /* must be at least this small, or we screwed up limiting */
        ASSERT(lim->io_w_cur >= bytes);
        lim->io_w_cur -= bytes;
      }
    }

    ++scan;
  }
  ASSERT(scan == evnt->lim_num);
  
  evnt->acct.bytes_w += bytes;
}

void evnt_pkt_wait_r(struct Evnt *evnt)
{
  ASSERT(evnt__valid(evnt));

  if (evnt->flag_q_none)
  {
    ASSERT(evnt->acct.req_put >= evnt->acct.req_got);
    evnt_del(&q_none, evnt); evnt->flag_q_none = FALSE;
    evnt_add(&q_recv, evnt); evnt->flag_q_recv = TRUE;
    evnt_poll->wait_cntl_add(evnt, POLLIN);
  }

  ASSERT(evnt__valid(evnt));
}

void evnt_put_pkt(struct Evnt *evnt)
{
  if (evnt->flag_q_pkt_move)
    evnt_pkt_wait_r(evnt);
  
  ++evnt->acct.req_put;
  
  ASSERT(evnt__valid(evnt));
}

void evnt_got_pkt(struct Evnt *evnt)
{
  ASSERT(evnt__valid(evnt));
  
  ++evnt->acct.req_got;
  
  if (evnt->flag_q_pkt_move &&
      !evnt->flag_q_send_recv && (evnt->acct.req_put == evnt->acct.req_got))
  {
    ASSERT(evnt->acct.req_put >= evnt->acct.req_got);
    evnt_del(&q_recv, evnt), evnt->flag_q_recv = FALSE;
    evnt_add(&q_none, evnt), evnt->flag_q_none = TRUE;
    evnt_poll->wait_cntl_del(evnt, POLLIN);
  }
  
  ASSERT(evnt__valid(evnt));
}

static int evnt__call_send(struct Evnt *evnt, unsigned int *ern)
{
  size_t tmp = evnt->io_w->len;
  int fd = evnt_fd(evnt);
  struct Evnt_limit *lim = NULL;

  if (!(lim = evnt_limit_w(evnt, evnt->io_w->len)))
  {
    if (!vstr_sc_write_fd(evnt->io_w, 1, tmp, fd, ern) && (errno != EAGAIN))
      return (FALSE);
  }
  else if (lim->io_w_cur)
  {
    if (!vstr_sc_write_fd(evnt->io_w, 1, lim->io_w_cur, fd, ern) &&
        (errno != EAGAIN))
      return (FALSE);
  }

  tmp -= evnt->io_w->len;
  vlg_dbg3(vlg, "write($<sa:%p>) = %zu\n", EVNT_SA(evnt), tmp);
  
  evnt__acct_w(evnt, tmp);
  if (!evnt_limit_timeout_w(evnt, lim))
  {
    errno = ENOMEM, *ern = VSTR_TYPE_SC_WRITE_FD_ERR_MEM;
    return (FALSE);
  }
  
  return (TRUE);
}

int evnt_send_add(struct Evnt *evnt, int force_q, size_t max_sz)
{
  ASSERT(evnt__valid(evnt));
  
  vlg_dbg3(vlg, "q now = %u, q send recv = %u, force = %u\n",
           evnt->flag_q_send_now, evnt->flag_q_send_recv, force_q);
  
  if (!evnt->flag_q_send_recv && (evnt->io_w->len > max_sz))
  {
    if (!evnt__call_send(evnt, NULL))
    {
      ASSERT(evnt__valid(evnt));
      return (FALSE);
    }
    if (!evnt->io_w->len && !force_q)
    {
      ASSERT(evnt__valid(evnt));
      return (TRUE);
    }
  }

  /* already on send_q -- or already polling (and not forcing) */
  if (evnt->flag_q_send_now || evnt->tm_l_w ||
      (evnt->flag_q_send_recv && !force_q))
  {
    ASSERT(evnt__valid(evnt));
    return (TRUE);
  }
  
  evnt->s_next = q_send_now;
  q_send_now = evnt;
  evnt->flag_q_send_now = TRUE;
  
  ASSERT(evnt__valid(evnt));
  
  return (TRUE);
}

/* if a connection is on the send now q, then remove them ... this is only
 * done when the client gets killed, so it doesn't matter if it's slow */
void evnt_send_del(struct Evnt *evnt)
{
  struct Evnt **scan = &q_send_now;
  
  if (!evnt->flag_q_send_now)
    return;
  
  while (*scan && (*scan != evnt))
    scan = &(*scan)->s_next;
  
  ASSERT(*scan);
  
  *scan = evnt->s_next;

  evnt->flag_q_send_now = FALSE;
}

int evnt_shutdown_r(struct Evnt *evnt, int got_eof)
{
  ASSERT(evnt__valid(evnt));
  
  if (evnt->io_r_shutdown || evnt->io_w_shutdown)
    return (FALSE);
  
  evnt_poll->wait_cntl_del(evnt, POLLIN);
  
  vlg_dbg2(vlg, "shutdown(SHUT_RD, %d) from[$<sa:%p>]\n",
           got_eof, EVNT_SA(evnt));

  if (!got_eof && (shutdown(evnt_fd(evnt), SHUT_RD) == -1))
  {
    if (errno != ENOTCONN)
      vlg_warn(vlg, "shutdown(SHUT_RD): %m\n");
    return (FALSE);
  }
  
  evnt->io_r_shutdown = TRUE;

  ASSERT(evnt__valid(evnt));

  return (TRUE);
}

static void evnt__send_fin(struct Evnt *evnt)
{
  if (0)
  { /* nothing */ }
  else if ( evnt->flag_q_send_recv && !evnt->io_w->len)
  {
    evnt_del(&q_send_recv, evnt); evnt->flag_q_send_recv = FALSE;
    if (evnt->flag_q_pkt_move && (evnt->acct.req_put == evnt->acct.req_got))
    {
      evnt_add(&q_none, evnt); evnt->flag_q_none = TRUE;
      evnt_poll->wait_cntl_del(evnt, POLLIN | POLLOUT);
    }
    else
    {
      evnt_add(&q_recv, evnt); evnt->flag_q_recv = TRUE;
      evnt_poll->wait_cntl_del(evnt, POLLOUT);
    }
  }
  else if (!evnt->flag_q_send_recv &&  evnt->io_w->len)
  {
    int pflags = evnt->tm_l_w ? 0 : POLLOUT;
    ASSERT(evnt->flag_q_none || evnt->flag_q_recv);
    if (evnt->flag_q_none)
      evnt_del(&q_none, evnt), evnt->flag_q_none = FALSE;
    else
      evnt_del(&q_recv, evnt), evnt->flag_q_recv = FALSE;
    evnt_add(&q_send_recv, evnt); evnt->flag_q_send_recv = TRUE;
    if (!evnt->io_r_shutdown && !evnt->tm_l_r) pflags |= POLLIN;
    if (!pflags)
      ++evnt__scan_ready_moved_send_zero_fds;
    evnt_poll->wait_cntl_add(evnt, pflags);
  }
}

int evnt_shutdown_w(struct Evnt *evnt)
{
  ASSERT(evnt__valid(evnt));

  vlg_dbg2(vlg, "shutdown(SHUT_WR) from[$<sa:%p>]\n", EVNT_SA(evnt));

  evnt_fd_set_cork(evnt, FALSE); /* eats data in 2.4.22-1.2199.4.legacy.npt */
  
  if (evnt->io_r_shutdown || evnt->io_w_shutdown)
    return (FALSE);
  
  if (shutdown(evnt_fd(evnt), SHUT_WR) == -1)
  {
    if (errno != ENOTCONN)
      vlg_warn(vlg, "shutdown(SHUT_WR): %m\n");
    return (FALSE);
  }
  evnt->io_w_shutdown = TRUE;

  vstr_del(evnt->io_w, 1, evnt->io_w->len);
  vstr_del(evnt->io_r, 1, evnt->io_r->len);
  
  evnt__send_fin(evnt);
  
  if (evnt->flag_q_recv)
    evnt_poll->wait_cntl_add(evnt, POLLIN);
  
  ASSERT(evnt__valid(evnt));

  return (TRUE);
}

int evnt_recv(struct Evnt *evnt, unsigned int *ern)
{
  Vstr_base *data = evnt->io_r;
  size_t tmp = evnt->io_r->len;
  unsigned int num_min = 2;
  unsigned int num_max = 6; /* ave. browser reqs are 500ish, ab is much less */
  struct Evnt_limit *lim = NULL;
  unsigned int buf_sz = 0;

  ASSERT(evnt__valid(evnt) && ern);

  /* default for HTTPD's buf size of 120 (128 - 8) */
  if (!vstr_cntl_conf(data->conf, VSTR_CNTL_CONF_GET_NUM_BUF_SZ, &buf_sz))
    buf_sz = 120;

  if (evnt->prev_bytes_r >= (buf_sz * 2))
  {  
    num_min =  8; /* 8 * 120 = 960 */
    num_max =  8;
  }
  if (evnt->prev_bytes_r >= (buf_sz * 8))
    num_max = 64; /* 64 * 120 = 7680 */

  if (!(lim = evnt_limit_r(evnt, num_max * buf_sz)))
    vstr_sc_read_iov_fd(data, data->len, evnt_fd(evnt), num_min, num_max, ern);
  else if (lim->io_r_cur)
    vstr_sc_read_len_fd(data, data->len, evnt_fd(evnt), lim->io_r_cur, ern);
  else /* pretend we read "something" ... but magicly got nothing, not EOF */
    *ern = VSTR_TYPE_SC_READ_FD_ERR_NONE;
  
  evnt->prev_bytes_r = (evnt->io_r->len - tmp);
  evnt__acct_r(evnt, evnt->prev_bytes_r);
  
  vlg_dbg3(vlg, "read($<sa:%p>) = %ju\n", EVNT_SA(evnt), evnt->prev_bytes_r);
  
  if (!evnt_limit_timeout_r(evnt, lim))
    errno = ENOMEM, *ern = VSTR_TYPE_SC_READ_FD_ERR_MEM;
    
  switch (*ern)
  {
    case VSTR_TYPE_SC_READ_FD_ERR_NONE:
      if (evnt->io_w_shutdown) /* doesn't count if we can't respond */
        vstr_del(data, 1, data->len);
      else
        EVNT__COPY_TV(&evnt->mtime);
      return (TRUE);

    case VSTR_TYPE_SC_READ_FD_ERR_MEM:
      vlg_warn(vlg, "%s\n", __func__);
      break;

    case VSTR_TYPE_SC_READ_FD_ERR_READ_ERRNO:
      if (errno == EAGAIN)
        return (TRUE);
      break;

    case VSTR_TYPE_SC_READ_FD_ERR_EOF:
      break;

    default: /* unknown */
      vlg_warn(vlg, "read_iov() = %d: %m\n", *ern);
  }
  
  return (FALSE);
}

int evnt_send(struct Evnt *evnt)
{
  unsigned int ern = 0;
  
  ASSERT(evnt__valid(evnt));

  if (!evnt__call_send(evnt, &ern))
    return (FALSE);

  EVNT__COPY_TV(&evnt->mtime);

  evnt__send_fin(evnt);
  
  ASSERT(evnt__valid(evnt));
  
  return (TRUE);
}

#ifndef HAVE_OFF64_T
# define sendfile64 sendfile
#endif

int evnt_sendfile(struct Evnt *evnt, int ffd,
                  uintmax_t *f_off, uintmax_t *f_len, unsigned int *ern)
{
  ssize_t ret = 0;
  off64_t tmp_off = *f_off;
  size_t  tmp_len = *f_len;
  struct Evnt_limit *lim = NULL;
  
  *ern = 0;
  
  ASSERT(evnt__valid(evnt));

  ASSERT(!evnt->io_w->len);

  if (*f_len > SSIZE_MAX)
    tmp_len =  SSIZE_MAX;
  
  if ((lim = evnt_limit_w(evnt, tmp_len)))
    tmp_len = lim->io_w_cur;
  
  if ((ret = sendfile64(evnt_fd(evnt), ffd, &tmp_off, tmp_len)) == -1)
  {
    if (errno == EAGAIN)
      return (TRUE);
    
    *ern = VSTR_TYPE_SC_READ_FD_ERR_READ_ERRNO;
    return (FALSE);
  }

  if (!ret && (!lim || lim->io_w_cur))
  {
    *ern = VSTR_TYPE_SC_READ_FD_ERR_EOF;
    return (FALSE);
  }
  
  *f_off = tmp_off;

  evnt__acct_w(evnt, ret);
  if (!evnt_limit_timeout_w(evnt, lim))
  {
    errno = ENOMEM, *ern = VSTR_TYPE_SC_WRITE_FD_ERR_MEM;
    return (FALSE);
  }
  
  EVNT__COPY_TV(&evnt->mtime);
  
  *f_len -= ret;

  return (TRUE);
}

int evnt_sc_read_send(struct Evnt *evnt, int fd, uintmax_t *len)
{
  Vstr_base *out = evnt->io_w;
  size_t orig_len = out->len;
  size_t tmp = 0;
  int ret = IO_OK;

  ASSERT(len && *len);

  if ((ret = io_get(out, fd)) == IO_FAIL)
    return (EVNT_IO_READ_ERR);

  if (ret == IO_EOF)
    return (EVNT_IO_READ_EOF);
    
  tmp = out->len - orig_len;

  if (tmp >= *len)
  { /* we might not be transfering to EOF, so reduce if needed */
    vstr_sc_reduce(out, 1, out->len, tmp - *len);
    ASSERT((out->len - orig_len) == *len);
    *len = 0;
    return (EVNT_IO_READ_FIN);
  }

  *len -= tmp;
  
  if (!evnt_send(evnt))
    return (EVNT_IO_SEND_ERR);
  
  return (EVNT_IO_OK);
}

int evnt_timeout_msecs(void)
{
  const struct timeval *tv = NULL;
  int msecs = -1;
  
  if (q_send_now)
    msecs = 0;
  else if ((tv = timer_q_first_timeval()))
  {
    long diff = 0;
    struct timeval now_timeval;

    EVNT__COPY_TV(&now_timeval);
  
    diff = timer_q_timeval_diff_msecs(tv, &now_timeval);
  
    if (diff > 0)
    {
      if (diff >= INT_MAX)
        msecs = INT_MAX - 1;
      else
        msecs = diff;
    }
    else
      msecs = 0;
  }

  vlg_dbg2(vlg, "get_timeout = %'d\n", msecs);
  
  return (msecs);
}

void evnt_scan_q_close(void)
{
  struct Evnt *scan = NULL;

  while ((scan = q_closed))
  {
    ASSERT(evnt__valid(scan));
    
    scan->flag_q_closed = FALSE;
    q_closed = scan->c_next;
    
    evnt_free(scan);
  }

  ASSERT(!q_closed);
}

/* if something goes queue all accept'ing events to be closed */
void evnt_acpt_close_all(void)
{
  struct Evnt *evnt = q_accept; /* struct Evnt *evnt = evnt_queue("accept"); */

  while (evnt)
  {
    evnt_close(evnt);

    evnt = evnt->next;
  }
}

void evnt_scan_fds(unsigned int ready, size_t max_sz)
{
  const int bad_poll_flags = (POLLERR | POLLHUP | POLLNVAL);
  struct Evnt *scan = NULL;

  EVNT__UPDATE_TV();
  
  scan = q_connect;
  while (scan && ready)
  {
    struct Evnt *scan_next = NULL;
    int done = FALSE;
    int revents = 0;

    ASSERT(evnt__valid(scan));
    
    if (!scan->flag_q_connect)
      break;
    
    revents = SOCKET_POLL_INDICATOR(scan->ind)->revents;
    SOCKET_POLL_INDICATOR(scan->ind)->revents = 0;
    
    if (scan->flag_q_closed)
    {
      done = !!revents;
      scan_next = scan->next;
      goto next_connect;
    }
    
    assert(!(revents & POLLIN));
    /* done as one so we get error code */
    if (revents & (POLLOUT|bad_poll_flags))
    {
      int ern = 0;
      socklen_t len = sizeof(int);
      int ret = 0;
      
      done = TRUE;
      
      ret = getsockopt(evnt_fd(scan), SOL_SOCKET, SO_ERROR, &ern, &len);
      if (ret == -1)
        vlg_err(vlg, EXIT_FAILURE, "getsockopt(SO_ERROR): %m\n");
      else if (ern)
      {
        errno = ern;
        vlg_warn(vlg, "connect(): %m\n");

        scan_next = scan->next;
        evnt__close_now(scan);
      }
      else
      {
        evnt_del(&q_connect, scan); scan->flag_q_connect = FALSE;
        evnt_add(&q_none,    scan); scan->flag_q_none    = TRUE;
        evnt_poll->wait_cntl_del(scan, POLLOUT);

        if (!scan->cbs->cb_func_connect(scan))
          evnt__close_now(scan);
      }
      goto next_connect;
    }
    ASSERT(!done);
    if (evnt_poll->direct_enabled()) break;

    scan_next = scan->next;
   next_connect:
    if (done)
      --ready;

    scan = scan_next;
  }

  scan = q_accept;
  while (scan && ready)
  { /* Papers have suggested that preferring read over accept is better
     * -- edge triggering needs to requeue on non failure */
    struct Evnt *scan_next = NULL;
    int done = FALSE;
    int revents = 0;

    ASSERT(evnt__valid(scan));
    
    if (!scan->flag_q_accept)
      break;
    
    revents = SOCKET_POLL_INDICATOR(scan->ind)->revents;
    SOCKET_POLL_INDICATOR(scan->ind)->revents = 0;
    
    if (scan->flag_q_closed)
    {
      done = !!revents;
      scan_next = scan->next;
      goto next_accept;
    }
    
    assert(!(revents & POLLOUT));
    if (!done && (revents & bad_poll_flags))
    { /* done first as it's an error with the accept fd, whereas accept
       * generates new fds */
      done = TRUE;
      scan_next = scan->next;
      evnt__close_now(scan);
      goto next_accept;
    }

    if (revents & POLLIN)
    {
      struct sockaddr_storage sstore[1];
      struct sockaddr *sa = (struct sockaddr *) sstore;
      socklen_t len = sizeof(struct sockaddr_storage);
      int fd = -1;
      struct Evnt *tmp = NULL;
      unsigned int acpt_num = 0;
      
      done = TRUE;

      /* ignore all accept() errors -- bad_poll_flags fixes here */
      /* FIXME: apache seems to assume certain errors are really bad and we
       * should just kill the listen socket and wait to die. But for instance.
       * we can't just kill the socket on EMFILE, as we might have hit our
       * resource limit */
      while ((revents & POLLIN) && (fd = accept(evnt_fd(scan), sa, &len)) != -1)
      {
        if (!(tmp = scan->cbs->cb_func_accept(scan, fd, sa, len)))
        {
          close(fd);
          scan_next = scan->next;
          goto next_accept;
        }

        if (!acpt_num) /* for the first one, update */
          EVNT__COPY_TV(&scan->mtime);
        
        if (!tmp->flag_q_closed)
        {
          ++ready; /* give a read event to this new event */
          tmp->flag_fully_acpt = TRUE;
        }
        assert(SOCKET_POLL_INDICATOR(tmp->ind)->events  == POLLIN);
        assert(SOCKET_POLL_INDICATOR(tmp->ind)->revents == POLLIN);
        assert(tmp == q_recv);
        
        if (++acpt_num >= evnt__accept_limit)
          break;
      }
      
      scan_next = scan->next;
      goto next_accept;
    }
    ASSERT(!done);
    if (evnt_poll->direct_enabled()) break;
    
    scan_next = scan->next;
      
   next_accept:
    if (done)
      --ready;

    scan = scan_next;
  }  

  evnt__scan_ready_moved_send_zero_fds = 0;
  scan = q_recv;
  while (scan && ready)
  {
    struct Evnt *scan_next = NULL;
    int done = FALSE;
    int revents = 0;
    
    ASSERT(evnt__valid(scan));

    if (!scan->flag_q_recv)
      break;
    
    revents = SOCKET_POLL_INDICATOR(scan->ind)->revents;
    SOCKET_POLL_INDICATOR(scan->ind)->revents = 0;
    
    if (scan->flag_q_closed)
    {
      done = !!revents;
      scan_next = scan->next;
      goto next_recv;
    }
    
    if (revents & POLLIN)
    {
      done = TRUE;
      if (!scan->cbs->cb_func_recv(scan))
      {
        scan_next = scan->next;
        evnt__close_now(scan);
        goto next_recv;
      }
    }

    if (!done && (revents & bad_poll_flags))
    {
      done = TRUE;
      if (scan->io_r_shutdown || scan->io_w_shutdown ||
          !scan->cbs->cb_func_shutdown_r(scan))
      {
        scan_next = scan->next;
        evnt__close_now(scan);
        goto next_recv;
      }
    }

    scan_next = scan->next;
    
   next_recv:
    if (!done && evnt_poll->direct_enabled()) break;

    if (done)
      --ready;
    
    scan = scan_next;
  }
  
  scan = q_send_recv;
  while (scan && ready)
  {
    struct Evnt *scan_next = NULL;
    int done = FALSE;
    int revents = 0;
    
    ASSERT(evnt__valid(scan));
    
    if (!scan->flag_q_send_recv)
      break;
    
    revents = SOCKET_POLL_INDICATOR(scan->ind)->revents;
    SOCKET_POLL_INDICATOR(scan->ind)->revents = 0;
    
    if (scan->flag_q_closed)
    {
      done = !!revents;
      scan_next = scan->next;
      goto next_send;
    }
    
    if (revents & POLLIN)
    {
      done = TRUE;
      if (!scan->cbs->cb_func_recv(scan))
      {
        scan_next = scan->next;
        evnt__close_now(scan);
        goto next_send;
      }
    }
    
    if (revents & POLLOUT)
    {
      done = TRUE; /* need groups so we can do direct send here */
      if (!evnt_send_add(scan, TRUE, max_sz))
      {
        scan_next = scan->next;
        evnt__close_now(scan);
        goto next_send;
      }
    }

    if (!done && (revents & bad_poll_flags))
    {
      done = TRUE;
      if (scan->io_r_shutdown || !scan->cbs->cb_func_shutdown_r(scan))
      {
        scan_next = scan->next;
        evnt__close_now(scan);
        goto next_send;
      }
    }

    scan_next = scan->next;

   next_send:
    if (!done && evnt__scan_ready_moved_send_zero_fds)
      --evnt__scan_ready_moved_send_zero_fds;      
    else
    {
      if (!done && evnt_poll->direct_enabled()) break;
      
      if (done)
        --ready;
    }
    
    scan = scan_next;
  }

  scan = q_none;
  while (scan && ready)
  {
    struct Evnt *scan_next = scan->next;
    int done = FALSE;

    ASSERT(evnt__valid(scan));
    
    if (!scan->flag_q_none)
      break;
    
    if (scan->flag_q_closed)
      goto next_none;

    if (SOCKET_POLL_INDICATOR(scan->ind)->revents)
    { /* POLLIN == EOF ? */
      /* FIXME: failure cb */
      done = TRUE;

      evnt__close_now(scan);
      goto next_none;
    }

    ASSERT(!done);
    if (evnt_poll->direct_enabled()) break;
    
   next_none:
    if (done)
      --ready;
    
    scan = scan_next;
  }

  if (q_closed)
    evnt_scan_q_close();
  else if (ready) /* FIXME: needs a different approach */
    vlg_warn(vlg, "ready = %d\n", ready);
}

void evnt_scan_send_fds(void)
{
  struct Evnt **scan = NULL;

  evnt_scan_q_close();

  scan = &q_send_now;
  while (*scan)
  {
    struct Evnt *tmp = *scan;

    tmp->flag_q_send_now = FALSE;
    *scan = tmp->s_next;
    if (!tmp->cbs->cb_func_send(tmp))
    {
      evnt__close_now(tmp);
      continue;
    }
    if (tmp == *scan) /* added back to q */
    {
      ASSERT(tmp->flag_q_send_now == TRUE);
      scan = &tmp->s_next;
    }
  }

  evnt_scan_q_close();
}

static void evnt__close_1(struct Evnt **root)
{
  struct Evnt *scan = *root;

  *root = NULL;
  
  while (scan)
  {
    struct Evnt *scan_next = scan->next;
    Vstr_ref *acpt_sa = scan->acpt_sa_ref;
    Vstr_ref *sa = scan->sa_ref;
    Timer_q_node *tm_o  = scan->tm_o;
    Timer_q_node *tm_l_r  = scan->tm_l_r;
    Timer_q_node *tm_l_w  = scan->tm_l_w;

    vstr_free_base(scan->io_w); scan->io_w = NULL;
    vstr_free_base(scan->io_r); scan->io_r = NULL;
  
    evnt_poll->del(scan);
    
    --evnt__num;
    scan->cbs->cb_func_free(scan);
    evnt__free2(sa, acpt_sa, tm_o, tm_l_r, tm_l_w);
    
    scan = scan_next;
  }
}

/* closes everything instantly... */
void evnt_close_all(void)
{
  q_send_now = NULL;
  q_closed   = NULL;

  evnt__close_1(&q_connect);
  evnt__close_1(&q_accept);
  evnt__close_1(&q_recv);
  evnt__close_1(&q_send_recv);
  evnt__close_1(&q_none);
  ASSERT(evnt__num == evnt__debug_num_all());
}

void evnt_out_dbg3(const char *prefix)
{
  if (vlg->out_dbg < 3)
    return;
  
  vlg_dbg3(vlg, "%s T=%u c=%u a=%u r=%u s=%u n=%u [SN=%u]\n",
           prefix, evnt_num_all(),
           evnt__debug_num_1(q_connect),
           evnt__debug_num_1(q_accept),
           evnt__debug_num_1(q_recv),
           evnt__debug_num_1(q_send_recv),
           evnt__debug_num_1(q_none),
           evnt__debug_num_1(q_send_now));
}

void evnt_stats_add(struct Evnt *dst, const struct Evnt *src)
{
  EVNT__COPY_TV(&dst->mtime);

  dst->acct.req_put += src->acct.req_put;
  dst->acct.req_got += src->acct.req_got;

  dst->acct.bytes_r += src->acct.bytes_r;
  dst->acct.bytes_w += src->acct.bytes_w;
}

unsigned int evnt_num_all(void)
{
  ASSERT(evnt__num == evnt__debug_num_all());
  return (evnt__num);
}

int evnt_waiting(void)
{
  return (q_connect || q_accept || q_recv || q_send_recv || q_send_now);
}

struct Evnt *evnt_find_least_used(void)
{
  struct Evnt *con     = NULL;
  struct Evnt *con_min = NULL;

  /*  Find a usable connection, tries to find the least used connection
   * preferring ones not blocking on send IO */
  if (!(con = q_none) &&
      !(con = q_recv) &&
      !(con = q_send_recv))
    return (NULL);
  
  /* FIXME: not optimal, only want to change after a certain level */
  con_min = con;
  while (con)
  {
    if (con_min->io_w->len > con->io_w->len)
      con_min = con;
    con = con->next;
  }

  return (con_min);
}

#define MATCH_Q_NAME(x)                         \
    if (CSTREQ(qname, #x ))                     \
      return ( q_ ## x )                        \

struct Evnt *evnt_queue(const char *qname)
{
  MATCH_Q_NAME(connect);
  MATCH_Q_NAME(accept);
  MATCH_Q_NAME(send_recv);
  MATCH_Q_NAME(recv);
  MATCH_Q_NAME(none);
  MATCH_Q_NAME(send_now);

  return (NULL);
}

void evnt_fd_set_nagle(struct Evnt *evnt, int val)
{
  ASSERT(evnt__valid(evnt));

  val = !!val;

  if (evnt->flag_io_nagle == val)
    return;
  
  if (!evnt_fd__set_nodelay(evnt_fd(evnt), !val))
    return;
  
  evnt->flag_io_nagle = val;
}

void evnt_fd_set_cork(struct Evnt *evnt, int val)
{ /* assume it can't work for set and fail for unset */
  ASSERT(evnt__valid(evnt));

  if (!USE_TCP_CORK)
    return;

  val = !!val;
  
  if (evnt->flag_io_cork == val)
    return;

  if (val) /* flags can't be combined ... stupid */
    evnt_fd_set_nagle(evnt, TRUE);

  if (!evnt_fd__set_cork(evnt_fd(evnt), val))
    return;
  
  evnt->flag_io_cork = val;
}

static void evnt__free_base_noerrno(Vstr_base *s1)
{
  int saved_errno = errno;
  vstr_free_base(s1);
  errno = saved_errno;
}

int evnt_fd_set_filter(struct Evnt *evnt, const char *fname)
{
  int fd = evnt_fd(evnt);
  Vstr_base *s1 = NULL;
  unsigned int ern = 0;

  if (!CONF_USE_SOCKET_FILTERS)
    return (TRUE);
  
  if (!(s1 = vstr_make_base(NULL)))
    VLG_WARNNOMEM_RET(FALSE, (vlg, "filter_attach0: %m\n"));

  vstr_sc_read_len_file(s1, 0, fname, 0, 0, &ern);

  if (ern &&
      !(((ern == VSTR_TYPE_SC_READ_FILE_ERR_OPEN_ERRNO) &&
         (errno == ENOENT)) ||
        ((ern == VSTR_TYPE_SC_READ_FILE_ERR_FSTAT_ERRNO) &&
         (errno == ENOSPC))))
  {
    evnt__free_base_noerrno(s1);
    VLG_WARN_RET(FALSE, (vlg, "filter_attach1(%s): %m\n", fname));
  }
  else if ((s1->len / sizeof(struct sock_filter)) > USHRT_MAX)
  {
    vstr_free_base(s1);  
    errno = E2BIG;
    VLG_WARN_RET(FALSE, (vlg, "filter_attach2(%s): %m\n", fname));
  }
  else if (!s1->len)
  {
    vstr_free_base(s1);  
    if (!evnt->flag_io_filter)
      vlg_warn(vlg, "filter_attach3(%s): Empty file\n", fname);
    else if (setsockopt(fd, SOL_SOCKET, SO_DETACH_FILTER, NULL, 0) == -1)
    {
      evnt__free_base_noerrno(s1);
      VLG_WARN_RET(FALSE, (vlg, "setsockopt(SOCKET, DETACH_FILTER, %s): %m\n",
                           fname));
    }
    
    evnt->flag_io_filter = FALSE;
    return (TRUE);
  }
  else
  {
    struct sock_fprog filter[1];
    socklen_t len = sizeof(filter);

    filter->len    = s1->len / sizeof(struct sock_filter);
    filter->filter = (void *)vstr_export_cstr_ptr(s1, 1, s1->len);
    
    if (!filter->filter)
      VLG_WARNNOMEM_RET(FALSE, (vlg, "filter_attach4: %m\n"));
  
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, filter, len) == -1)
    {
      evnt__free_base_noerrno(s1);
      VLG_WARN_RET(FALSE, (vlg,  "setsockopt(SOCKET, ATTACH_FILTER, %s): %m\n",
                           fname));
    }
  }

  evnt->flag_io_filter = TRUE;
  
  vstr_free_base(s1);

  return (TRUE);
}

static Timer_q_base *evnt__timeout_1   = NULL;
static Timer_q_base *evnt__timeout_10  = NULL;
static Timer_q_base *evnt__timeout_100 = NULL;

static Timer_q_node *evnt__timeout_mtime_make(struct Evnt *evnt,
                                              struct timeval *tv,
                                              unsigned long msecs)
{
  Timer_q_node *tm_o = NULL;

  vlg_dbg2(vlg, "mtime_make($<sa:%p>, %'lu)\n", EVNT_SA(evnt), msecs);
  
  if (0) { }
  else if (msecs >= ( 99 * 1000))
  {
    TIMER_Q_TIMEVAL_ADD_SECS(tv, 100, 0);
    tm_o = timer_q_add_node(evnt__timeout_100, evnt, tv,
                            TIMER_Q_FLAG_NODE_DEFAULT);
  }
  else if (msecs >= (  9 * 1000))
  {
    TIMER_Q_TIMEVAL_ADD_SECS(tv,  10, 0);
    tm_o = timer_q_add_node(evnt__timeout_10,  evnt, tv,
                            TIMER_Q_FLAG_NODE_DEFAULT);
  }
  else
  {
    TIMER_Q_TIMEVAL_ADD_SECS(tv,   1, 0);
    tm_o = timer_q_add_node(evnt__timeout_1,   evnt, tv,
                            TIMER_Q_FLAG_NODE_DEFAULT);
  }

  return (tm_o);
}

static void evnt__timer_cb_mtime(int type, void *data)
{
  struct Evnt *evnt = data;
  struct timeval tv[1];
  const struct timeval *evnt_tv;
  unsigned long diff = 0;

  if (!evnt) /* deleted */
    return;
  
  ASSERT(evnt__valid(evnt));
  
  if (type == TIMER_Q_TYPE_CALL_RUN_ALL)
    return;

  evnt->tm_o = NULL;
  
  if (type == TIMER_Q_TYPE_CALL_DEL)
    return;

  EVNT__COPY_TV(tv);

  evnt_tv = &evnt->mtime;
  if (evnt->flag_io_wonly_tm && !evnt->io_w->len)
    evnt_tv = tv;

  /* find out time elapsed */
  diff = timer_q_timeval_udiff_msecs(tv, evnt_tv);
  if (diff < evnt->msecs_tm_mtime)
    diff = evnt->msecs_tm_mtime - diff; /* seconds left until timeout */
  else
  {
    vlg_dbg2(vlg, "timeout from[$<sa:%p>] = (%'lu, %'lu)\n",
             EVNT_SA(evnt), diff, evnt->msecs_tm_mtime);
    if (evnt->flag_insta_close || !evnt_shutdown_w(evnt))
    {
      evnt_close(evnt);
      return;
    }

    /* FIXME: linger close time configurable? */
    EVNT__COPY_TV(&evnt->mtime);
    evnt->msecs_tm_mtime /= 2;
    diff = evnt->msecs_tm_mtime;
  }
  
  if (!(evnt->tm_o = evnt__timeout_mtime_make(evnt, tv, diff)))
  {
    errno = ENOMEM;
    vlg_warn(vlg, "%s: %m\n", "timer reinit");
    evnt_close(evnt);
  }
}

void evnt_timeout_init(void)
{
  int flags = TIMER_Q_FLAG_BASE_DEFAULT;
  
  ASSERT(!evnt__timeout_1);

  EVNT__UPDATE_TV();

  evnt__timeout_1   = timer_q_add_base(evnt__timer_cb_mtime, flags);
  evnt__timeout_10  = timer_q_add_base(evnt__timer_cb_mtime, flags);
  evnt__timeout_100 = timer_q_add_base(evnt__timer_cb_mtime, flags);

  if (!evnt__timeout_1 || !evnt__timeout_10 || !evnt__timeout_100)
    VLG_ERRNOMEM((vlg, EXIT_FAILURE, "timer init"));

  /* we always allocate limit timers, just easier that way ... */
  evnt__timeout_lim_r_1   = timer_q_add_base(evnt__timer_cb_lim_r, flags);
  evnt__timeout_lim_r_10  = timer_q_add_base(evnt__timer_cb_lim_r, flags);
  evnt__timeout_lim_w_1   = timer_q_add_base(evnt__timer_cb_lim_w, flags);
  evnt__timeout_lim_w_10  = timer_q_add_base(evnt__timer_cb_lim_w, flags);

  if (!evnt__timeout_lim_r_1 || !evnt__timeout_lim_r_10 ||
      !evnt__timeout_lim_w_1 || !evnt__timeout_lim_w_10)
    VLG_ERRNOMEM((vlg, EXIT_FAILURE, "timer init"));
}

void evnt_timeout_exit(void)
{
  ASSERT(evnt__timeout_1);
  
  timer_q_del_base(evnt__timeout_1);        evnt__timeout_1   = NULL;
  timer_q_del_base(evnt__timeout_10);       evnt__timeout_10  = NULL;
  timer_q_del_base(evnt__timeout_100);      evnt__timeout_100 = NULL;
  timer_q_del_base(evnt__timeout_lim_r_1);  evnt__timeout_lim_r_1 = NULL;
  timer_q_del_base(evnt__timeout_lim_r_10); evnt__timeout_lim_r_10 = NULL;
  timer_q_del_base(evnt__timeout_lim_w_1);  evnt__timeout_lim_w_1 = NULL;
  timer_q_del_base(evnt__timeout_lim_w_10); evnt__timeout_lim_w_10 = NULL;
}

int evnt_sc_timeout_via_mtime(struct Evnt *evnt, unsigned long msecs)
{
  struct timeval tv[1];

  if (!(evnt->msecs_tm_mtime = msecs))
    return (TRUE);
  
  EVNT__COPY_TV(tv);
  
  if (!(evnt->tm_o = evnt__timeout_mtime_make(evnt, tv, msecs)))
    return (FALSE);

  return (TRUE);
}

static void evnt__timed_updates(const struct timeval *tv)
{
  static time_t last_sec = 0;

  if (!last_sec || (difftime(tv->tv_sec, last_sec) > (5 * 60)))
  { /* do updates about once every 5 minutes (don't use timer_q as we don't
     * want to be woken for this). */
    struct stat buf[1];
    
    last_sec = tv->tv_sec;

    /* Maybe have Libc stat/update /etc/localtime data.
     * Note that if we are in a chroot() without one don't let
     * GLibc fuck it up */
    if (!stat ("/etc/localtime", buf))
      tzset();
  }
}

void evnt_sc_main_loop(size_t max_sz)
{
  int ready = 0;
  struct timeval tv[1];

  EVNT__UPDATE_TV();
  ready = evnt_poll->poll();
  if ((ready == -1) && (errno != EINTR))
    vlg_err(vlg, EXIT_FAILURE, "%s: %m\n", "poll");
  if (ready == -1)
    return;
  
  evnt_out_dbg3("1");
  evnt_scan_fds(ready, max_sz);
  evnt_out_dbg3("2");
  evnt_scan_send_fds();
  evnt_out_dbg3("3");

  EVNT__UPDATE_TV();
  EVNT__COPY_TV(tv);
  timer_q_run_norm(tv);

  evnt__timed_updates(tv);
  
  evnt_out_dbg3("4");
  evnt_scan_send_fds();
  evnt_out_dbg3("5");
}

time_t evnt_sc_time(void)
{
  time_t ret = -1;
  
  if (!CONF_GETTIMEOFDAY_TIME)
    ret = time(NULL);
  else
  {
    struct timeval tv[1];
    
    EVNT__COPY_TV(tv);    
    ret = tv->tv_sec;
  }

  return (ret);
}

void evnt_sc_serv_cb_func_acpt_free(struct Evnt *evnt)
{
  struct Acpt_listener *acpt_listener = (struct Acpt_listener *)evnt;
  struct Acpt_data *acpt_data = acpt_listener->ref->ptr;

  evnt_vlg_stats_info(acpt_listener->evnt, "ACCEPT FREE");

  acpt_data->evnt = NULL;
  vstr_ref_del(acpt_listener->ref);
  vstr_ref_del(acpt_listener->def_policy);
  
  F(acpt_listener);
}

static void evnt__sc_serv_make_acpt_data_cb(Vstr_ref *ref)
{
  struct Acpt_data *ptr = NULL;
  
  if (!ref)
    return;

  ptr = ref->ptr;
  vstr_ref_del(ptr->sa);
  F(ptr);
  free(ref);
}

struct Evnt *evnt_sc_serv_make_bind_ipv4(const char *acpt_addr,
                                         unsigned short acpt_port,
                                         unsigned int q_listen_len,
                                         unsigned int max_connections,
                                         unsigned int defer_accept,
                                         const char *acpt_filter_file,
                                         const char *acpt_cong)
{
  struct sockaddr_in *sinv4 = NULL;
  Acpt_listener *acpt_listener = NULL;
  Acpt_data *acpt_data = NULL;
  Vstr_ref *ref = NULL;
  
  if (!(acpt_listener = MK(sizeof(Acpt_listener))))
    VLG_ERRNOMEM((vlg, EXIT_FAILURE, "make_bind(%s, %hu): %m\n",
                  acpt_addr, acpt_port));
  acpt_listener->max_connections = max_connections;
  acpt_listener->def_policy = NULL;
  
  if (!(acpt_data = MK(sizeof(Acpt_data))))
    VLG_ERRNOMEM((vlg, EXIT_FAILURE, "make_bind(%s, %hu): %m\n",
                  acpt_addr, acpt_port));
  acpt_data->evnt = NULL;
  acpt_data->sa   = NULL;

  if (!(ref = vstr_ref_make_ptr(acpt_data, evnt__sc_serv_make_acpt_data_cb)))
    VLG_ERRNOMEM((vlg, EXIT_FAILURE, "make_bind(%s, %hu): %m\n",
                  acpt_addr, acpt_port));
  acpt_listener->ref = ref;
  
  if (!evnt_make_bind_ipv4(acpt_listener->evnt, acpt_addr, acpt_port,
                           q_listen_len, acpt_cong))
    vlg_err(vlg, 2, "make_bind(%s, %hd, %d, %s): Failed!\n",
            acpt_addr ? acpt_addr : "any", acpt_port, q_listen_len, acpt_cong);
  acpt_data->evnt = acpt_listener->evnt;
  acpt_data->sa   = vstr_ref_add(acpt_data->evnt->sa_ref);
  
  sinv4 = EVNT_SA_IN4(acpt_listener->evnt);
  ASSERT(!acpt_port || (acpt_port == ntohs(sinv4->sin_port)));

  if (defer_accept)
    evnt_fd_set_defer_accept(acpt_listener->evnt, defer_accept);
  
  if (acpt_filter_file &&
      !evnt_fd_set_filter(acpt_listener->evnt, acpt_filter_file))
    vlg_err(vlg, 3, "set_filter(%s): %m\n", acpt_filter_file);
  
  return (acpt_listener->evnt);
}

struct Evnt *evnt_sc_serv_make_bind_local(const char *acpt_addr,
                                          unsigned int q_listen_len,
                                          unsigned int max_connections,
                                          unsigned int local_perms,
                                          const char *acpt_filter_file)
{
  Acpt_listener *acpt_listener = NULL;
  Acpt_data *acpt_data = NULL;
  Vstr_ref *ref = NULL;
  
  if (!(acpt_listener = MK(sizeof(Acpt_listener))))
    VLG_ERRNOMEM((vlg, EXIT_FAILURE, "make_bind(%s): %m\n",
                  acpt_addr));
  acpt_listener->max_connections = max_connections;
  acpt_listener->def_policy = NULL;
  
  if (!(acpt_data = MK(sizeof(Acpt_data))))
    VLG_ERRNOMEM((vlg, EXIT_FAILURE, "make_bind(%s): %m\n",
                  acpt_addr));
  acpt_data->evnt = NULL;
  acpt_data->sa   = NULL;

  if (!(ref = vstr_ref_make_ptr(acpt_data, evnt__sc_serv_make_acpt_data_cb)))
    VLG_ERRNOMEM((vlg, EXIT_FAILURE, "make_bind(%s): %m\n",
                  acpt_addr));
  acpt_listener->ref = ref;
  
  if (!evnt_make_bind_local(acpt_listener->evnt, acpt_addr,
                            q_listen_len, local_perms))
    vlg_err(vlg, 2, "make_bind(%s, %d): Failed!\n", acpt_addr, q_listen_len);
  
  acpt_data->evnt = acpt_listener->evnt;
  acpt_data->sa   = vstr_ref_add(acpt_data->evnt->sa_ref);

  if (acpt_filter_file &&
      !evnt_fd_set_filter(acpt_listener->evnt, acpt_filter_file))
    vlg_err(vlg, 3, "set_filter(%s): %m\n", acpt_filter_file);
  
  return (acpt_listener->evnt);
}

void evnt_vlg_stats_info(struct Evnt *evnt, const char *prefix)
{
  vlg_info(vlg, "%s from[$<sa:%p>] req_got[%'ju:%ju] req_put[%'ju:%ju]"
           " recv[${BKMG.ju:%ju}:%ju] send[${BKMG.ju:%ju}:%ju]\n",
           prefix, EVNT_SA(evnt),
           evnt->acct.req_got, evnt->acct.req_got,
           evnt->acct.req_put, evnt->acct.req_put,
           evnt->acct.bytes_r, evnt->acct.bytes_r,
           evnt->acct.bytes_w, evnt->acct.bytes_w);
}

#ifdef TCP_DEFER_ACCEPT
# define USE_TCP_DEFER_ACCEPT 1
#else
# define USE_TCP_DEFER_ACCEPT 0
# define TCP_DEFER_ACCEPT 0
#endif

void evnt_fd_set_defer_accept(struct Evnt *evnt, int val)
{
  socklen_t len = sizeof(int);

  ASSERT(evnt__valid(evnt));

  if (!USE_TCP_DEFER_ACCEPT)
    return;
  
  /* ignore return val */
  setsockopt(evnt_fd(evnt), IPPROTO_TCP, TCP_DEFER_ACCEPT, &val, len);
}

pid_t evnt_make_child(void)
{
  pid_t ret = fork();

  if (!ret)
  {
    evnt__is_child = TRUE;
    evnt_poll->child_init();
  }
  
  return (ret);
}

int evnt_is_child(void)
{
  return (evnt__is_child);
}

static int evnt__block_child_beg(void)
{
  if (!evnt_is_child())
    return (TRUE);
  
  if (PROC_CNTL_PDEATHSIG(SIGTERM) == -1)
    vlg_err(vlg, EXIT_FAILURE,
            "prctl(%s, %s): %m\n", "PR_SET_PDEATHSIG", "SIGTERM");

  if (evnt_signal_child_exited)
    return (FALSE);

  return (TRUE);
}

static int evnt__block_child_end(void)
{
  if (!evnt_is_child())
    return (TRUE);
  
  if (PROC_CNTL_PDEATHSIG(SIGCHLD) == -1)
    vlg_err(vlg, EXIT_FAILURE,
            "prctl(%s, %s): %m\n", "PR_SET_PDEATHSIG", "SIGCHLD");
  
  return (TRUE);
}

/* if we are blocking forever, and the only thing we are waiting for is
 * a single accept() fd, just call accept() */
int evnt_q_tst_accept(int msecs)
{
  if (msecs != -1)
    return (FALSE);

  if (!q_accept || q_accept->next)
    return (FALSE);

  if (q_connect || q_recv || q_send_recv)
    return (FALSE);

  /* note, can have as many evnt's in q_none as we want */
  
  return (TRUE);
}

void evnt_swap_accept_read(struct Evnt *evnt)
{
  evnt_del(&q_accept, evnt); evnt->flag_q_accept = FALSE;
  evnt_add(&q_recv, evnt);   evnt->flag_q_recv   = TRUE;

  ASSERT(evnt__valid(evnt));
}

int evnt_block_poll_accept(void)
{
  int fd = -1;
  struct Evnt *scan = q_accept;
  struct sockaddr_in sa;
  socklen_t len = sizeof(struct sockaddr_in);
  struct Evnt *tmp = NULL;

  /* need to make sure we die if the parent does */
  evnt_fd__set_nonblock(evnt_fd(scan), FALSE);
  if (!evnt__block_child_beg())
    goto block_beg_fail;

  fd = accept(evnt_fd(scan), (struct sockaddr *) &sa, &len);
  evnt__block_child_end();
  evnt_fd__set_nonblock(evnt_fd(scan), TRUE);
    
  if (fd == -1)
    goto accept_fail;

  if (!(tmp = scan->cbs->cb_func_accept(scan,
                                        fd, (struct sockaddr *) &sa, len)))
    goto cb_accept_fail;

  if (!tmp->flag_q_closed)
    tmp->flag_fully_acpt = TRUE;
  assert(SOCKET_POLL_INDICATOR(tmp->ind)->events  == POLLIN);
  assert(SOCKET_POLL_INDICATOR(tmp->ind)->revents == POLLIN);
  assert(tmp == q_recv);

  return (1);
  
 block_beg_fail:
  evnt_fd__set_nonblock(evnt_fd(scan), TRUE);
  goto accept_fail;

 cb_accept_fail:
  close(fd);
 accept_fail:
  errno = EINTR;
  return (-1);
}

void evnt_q_move_front(struct Evnt *evnt)
{
  evnt__del_whatever(evnt); /* move to front of queue */
  evnt__add_whatever(evnt);
}

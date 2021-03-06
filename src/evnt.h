#ifndef EVENT_H
#define EVENT_H

#include "vlg.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>

#include <timer_q.h>

#ifdef __linux__
# include <sys/prctl.h>
#endif

#ifdef PR_SET_PDEATHSIG
# define PROC_CNTL_PDEATHSIG(x1) prctl(PR_SET_PDEATHSIG, x1, 0, 0, 0)
#else
# define PROC_CNTL_PDEATHSIG(x1) (-1)
#endif

#ifndef EVNT_COMPILE_INLINE
#define EVNT_COMPILE_INLINE 1
#endif

#ifndef EVNT_CONF_NAGLE
#define EVNT_CONF_NAGLE FALSE /* configurable */
#endif

#define EVNT_IO_OK 0
#define EVNT_IO_READ_EOF 1
#define EVNT_IO_READ_FIN 2
#define EVNT_IO_READ_ERR 3
#define EVNT_IO_SEND_ERR 4

struct Evnt;

struct Evnt_cbs
{
 struct Evnt *(*cb_func_accept)    (struct Evnt *,
                                    int, struct sockaddr *, socklen_t);
 int          (*cb_func_connect)   (struct Evnt *);
 int          (*cb_func_recv)      (struct Evnt *);
 int          (*cb_func_send)      (struct Evnt *);
 void         (*cb_func_free)      (struct Evnt *);
 int          (*cb_func_shutdown_r)(struct Evnt *);
};

struct Evnt_limit
{
 unsigned long io_r_max; /* read/accept */
 unsigned long io_r_cur;
 struct timeval io_r_tm;

 unsigned long io_w_max; /* write/sendfile/connect */
 unsigned long io_w_cur;
 struct timeval io_w_tm;
};


struct Evnt
{
 struct Evnt *next;
 struct Evnt *prev;

 const struct Evnt_cbs *cbs;

 Vstr_ref **lims; /* array of references to struct Evnt_limit */
 unsigned int lim_num;

 unsigned int ind; /* socket poll */

 Vstr_ref *sa_ref;
 Vstr_ref *acpt_sa_ref;

 Vstr_base *io_r;
 Vstr_base *io_w;

 struct Evnt *s_next;
 struct Evnt *c_next;
 
 Timer_q_node *tm_o; /* timeout */
 Timer_q_node *tm_l_r; /* limit read/recv */
 Timer_q_node *tm_l_w; /* limit write/send */

 struct timeval ctime;
 struct timeval mtime;

 unsigned long msecs_tm_mtime;
 
 uintmax_t prev_bytes_r;
 struct
 {
  uintmax_t req_put;
  uintmax_t req_got;
  uintmax_t bytes_r;
  uintmax_t bytes_w;
 } acct;
 
 unsigned int flag_q_accept     : 1;
 unsigned int flag_q_connect    : 1;
 unsigned int flag_q_recv       : 1;
 unsigned int flag_q_send_recv  : 1;
 unsigned int flag_q_none       : 1;
 
 unsigned int flag_q_send_now   : 1;
 unsigned int flag_q_closed     : 1;

 unsigned int flag_q_pkt_move   : 1; /* 8 */

 unsigned int flag_io_nagle     : 1;
 unsigned int flag_io_cork      : 1;

 unsigned int flag_io_filter    : 1;

 unsigned int flag_fully_acpt   : 1;

 unsigned int flag_insta_close  : 1;

 unsigned int io_r_shutdown     : 1;
 unsigned int io_w_shutdown     : 1;

 unsigned int flag_io_r_limited : 1; /* 16 */
 unsigned int flag_io_w_limited : 1;

 unsigned int flag_io_wonly_tm  : 1;

 unsigned int flag_got_EAGAIN   : 1; /* 19 */
};

#ifndef  EVNT_USE_EPOLL
# ifdef  HAVE_SYS_EPOLL_H
#  define EVNT_USE_EPOLL 1
# else
#  define EVNT_USE_EPOLL 0
# endif
#endif

struct Evnt_poll
{
  int (*init)(void);
  int (*direct_enabled)(void);
  int (*child_init)(void);
  
  void (*wait_cntl_add)(struct Evnt *evnt, int flags);
  void (*wait_cntl_del)(struct Evnt *evnt, int flags);

  unsigned int (*add)(struct Evnt *evnt, int fd);
  void         (*del)(struct Evnt *evnt);

  int (*swap_accept_read)(struct Evnt *evnt, int fd);

  int (*poll)(void);
};

extern const struct Evnt_poll *evnt_poll;
extern const struct Evnt_poll evnt_poll_be_poll;
extern const struct Evnt_poll evnt_poll_be_epoll;

/* NOTE: ifdef city when we have kqueue etc. */
#define EVNT_POLL_BE_DEF evnt_poll_be_epoll

#if ! COMPILE_DEBUG
# define EVNT_SA(x)     ((struct sockaddr     *)(x)->sa_ref->ptr)
# define EVNT_SA_IN4(x) ((struct sockaddr_in  *)(x)->sa_ref->ptr)
# define EVNT_SA_IN6(x) ((struct sockaddr_in6 *)(x)->sa_ref->ptr)
# define EVNT_SA_UN(x)  ((struct sockaddr_un  *)(x)->sa_ref->ptr)
#else
#include <netinet/in.h>
#include <sys/un.h>

static struct sockaddr     *evnt___chk_sa(void *ptr) COMPILE_ATTR_USED();
static struct sockaddr     *evnt___chk_sa(void *ptr)
{
  struct sockaddr *sa = ptr;
  if (sa && /* vlg__fmt__add_vstr_add_sa accepts NULLs */
      (sa->sa_family != AF_INET) &&
      (sa->sa_family != AF_INET6) &&
      (sa->sa_family != AF_LOCAL))
    abort();
  return (sa);
}
static struct sockaddr_in  *evnt___chk_in(void *ptr) COMPILE_ATTR_USED();
static struct sockaddr_in  *evnt___chk_in(void *ptr)
{
  struct sockaddr_in *sa = ptr;
  if (sa->sin_family != AF_INET)
    abort();
  return (sa);
}
static struct sockaddr_in6 *evnt___chk_in6(void *ptr) COMPILE_ATTR_USED();
static struct sockaddr_in6 *evnt___chk_in6(void *ptr)
{
  struct sockaddr_in6 *sa = ptr;
  if (sa->sin6_family != AF_INET6)
    abort();
  return (sa);
}
static struct sockaddr_un  *evnt___chk_un(void *ptr) COMPILE_ATTR_USED();
static struct sockaddr_un  *evnt___chk_un(void *ptr)
{
  struct sockaddr_un *sa = ptr;
  if (sa->sun_family != AF_LOCAL)
    abort();
  return (sa);
}

# define EVNT_SA(x)     evnt___chk_sa((x)->sa_ref->ptr)
# define EVNT_SA_IN4(x) evnt___chk_in((x)->sa_ref->ptr)
# define EVNT_SA_IN6(x) evnt___chk_in6((x)->sa_ref->ptr)
# define EVNT_SA_UN(x)  evnt___chk_un((x)->sa_ref->ptr)
#endif

/* FIXME: bad namespace */
typedef struct Acpt_data
{
 struct Evnt *evnt;
 Vstr_ref *sa;
} Acpt_data;
#if ! COMPILE_DEBUG
# define ACPT_SA(x)     ((struct sockaddr     *)(x)->sa->ptr)
# define ACPT_SA_IN4(x) ((struct sockaddr_in  *)(x)->sa->ptr)
# define ACPT_SA_IN6(x) ((struct sockaddr_in6 *)(x)->sa->ptr)
# define ACPT_SA_UN(x)  ((struct sockaddr_un  *)(x)->sa->ptr)
#else
# define ACPT_SA(x)     evnt___chk_sa((x)->sa->ptr)
# define ACPT_SA_IN4(x) evnt___chk_in((x)->sa->ptr)
# define ACPT_SA_IN6(x) evnt___chk_in6((x)->sa->ptr)
# define ACPT_SA_UN(x)  evnt___chk_un((x)->sa->ptr)
#endif

# define EVNT_ACPT_EXISTS(x) (!!(x)->acpt_sa_ref)
# define EVNT_ACPT_DATA(x)   ((Acpt_data *)((x)->acpt_sa_ref->ptr))
# define EVNT_ACPT_SA(x)     ACPT_SA(EVNT_ACPT_DATA(x))
# define EVNT_ACPT_SA_IN4(x) ACPT_SA_IN4(EVNT_ACPT_DATA(x))
# define EVNT_ACPT_SA_IN6(x) ACPT_SA_IN6(EVNT_ACPT_DATA(x))
# define EVNT_ACPT_SA_UN(x)  ACPT_SA_UN(EVNT_ACPT_DATA(x))

typedef struct Acpt_listener
{
 struct Evnt evnt[1];
 unsigned int max_connections;
 Vstr_ref *def_policy;
 Vstr_ref *ref;
} Acpt_listener;

extern volatile sig_atomic_t evnt_signal_child_exited;
extern volatile sig_atomic_t evnt_signal_term;

#define EVNT_GOT_SIGNAL() (evnt_signal_child_exited || evnt_signal_term)

extern int evnt_opt_nagle;

extern void evnt_logger(Vlg *);
extern void evnt_poll_logger(Vlg *);

extern void evnt_fd__set_nonblock(int, int);

extern int evnt_fd(struct Evnt *);

extern int evnt_cb_func_connect(struct Evnt *);
extern struct Evnt *evnt_cb_func_accept(struct Evnt *,
                                        int, struct sockaddr *, socklen_t);
extern int evnt_cb_func_recv(struct Evnt *);
extern int evnt_cb_func_send(struct Evnt *);
extern void evnt_cb_func_free(struct Evnt *);
extern void evnt_cb_func_F(struct Evnt *);
extern int evnt_cb_func_shutdown_r(struct Evnt *);

extern int evnt_limit_add(struct Evnt *, Vstr_ref *);
extern int evnt_limit_dup(struct Evnt *, const struct Evnt_limit *);
extern void evnt_limit_chg(struct Evnt *, unsigned int, Vstr_ref *);
extern void evnt_limit_alt(struct Evnt *, unsigned int,
                           const struct Evnt_limit *);
extern void evnt_limit_free(struct Evnt *);

extern int evnt_make_con_ipv4(struct Evnt *, const char *, short);
extern int evnt_make_con_local(struct Evnt *, const char *);
extern int evnt_make_bind_ipv4(struct Evnt *, const char *, short,
                               unsigned int, const char *);
extern int evnt_make_bind_local(struct Evnt *, const char *,
                                unsigned int, unsigned int);
extern int evnt_make_acpt_ref(struct Evnt *, int, Vstr_ref *);
extern int evnt_make_acpt_dup(struct Evnt *, int, struct sockaddr *, socklen_t);
extern int evnt_make_custom(struct Evnt *, int, Vstr_ref *, int);

extern void evnt_free(struct Evnt *);
extern void evnt_close(struct Evnt *);
extern void evnt_close_all(void);

extern void evnt_pkt_wait_r(struct Evnt *);
extern void evnt_put_pkt(struct Evnt *);
extern void evnt_got_pkt(struct Evnt *);

extern int evnt_shutdown_r(struct Evnt *, int);
extern int evnt_shutdown_w(struct Evnt *);
extern int evnt_recv(struct Evnt *, unsigned int *);
extern int evnt_send(struct Evnt *);
extern int evnt_sendfile(struct Evnt *, int,
                         uintmax_t *, uintmax_t *, unsigned int *);
extern int evnt_sc_read_send(struct Evnt *, int, uintmax_t *);
extern int  evnt_send_add(struct Evnt *, int, size_t);
extern void evnt_send_del(struct Evnt *);
extern void evnt_scan_fds(unsigned int, size_t);
extern void evnt_scan_send_fds(void);
extern void evnt_scan_q_close(void);
extern void evnt_acpt_close_all(void);


extern void evnt_stats_add(struct Evnt *, const struct Evnt *);

extern unsigned int evnt_num_all(void);
extern int evnt_waiting(void);

extern void evnt_fd_set_nagle(struct Evnt *, int);
extern void evnt_fd_set_cork(struct Evnt *, int);
extern void evnt_fd_set_defer_accept(struct Evnt *, int);
extern int  evnt_fd_set_filter(struct Evnt *, const char *);

extern void evnt_timeout_init(void);
extern void evnt_timeout_exit(void);

extern pid_t evnt_make_child(void);
extern int   evnt_is_child(void);

extern int evnt_sc_timeout_via_mtime(struct Evnt *, unsigned long);

extern void evnt_sc_main_loop(size_t);

extern time_t evnt_sc_time(void);

extern void evnt_sc_serv_cb_func_acpt_free(struct Evnt *);
extern struct Evnt *evnt_sc_serv_make_bind_ipv4(const char *, unsigned short,
                                                unsigned int, unsigned int,
                                                unsigned int, const char *,
                                                const char *);
extern struct Evnt *evnt_sc_serv_make_bind_local(const char *, unsigned int,
                                                 unsigned int, unsigned int,
                                                 const char *);

extern void evnt_vlg_stats_info(struct Evnt *, const char *);

extern struct Evnt *evnt_find_least_used(void);

extern struct Evnt *evnt_queue(const char *);

extern void evnt_out_dbg3(const char *);

extern int evnt_timeout_msecs(void);
extern int evnt_q_tst_accept(int);
extern void evnt_swap_accept_read(struct Evnt *);
extern int evnt_block_poll_accept(void);
extern void evnt_q_move_front(struct Evnt *);


#endif

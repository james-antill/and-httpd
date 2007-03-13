/*
 *  Copyright (C) 2002, 2003, 2004, 2005, 2006  James Antill
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
/* poll wrapper interface, for IO events */
#include <vstr.h>

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <socket_poll.h>

#define EVNT__POLL_FLGS(x)                                              \
 ((((x) & (POLLIN | POLLOUT)) == (POLLIN | POLLOUT)) ? "(POLLIN | POLLOUT)" : \
  (((x) &  POLLIN)                                   ? "(POLLIN)"           : \
  (((x) &           POLLOUT)                         ?          "(POLLOUT)" : \
   "()")))

#define CONF_EVNT_NO_EPOLL FALSE
#define CONF_EVNT_EPOLL_SZ (10 * 1000) /* size is just a speed hint */
#define CONF_EVNT_DUP_EPOLL TRUE /* doesn't work if FALSE and multi proc */

#include "vlg.h"

#define EX_UTILS_NO_FUNCS 1
#include "ex_utils.h"

#include "evnt.h"

const struct Evnt_poll *evnt_poll = NULL;

static Vlg *vlg = NULL;

void evnt_poll_logger(Vlg *passed_vlg)
{
  vlg = passed_vlg;
}

static int evnt__poll_init(void)
{
  return (TRUE);
}

static int evnt__poll_direct_enabled(void)
{
  return (FALSE);
}

static int evnt__poll_child_init(void)
{
  return (TRUE);
}

static void evnt__poll_wait_cntl_add(struct Evnt *evnt, int flags)
{
  /* FIXME: do the POLLOUT revents differently ... move accept into the cb */
  SOCKET_POLL_INDICATOR(evnt->ind)->events  |= flags;
  SOCKET_POLL_INDICATOR(evnt->ind)->revents |= (flags & POLLIN);
}

static void evnt__poll_wait_cntl_del(struct Evnt *evnt, int flags)
{
  SOCKET_POLL_INDICATOR(evnt->ind)->events  &= ~flags;
  SOCKET_POLL_INDICATOR(evnt->ind)->revents &= ~flags;  
}

static unsigned int evnt__poll_add(struct Evnt *COMPILE_ATTR_UNUSED(evnt), int fd)
{
  return (socket_poll_add(fd));
}

static void evnt__poll_del(struct Evnt *evnt)
{
  if (SOCKET_POLL_INDICATOR(evnt->ind)->fd != -1)
    close(SOCKET_POLL_INDICATOR(evnt->ind)->fd);
  socket_poll_del(evnt->ind);
}

/* NOTE: that because of socket_poll direct mapping etc. we can't be "clever" */
static int evnt__poll_swap_accept_read(struct Evnt *evnt, int fd)
{
  unsigned int old_ind = evnt->ind;
  
  assert(SOCKET_POLL_INDICATOR(evnt->ind)->fd != fd);
  
  if (!(evnt->ind = socket_poll_add(fd)))
    goto poll_add_fail;
  
  if (!(evnt->io_r = vstr_make_base(NULL)) ||
      !(evnt->io_w = vstr_make_base(NULL)))
    goto malloc_base_fail;

  SOCKET_POLL_INDICATOR(evnt->ind)->events  |= POLLIN;
  SOCKET_POLL_INDICATOR(evnt->ind)->revents |= POLLIN;

  socket_poll_del(old_ind);

  evnt_fd__set_nonblock(fd, TRUE);
  
  evnt_swap_accept_read(evnt);

  return (TRUE);

 malloc_base_fail:
  socket_poll_del(evnt->ind);
  evnt->ind = old_ind;
  vstr_free_base(evnt->io_r); evnt->io_r = NULL;
  ASSERT(!evnt->io_r && !evnt->io_w);
 poll_add_fail:
  return (FALSE);
}

static int evnt__poll_poll(void)
{
  int msecs = evnt_timeout_msecs();

  if (EVNT_GOT_SIGNAL())
    return (errno = EINTR, -1);

  if (evnt_q_tst_accept(msecs))
    return (evnt_block_poll_accept());
  
  return (socket_poll_update_all(msecs));
}

const struct Evnt_poll evnt_poll_be_poll = {
 evnt__poll_init, evnt__poll_direct_enabled, evnt__poll_child_init,
 evnt__poll_wait_cntl_add, evnt__poll_wait_cntl_del,
 evnt__poll_add, evnt__poll_del,
 evnt__poll_swap_accept_read,
 evnt__poll_poll
};

#if !EVNT_USE_EPOLL
/* pretend epoll == poll, so we dont' have to ifdef everywhere for names */
const struct Evnt_poll evnt_poll_be_epoll = {
 evnt__poll_init, evnt__poll_direct_enabled, evnt__poll_child_init,
 evnt__poll_wait_cntl_add, evnt__poll_wait_cntl_del,
 evnt__poll_add, evnt__poll_del,
 evnt__poll_swap_accept_read,
 evnt__poll_poll
};
#else

#include <sys/epoll.h>

static int evnt__epoll_fd = -1;

static int evnt__epoll_init(void)
{
  assert(POLLIN  == EPOLLIN);
  assert(POLLOUT == EPOLLOUT);
  assert(POLLHUP == EPOLLHUP);
  assert(POLLERR == EPOLLERR);

  if (!CONF_EVNT_NO_EPOLL)
  {
    evnt__epoll_fd = epoll_create(CONF_EVNT_EPOLL_SZ);
  
    vlg_dbg2(vlg, "epoll_create(%d): %m\n", evnt__epoll_fd);
  }
  
  return (evnt__epoll_fd != -1);
}

static int evnt__epoll_direct_enabled(void)
{
  return (evnt__epoll_fd != -1);
}

static int evnt__epoll_readd(struct Evnt *evnt)
{
  struct epoll_event epevent[1];

  while (evnt)
  {
    int flags = SOCKET_POLL_INDICATOR(evnt->ind)->events;    

    vlg_dbg2(vlg, "epoll_readd($<sa:%p>,%u=%s)\n", EVNT_SA(evnt),
             flags, EVNT__POLL_FLGS(flags));
    epevent->events   = flags;
    epevent->data.u64 = 0; /* FIXME: keep valgrind happy */
    epevent->data.ptr = evnt;

    if (epoll_ctl(evnt__epoll_fd, EPOLL_CTL_ADD, evnt_fd(evnt), epevent) == -1)
      vlg_err(vlg, EXIT_FAILURE, "epoll_readd: %m\n");
    
    evnt = evnt->next;
  }

  return (TRUE);
}

static int evnt__epoll_child_init(void)
{ /* Can't share epoll() fd's between tasks ... */
  if (CONF_EVNT_DUP_EPOLL && evnt_poll->direct_enabled())
  {
    close(evnt__epoll_fd);
    evnt__epoll_fd = epoll_create(CONF_EVNT_EPOLL_SZ); /* size does nothing */
    if (evnt__epoll_fd == -1)
      VLG_WARN_RET(FALSE, (vlg, "epoll_recreate(): %m\n"));

    evnt__epoll_readd(evnt_queue("connect"));
    evnt__epoll_readd(evnt_queue("accept"));
    evnt__epoll_readd(evnt_queue("recv"));
    evnt__epoll_readd(evnt_queue("send_recv"));
    evnt__epoll_readd(evnt_queue("none"));
  }

  return (TRUE);
}

static void evnt__epoll_wait_cntl_add(struct Evnt *evnt, int flags)
{
  if ((SOCKET_POLL_INDICATOR(evnt->ind)->events & flags) == flags)
    return;

  /* FIXME: do the POLLOUT revents differently ... move accept into the cb */
  SOCKET_POLL_INDICATOR(evnt->ind)->events  |=  flags;
  SOCKET_POLL_INDICATOR(evnt->ind)->revents |= (flags & POLLIN);
  
  if (evnt_poll->direct_enabled())
  {
    struct epoll_event epevent[1];
    
    flags = SOCKET_POLL_INDICATOR(evnt->ind)->events;    
    vlg_dbg2(vlg, "epoll_mod_add($<sa:%p>,%u=%s)\n", EVNT_SA(evnt),
             flags, EVNT__POLL_FLGS(flags));
    epevent->events   = flags;
    epevent->data.u64 = 0; /* FIXME: keep valgrind happy */
    epevent->data.ptr = evnt;

    if (epoll_ctl(evnt__epoll_fd, EPOLL_CTL_MOD, evnt_fd(evnt), epevent) == -1)
      vlg_err(vlg, EXIT_FAILURE, "epoll: %m\n");
  }
}

static void evnt__epoll_wait_cntl_del(struct Evnt *evnt, int flags)
{
  if (!(SOCKET_POLL_INDICATOR(evnt->ind)->events & flags))
    return;
  
  SOCKET_POLL_INDICATOR(evnt->ind)->events  &= ~flags;
  SOCKET_POLL_INDICATOR(evnt->ind)->revents &= ~flags;
  
  if (flags && evnt_poll->direct_enabled())
  {
    struct epoll_event epevent[1];
    
    flags = SOCKET_POLL_INDICATOR(evnt->ind)->events;
    vlg_dbg2(vlg, "epoll_mod_del($<sa:%p>,%u=%s)\n", EVNT_SA(evnt),
             flags, EVNT__POLL_FLGS(flags));
    epevent->events   = flags;
    epevent->data.u64 = 0; /* FIXME: keep valgrind happy */
    epevent->data.ptr = evnt;

    if (epoll_ctl(evnt__epoll_fd, EPOLL_CTL_MOD, evnt_fd(evnt), epevent) == -1)
      vlg_err(vlg, EXIT_FAILURE, "epoll: %m\n");
  }
}

static unsigned int evnt__epoll_add(struct Evnt *evnt, int fd)
{
  unsigned int ind = socket_poll_add(fd);

  if (ind && evnt_poll->direct_enabled())
  {
    struct epoll_event epevent[1];
    int flags = 0;

    vlg_dbg2(vlg, "epoll_add($<sa:%p>,%u=%s)\n", EVNT_SA(evnt),
             flags, EVNT__POLL_FLGS(flags));
    epevent->events   = flags;
    epevent->data.u64 = 0; /* FIXME: keep valgrind happy */
    epevent->data.ptr = evnt;
    
    if (epoll_ctl(evnt__epoll_fd, EPOLL_CTL_ADD, fd, epevent) == -1)
    {
      vlg_warn(vlg, "epoll: %m\n");
      socket_poll_del(fd);
    }  
  }
  
  return (ind);
}

static void evnt__epoll_del(struct Evnt *evnt)
{
  if (SOCKET_POLL_INDICATOR(evnt->ind)->fd != -1)
    close(SOCKET_POLL_INDICATOR(evnt->ind)->fd);
  socket_poll_del(evnt->ind);

  /* done via. the close() */
  if (FALSE && evnt_poll->direct_enabled())
  {
    int fd = SOCKET_POLL_INDICATOR(evnt->ind)->fd;
    struct epoll_event epevent[1];

    vlg_dbg2(vlg, "epoll_del($<sa:%p>)\n", EVNT_SA(evnt));
    epevent->events   = 0;
    epevent->data.u64 = 0; /* FIXME: keep valgrind happy */
    epevent->data.ptr = evnt;
    
    if (epoll_ctl(evnt__epoll_fd, EPOLL_CTL_DEL, fd, epevent) == -1)
      vlg_abort(vlg, "epoll: %m\n");
  }
}

static int evnt__epoll_swap_accept_read(struct Evnt *evnt, int fd)
{
  unsigned int old_ind = evnt->ind;
  int old_fd = SOCKET_POLL_INDICATOR(old_ind)->fd;
  
  assert(SOCKET_POLL_INDICATOR(evnt->ind)->fd != fd);
  
  if (!(evnt->ind = socket_poll_add(fd)))
    goto poll_add_fail;
  
  if (!(evnt->io_r = vstr_make_base(NULL)) ||
      !(evnt->io_w = vstr_make_base(NULL)))
    goto malloc_base_fail;

  SOCKET_POLL_INDICATOR(evnt->ind)->events  |= POLLIN;
  SOCKET_POLL_INDICATOR(evnt->ind)->revents |= POLLIN;

  socket_poll_del(old_ind);

  if (evnt_poll->direct_enabled())
  {
    struct epoll_event epevent[1];

    vlg_dbg2(vlg, "epoll_swap($<sa:%p>,%d,%d)\n", EVNT_SA(evnt), old_fd, fd);
    
    epevent->events   = POLLIN;
    epevent->data.u64 = 0; /* FIXME: keep valgrind happy */
    epevent->data.ptr = evnt;
    
    if (epoll_ctl(evnt__epoll_fd, EPOLL_CTL_DEL, old_fd, epevent) == -1)
      vlg_abort(vlg, "epoll: %m\n");
    
    epevent->events   = SOCKET_POLL_INDICATOR(evnt->ind)->events;
    epevent->data.ptr = evnt;
    
    if (epoll_ctl(evnt__epoll_fd, EPOLL_CTL_ADD, fd, epevent) == -1)
      vlg_abort(vlg, "epoll: %m\n");
  }
  
  evnt_fd__set_nonblock(fd, TRUE);
  
  evnt_swap_accept_read(evnt);

  return (TRUE);
  
 malloc_base_fail:
  socket_poll_del(evnt->ind);
  evnt->ind = old_ind;
  vstr_free_base(evnt->io_r); evnt->io_r = NULL;
  ASSERT(!evnt->io_r && !evnt->io_w);
 poll_add_fail:
  return (FALSE);
}

#define EVNT__EPOLL_EVENTS 128
static int evnt__epoll_poll(void)
{
  struct epoll_event events[EVNT__EPOLL_EVENTS];
  int msecs = evnt_timeout_msecs();
  int ret = 0;
  unsigned int scan = 0;
  
  if (EVNT_GOT_SIGNAL())
    return (errno = EINTR, -1);

  if (evnt_q_tst_accept(msecs))
    return (evnt_block_poll_accept());
  
  if (!evnt_poll->direct_enabled())
    return (socket_poll_update_all(msecs));

  if (msecs)
  { /* do the double poll() that socket_poll_update_all() does for us */
    ret = epoll_wait(evnt__epoll_fd, events, EVNT__EPOLL_EVENTS, 0);
    if (ret == -1)
      return (ret);
  }

  if (!ret)
    ret = epoll_wait(evnt__epoll_fd, events, EVNT__EPOLL_EVENTS, msecs);
  if (ret == -1)
    return (ret);

  scan = ret;
  ASSERT(scan <= EVNT__EPOLL_EVENTS);
  while (scan-- > 0)
  {
    struct Evnt *evnt  = NULL;
    unsigned int flags = 0;
    
    flags = events[scan].events;
    evnt  = events[scan].data.ptr;

    vlg_dbg2(vlg, "epoll_wait($<sa:%p>,%u=%s)\n", EVNT_SA(evnt),
             flags, EVNT__POLL_FLGS(flags));
    vlg_dbg2(vlg, "epoll[flags]=a=%u|r=%u|s=%u\n",
             evnt->flag_q_accept, evnt->flag_q_recv, evnt->flag_q_send_recv);

    assert(((SOCKET_POLL_INDICATOR(evnt->ind)->events & flags) == flags) ||
           ((POLLHUP|POLLERR) & flags));
    
    SOCKET_POLL_INDICATOR(evnt->ind)->revents = flags;
    
    evnt_q_move_front(evnt);
  }

  return (ret);
}

const struct Evnt_poll evnt_poll_be_epoll = {
 evnt__epoll_init, evnt__epoll_direct_enabled, evnt__epoll_child_init,
 evnt__epoll_wait_cntl_add, evnt__epoll_wait_cntl_del,
 evnt__epoll_add, evnt__epoll_del,
 evnt__epoll_swap_accept_read,
 evnt__epoll_poll
};
#endif


# See if we can cast the automake spell. -*-Makefile-*-
#

#
AUTOMAKE_OPTIONS = no-dependencies 1.4

if DBG_VSTR
CFLAGS = # Remove -O2 automake/autoconf braindamage
if VSTR_DBG_AVAIL

GEN_CFLAGS = $(VSTR_DBG_CFLAGS) @CFLAGS@ @WARNS@
GEN_LDLIBS = $(VSTR_DBG_LDLIBS) @LDFLAGS@

else

GEN_CFLAGS = $(VSTR_CFLAGS) @CFLAGS@ @WARNS@
GEN_LDLIBS = $(VSTR_LDLIBS) @LDFLAGS@

endif
else

GEN_CFLAGS = $(VSTR_CFLAGS) @CFLAGS@ @WARNS@
GEN_LDLIBS = $(VSTR_LDLIBS) @LDFLAGS@

endif

# if USE_STATIC_LIBS
# GEN_CFLAGS += -DCONF_FULL_STATIC=1
# endif

CMDLINE_FILES_SRCS = date.c evnt.c hexdump.c opt.c vlg.c
CMDLINE_FILES_HDRS = date.h evnt.h hexdump.h opt.h vlg.h

DAEMON_FILES_SRCS = bag.c conf.c cntl.c date.c evnt.c hexdump.c \
                    opt.c opt_policy.c opt_serv.c vlg.c \
                    conf_inline.c opt_policy_inline.c
DAEMON_FILES_HDRS = bag.h conf.h cntl.h date.h evnt.h hexdump.h \
                    opt.h opt_policy.h opt_serv.h vlg.h


and_httpd_SOURCES      = mime_types.c httpd_conf_main.c httpd_conf_req.c \
                        httpd_policy.c httpd_policy_inline.c \
                        $(DAEMON_FILES_SRCS) httpd.c and-httpd.c
and_httpd_DEPENDENCIES = mime_types.h httpd_conf_main.h httpd_conf_req.h \
                        httpd_policy.h \
                        $(DAEMON_FILES_HDRS) httpd.h httpd_err_codes.h
and_httpd_CFLAGS   = $(GEN_CFLAGS) $(SOCKET_POLL_CFLAGS) $(TIMER_Q_CFLAGS) \
                     -DHTTPD_CONF_VERSION='"@VERSION@"'
and_httpd_LDADD    = $(GEN_LDLIBS) $(SOCKET_POLL_LDLIBS) $(TIMER_Q_LDLIBS)

if LIBCAP_AVAIL
and_httpd_LDADD += -lcap
endif

# These are "extra" ... but kind of needed

and_cntl_SOURCES      = $(CMDLINE_FILES_SRCS) and-cntl.c
and_cntl_DEPENDENCIES = $(CMDLINE_FILES_HDRS) mk.h
and_cntl_CFLAGS   = $(GEN_CFLAGS) $(SOCKET_POLL_CFLAGS) $(TIMER_Q_CFLAGS)
and_cntl_LDADD    = $(GEN_LDLIBS) $(SOCKET_POLL_LDLIBS) $(TIMER_Q_LDLIBS)

and_conf_SOURCES      = conf.c and-conf.c conf_inline.c
and_conf_DEPENDENCIES = conf.h ex_utils.h mk.h
and_conf_CFLAGS = $(GEN_CFLAGS)
and_conf_LDADD  = $(GEN_LDLIBS)

and_sock_filter_DEPENDENCIES = ex_utils.h
and_sock_filter_CFLAGS = $(GEN_CFLAGS)
and_sock_filter_LDADD  = $(GEN_LDLIBS)


if PERL_USR_BIN_AVAIL
TESTS_ENVIRONMENT = SRCDIR="$(srcdir)"
TESTS = ../tst/tst_sock_filter.pl ../tst/tst_conf.pl \
        ../tst/tst_httpd_cmd.pl ../tst/tst_httpd_conf.pl \
        ../tst/tst_httpd_pubonly.pl \
        ../tst/tst_httpd_none.pl \
        ../tst/tst_httpd_nonvhosts.pl \
        ../tst/tst_httpd_vhosts.pl
endif

httpdadmindir = $(sbindir)
httpdadmin_PROGRAMS = and-cntl and-httpd

httpduserdir = $(bindir)
httpduser_PROGRAMS = and-conf and-sock-filter

#ifndef OPT_SERV_H
#define OPT_SERV_H

#include "opt.h"
#include "conf.h"
#include "evnt.h"

#define OPT_SERV_CONF_BUF_SZ (128 - sizeof(Vstr_node_buf))
#define OPT_SERV_CONF_VSTR_PREALLOC_MAX 8 /* ~4 connections */
#define OPT_SERV_CONF_MEM_PREALLOC_MAX (128 * 1024)

#define OPT_SERV_CONF_USE_DAEMON FALSE
#define OPT_SERV_CONF_USE_DROP_PRIVS FALSE
#define OPT_SERV_CONF_USE_PDEATHSIG FALSE
#define OPT_SERV_CONF_DEF_RLIM_AS_CALL FALSE
#define OPT_SERV_CONF_DEF_RLIM_CORE_CALL FALSE
#define OPT_SERV_CONF_DEF_RLIM_FILE_CALL FALSE
#define OPT_SERV_CONF_DEF_TCP_DEFER_ACCEPT 8 /* HC usage txt */
#define OPT_SERV_CONF_DEF_PRIV_UID 60001
#define OPT_SERV_CONF_DEF_PRIV_GID 60001
#define OPT_SERV_CONF_DEF_NUM_PROCS 1
#define OPT_SERV_CONF_DEF_IDLE_TIMEOUT (2 * 60)
#define OPT_SERV_CONF_DEF_MAX_TIMEOUT 0 /* never */
#define OPT_SERV_CONF_USE_INSTA_CLOSE FALSE
#define OPT_SERV_CONF_DEF_Q_LISTEN_LEN 128
#define OPT_SERV_CONF_DEF_MAX_CONNECTIONS 0
#define OPT_SERV_CONF_DEF_RLIM_AS_NUM 0
#define OPT_SERV_CONF_DEF_RLIM_CORE_NUM 0
#define OPT_SERV_CONF_DEF_RLIM_FILE_NUM 0
#define OPT_SERV_CONF_USE_CAP_FOWNER FALSE
#define OPT_SERV_CONF_USE_DUMPABLE FALSE
#define OPT_SERV_CONF_VLG_DATE_FMT_TYPE VLG_DATE_FMT_SYSLOG_TRAD
#define OPT_SERV_CONF_VLG_SYSLOG_NATIVE FALSE
#define OPT_SERV_CONF_VLG_TWEAKED_SIZE FALSE
#define OPT_SERV_CONF_VLG_SIZE_DEF 0 /* syslog has 1024 limit as of FC5 */
#define OPT_SERV_CONF_VLG_SIZE_UNTWEAKED_CONSOLE    0
#define OPT_SERV_CONF_VLG_SIZE_UNTWEAKED_DAEMON  1024

typedef struct Opt_serv_policy_opts
{
 Vstr_ref *ref;
 struct Opt_serv_policy_opts *next;
 struct Opt_serv_opts *beg;

 Vstr_base *policy_name;

 struct Evnt_limit io_limit;
 Vstr_ref *ref_io_limit;
 struct Evnt_limit io_nslimit;

 unsigned int idle_timeout;
 unsigned int max_timeout;
 
 unsigned int max_connections;
 
 unsigned int use_insta_close : 1;
} Opt_serv_policy_opts; /* NOTE: remember to copy changes to
                         * opt_policy.c:opt_policy_init
                         * opt_policy.h:opt_policy_copy */

typedef struct Opt_serv_addr_opts
{
 struct Opt_serv_addr_opts *next;
 Vstr_base *acpt_filter_file;
 Vstr_base *acpt_address;
 Vstr_base *acpt_cong; /* tcp only */
 Vstr_base *def_policy;
 sa_family_t family;
 unsigned short tcp_port; /* tcp/udp/etc. only */
 unsigned int defer_accept; /* tcp only */
 unsigned int q_listen_len;
 unsigned int max_connections;
 unsigned int local_perms;
} Opt_serv_addr_opts;

typedef struct Opt_serv_opts
{
 Opt_serv_policy_opts *def_policy;

 Opt_serv_policy_opts *(*make_policy)(struct Opt_serv_opts *);
 int                   (*copy_policy)(struct Opt_serv_policy_opts *,
                                      const struct Opt_serv_policy_opts *);

 const char  *vers_cstr;
 const size_t vers_len;
 
 const char  *name_cstr;
       size_t name_len;
 
 unsigned int become_daemon : 1;
 unsigned int drop_privs : 1;
 unsigned int use_pdeathsig : 1;
 unsigned int no_conf_listen : 1;
 
 unsigned int rlim_as_call : 1;
 unsigned int rlim_core_call : 1;
 unsigned int rlim_file_call : 1;
 
 unsigned int keep_cap_fowner : 1; /* 8 */
 
 unsigned int make_dumpable : 1;

 unsigned int vlg_date_fmt_type : 2;

 unsigned int vlg_syslog_native : 1;

 unsigned int vlg_tweaked_size : 1; /* not user settable */

 size_t vlg_size;
 
 Vstr_base *pid_file;
 Vstr_base *cntl_file;
 Vstr_base *chroot_dir;

 Vstr_base *poll_backend;
 
 Vstr_base *vpriv_uid;
 Vstr_base *vpriv_gid;
 
 uid_t priv_uid;
 gid_t priv_gid;
 unsigned int num_procs;

 unsigned int syslog_facility;
 
 unsigned int rlim_as_num;
 unsigned int rlim_core_num;
 unsigned int rlim_file_num;

 struct Evnt_limit io_limit;
 Vstr_ref *ref_io_limit;
 struct Evnt_limit io_nslimit;

 unsigned int max_spare_bases;
 
 unsigned int max_spare_buf_nodes;
 unsigned int max_spare_ptr_nodes;
 unsigned int max_spare_ref_nodes;
 
 Opt_serv_addr_opts *addr_beg;
} Opt_serv_opts;
    
/* uid/gid default to NFS nobody */
#define OPT_SERV_CONF_INIT_OPTS(x, y)                                   \
    NULL,                                                               \
    opt_policy_make,                                                    \
    opt_policy_copy,                                                    \
    x,                                                                  \
    sizeof(x) - 1,                                                      \
    y,                                                                  \
    sizeof(y) - 1,                                                      \
    OPT_SERV_CONF_USE_DAEMON,                                           \
    OPT_SERV_CONF_USE_DROP_PRIVS,                                       \
    OPT_SERV_CONF_USE_PDEATHSIG,                                        \
    FALSE,                                                              \
    OPT_SERV_CONF_DEF_RLIM_AS_CALL,                                     \
    OPT_SERV_CONF_DEF_RLIM_CORE_CALL,                                   \
    OPT_SERV_CONF_DEF_RLIM_FILE_CALL,                                   \
    OPT_SERV_CONF_USE_CAP_FOWNER,                                       \
    OPT_SERV_CONF_USE_DUMPABLE,                                         \
    OPT_SERV_CONF_VLG_DATE_FMT_TYPE,                                    \
    OPT_SERV_CONF_VLG_SYSLOG_NATIVE,                                    \
    OPT_SERV_CONF_VLG_TWEAKED_SIZE,                                     \
    OPT_SERV_CONF_VLG_SIZE_DEF,                                         \
    NULL, NULL, NULL, NULL, NULL, NULL,                                 \
    OPT_SERV_CONF_DEF_PRIV_UID,                                         \
    OPT_SERV_CONF_DEF_PRIV_GID,                                         \
    OPT_SERV_CONF_DEF_NUM_PROCS,                                        \
    LOG_DAEMON,                                                         \
    OPT_SERV_CONF_DEF_RLIM_AS_NUM,                                      \
    OPT_SERV_CONF_DEF_RLIM_CORE_NUM,                                    \
    OPT_SERV_CONF_DEF_RLIM_FILE_NUM,                                    \
    {0, 0, {0,0}, 0, 0, {0,0}}, NULL,                                   \
    {0, 0, {0,0}, 0, 0, {0,0}},                                         \
    OPT_SERV_CONF_VSTR_PREALLOC_MAX,                                    \
    (OPT_SERV_CONF_MEM_PREALLOC_MAX / OPT_SERV_CONF_BUF_SZ),            \
    (OPT_SERV_CONF_MEM_PREALLOC_MAX / OPT_SERV_CONF_BUF_SZ),            \
    (OPT_SERV_CONF_MEM_PREALLOC_MAX / OPT_SERV_CONF_BUF_SZ),            \
    NULL

#define OPT_SERV_CONF_DECL_OPTS(N, x, y)                \
    Opt_serv_opts N[1] = {{OPT_SERV_CONF_INIT_OPTS(x, y)}}

extern void opt_serv_conf_free_beg(Opt_serv_opts *);
extern void opt_serv_conf_free_end(Opt_serv_opts *);
extern int  opt_serv_conf_init(Opt_serv_opts *, sa_family_t);

extern int opt_serv_conf(Opt_serv_opts *, Conf_parse *, Conf_token *)
    COMPILE_ATTR_NONNULL_A() COMPILE_ATTR_WARN_UNUSED_RET();
extern int opt_serv_conf_parse_cstr(Vstr_base *, Opt_serv_opts *, const char *)
    COMPILE_ATTR_NONNULL_A() COMPILE_ATTR_WARN_UNUSED_RET();
extern int opt_serv_conf_parse_file(Vstr_base *, Opt_serv_opts *, const char *)
    COMPILE_ATTR_NONNULL_A() COMPILE_ATTR_WARN_UNUSED_RET();

extern void opt_serv_logger(Vlg *)
    COMPILE_ATTR_NONNULL_A();

extern int opt_serv_sc_tst(Conf_parse *, Conf_token *, int *, int,
                           int (*tst_func)(Conf_parse *, Conf_token *,
                                           int *, int, void *), void *)
    COMPILE_ATTR_NONNULL_A() COMPILE_ATTR_WARN_UNUSED_RET();

extern int opt_serv_match_init(struct Opt_serv_opts *,
                               Conf_parse *, Conf_token *)
    COMPILE_ATTR_NONNULL_A() COMPILE_ATTR_WARN_UNUSED_RET();

extern void opt_serv_sc_drop_privs(Opt_serv_opts *)
    COMPILE_ATTR_NONNULL_A();
extern void opt_serv_sc_rlim_as_num(unsigned int);
extern void opt_serv_sc_rlim_core_num(unsigned int);
extern void opt_serv_sc_rlim_file_num(unsigned int);
extern int  opt_serv_sc_acpt_end(const Opt_serv_policy_opts *,
                                 struct Evnt *, struct Evnt *)
    COMPILE_ATTR_NONNULL_A() COMPILE_ATTR_WARN_UNUSED_RET();
extern void opt_serv_sc_free_beg(struct Evnt *, const char *)
    COMPILE_ATTR_NONNULL_A();
extern void opt_serv_sc_signals(void);
extern void opt_serv_sc_check_sig_children(void);
extern void opt_serv_sc_check_sig_term(void);

extern void opt_serv_sc_cntl_resources(const Opt_serv_opts *)
    COMPILE_ATTR_NONNULL_A();
extern int opt_serv_sc_append_hostname(Vstr_base *, size_t)
    COMPILE_ATTR_NONNULL_A();
extern int opt_serv_sc_append_cwd(Vstr_base *, size_t)
    COMPILE_ATTR_NONNULL_A();

extern int opt_serv_build_single_str(struct Opt_serv_opts *,
                                     const Conf_parse *, Conf_token *, int, int)
    COMPILE_ATTR_NONNULL_A() COMPILE_ATTR_WARN_UNUSED_RET();
extern int opt_serv_sc_make_str(struct Opt_serv_opts *,
                                Conf_parse *, Conf_token *,
                                Vstr_base *, size_t, size_t)
    COMPILE_ATTR_NONNULL_A() COMPILE_ATTR_WARN_UNUSED_RET();
extern int opt_serv_sc_make_static_path(struct Opt_serv_opts *,
                                        Conf_parse *, Conf_token *,
                                        Vstr_base *)
    COMPILE_ATTR_NONNULL_A() COMPILE_ATTR_WARN_UNUSED_RET();
extern int opt_serv_sc_make_static_input(struct Opt_serv_opts *,
                                         Conf_parse *, Conf_token *,
                                         Vstr_base *)
    COMPILE_ATTR_NONNULL_A() COMPILE_ATTR_WARN_UNUSED_RET();
extern int opt_serv_sc_make_uint(Conf_parse *, Conf_token *, unsigned int *)
    COMPILE_ATTR_NONNULL_A() COMPILE_ATTR_WARN_UNUSED_RET();
extern int opt_serv_sc_make_ulong(Conf_parse *, Conf_token *, unsigned long *)
    COMPILE_ATTR_NONNULL_A() COMPILE_ATTR_WARN_UNUSED_RET();
extern int opt_serv_sc_make_uintmax(Conf_parse *, Conf_token *, uintmax_t *)
    COMPILE_ATTR_NONNULL_A() COMPILE_ATTR_WARN_UNUSED_RET();


#ifndef CONF_FULL_STATIC
extern void opt_serv_sc_resolve_uid(struct Opt_serv_opts *, const char *,
                                    void (*)(const char *, int, const char *))
    COMPILE_ATTR_NONNULL_A();
extern void opt_serv_sc_resolve_gid(struct Opt_serv_opts *, const char *,
                                    void (*)(const char *, int, const char *))
    COMPILE_ATTR_NONNULL_A();
#endif

extern int opt_serv_sc_config_dir(Vstr_base *, void *, const char *,
                                  int (*)(Vstr_base *, void *, const char *))
    COMPILE_ATTR_NONNULL_A() COMPILE_ATTR_WARN_UNUSED_RET();


#define OPT_SERV_DECL_GETOPTS()                         \
   {"help", no_argument, NULL, 'h'},                    \
   {"daemon", optional_argument, NULL, 1},              \
   {"chroot", required_argument, NULL, 2},              \
   {"drop-privs", optional_argument, NULL, 3},          \
   {"priv-uid", required_argument, NULL, 4},            \
   {"priv-gid", required_argument, NULL, 5},            \
   {"pid-file", required_argument, NULL, 6},            \
   {"cntl-file", required_argument, NULL, 7},           \
   {"acpt-filter-file", required_argument, NULL, 8},    \
   {"accept-filter-file", required_argument, NULL, 8},  \
   {"processes", required_argument, NULL, 9},           \
   {"procs", required_argument, NULL, 9},               \
   {"debug", no_argument, NULL, 'd'},                   \
   {"host", required_argument, NULL, 'H'},              \
   {"local", required_argument, NULL, 'L'},             \
   {"port", required_argument, NULL, 'P'},              \
   {"nagle", optional_argument, NULL, 'n'},             \
   {"max-connections", required_argument, NULL, 'M'},   \
   {"idle-timeout", required_argument, NULL, 't'},      \
   {"defer-accept", required_argument, NULL, 10},       \
   {"io-r-limit-process", required_argument, NULL, 11}, \
   {"io-w-limit-process", required_argument, NULL, 12}, \
   {"io-r-limit-connection", required_argument, NULL, 13}, \
   {"io-w-limit-connection", required_argument, NULL, 14}, \
   {"version", no_argument, NULL, 'V'}

#define OPT_SERV_GETOPTS(opts)                                          \
    case 't': opts->def_policy->idle_timeout = atoi(optarg);        break; \
    case 'H': OPT_VSTR_ARG(opts->addr_beg->acpt_address);           break; \
    case 'L': OPT_VSTR_ARG(opts->addr_beg->acpt_address);           break; \
    case 'M': OPT_NUM_NR_ARG(opts->addr_beg->max_connections,           \
                             "max connections");                        \
    opts->def_policy->max_connections = opts->addr_beg->max_connections; \
    break;                                                              \
    case 'P': OPT_NUM_ARG(opts->addr_beg->tcp_port, "tcp port",         \
                          0, 65535, "");                                \
    opts->no_conf_listen = FALSE; break;                                \
    case 'd': vlg_debug(vlg);                                       break; \
                                                                        \
    case 'n': OPT_TOGGLE_ARG(evnt_opt_nagle);                       break; \
                                                                        \
    case 1: OPT_TOGGLE_ARG(opts->become_daemon);                    break; \
    case 2: OPT_VSTR_ARG(opts->chroot_dir);                         break; \
    case 3: OPT_TOGGLE_ARG(opts->drop_privs);                       break; \
    case 4: OPT_VSTR_ARG(opts->vpriv_uid);                          break; \
    case 5: OPT_VSTR_ARG(opts->vpriv_gid);                          break; \
    case 6: OPT_VSTR_ARG(opts->pid_file);                           break; \
    case 7: OPT_VSTR_ARG(opts->cntl_file);                          break; \
    case 8: OPT_VSTR_ARG(opts->addr_beg->acpt_filter_file);         break; \
    case 9: OPT_NUM_ARG(opts->num_procs, "number of processes",         \
                        1, 255, "");                                break; \
    case 10: OPT_NUM_ARG(opts->addr_beg->defer_accept,                  \
                         "seconds to defer connections",                \
                         0, 4906, " (1 hour 8 minutes)");           break; \
    case 11: OPT_NUM_NR_ARG(opts->io_limit.io_w_max,                    \
                            "process read limit");                  break; \
    case 12: OPT_NUM_NR_ARG(opts->io_limit.io_w_max,                    \
                            "process write limit");                 break; \
    case 13: OPT_NUM_NR_ARG(opts->io_nslimit.io_w_max,                  \
                            "connection read limit");               break; \
    case 14: OPT_NUM_NR_ARG(opts->io_nslimit.io_w_max,                  \
                            "connection write limit");              break
    


/* simple typer for EQ */
#define OPT_SERV_SYM_EQ(x)                      \
    conf_token_cmp_sym_cstr_eq(conf, token, x)

/* eXport data from configuration file to structs... */
#define OPT_SERV_X_TOGGLE(x) do {                               \
      int opt__val = (x);                                       \
                                                                \
      if (conf_sc_token_parse_toggle(conf, token, &opt__val))   \
        return (FALSE);                                         \
      (x) = opt__val;                                           \
    } while (FALSE)

#define OPT_SERV_X_NEG_TOGGLE(x) do {                           \
      int opt__val = !(x);                                      \
                                                                \
      if (conf_sc_token_parse_toggle(conf, token, &opt__val))   \
        return (FALSE);                                         \
      (x) = !opt__val;                                          \
    } while (FALSE)

#define OPT_SERV_X_SINGLE_UINT(x) do {                          \
      unsigned int opt__val = 0;                                \
                                                                \
      if (conf_sc_token_parse_uint(conf, token, &opt__val))     \
        return (FALSE);                                         \
      (x) = opt__val;                                           \
    } while (FALSE)

#define OPT_SERV_X_UINT(x) do {                                 \
      unsigned int opt__val = 0;                                \
                                                                \
      if (!opt_serv_sc_make_uint(conf, token, &opt__val))       \
        return (FALSE);                                         \
      (x) = opt__val;                                           \
    } while (FALSE)

#define OPT_SERV_X_SINGLE_ULONG(x) do {                         \
      unsigned long opt__val = 0;                               \
                                                                \
      if (conf_sc_token_parse_uint(conf, token, &opt__val))     \
        return (FALSE);                                         \
      (x) = opt__val;                                           \
    } while (FALSE)

#define OPT_SERV_X_ULONG(x) do {                                \
      unsigned long opt__val = 0;                               \
                                                                \
      if (!opt_serv_sc_make_ulong(conf, token, &opt__val))      \
        return (FALSE);                                         \
      (x) = opt__val;                                           \
    } while (FALSE)

#define OPT_SERV_X_SINGLE_UINTMAX(x) do {                       \
      uintmax_t opt__val = 0;                                   \
                                                                \
      if (conf_sc_token_parse_uintmax(conf, token, &opt__val))  \
        return (FALSE);                                         \
      (x) = opt__val;                                           \
    } while (FALSE)

#define OPT_SERV_X_UINTMAX(x) do {                              \
      uintmax_t opt__val = 0;                                   \
                                                                \
      if (!opt_serv_sc_make_uintmax(conf, token, &opt__val))    \
        return (FALSE);                                         \
      (x) = opt__val;                                           \
    } while (FALSE)

/* take either a number or one of a few symbols, allow clist around symbols */
#define OPT_SERV_X_SYM__NUM_BEG(x)                                      \
      if (!ern)                                                         \
        (x) = val;                                                      \
      else                                                              \
      {                                                                 \
        const Vstr_sect_node *pv = NULL;                                \
        int clist_num = FALSE;                                          \
                                                                        \
        if ((ern == CONF_SC_TYPE_RET_ERR_PARSE) &&                      \
            !(pv = conf_token_value(token)))                            \
          CONF_SC_TOGGLE_CLIST_VAR(clist_num);                          \
        if (ern && !(pv = conf_token_value(token)))                     \
          return (FALSE);                                               \
                                                                        \
        if (0) do { } while (FALSE)
    
#define OPT_SERV_X_SYM_SINGLE_UINT_BEG(x) do {                          \
      unsigned int val = 0;                                             \
      int ern = 0;                                                      \
                                                                        \
      ern = conf_sc_token_parse_uint(conf, token, &val);                \
      OPT_SERV_X_SYM__NUM_BEG(x)

#define OPT_SERV_X_SYM_UINT_BEG(x) do {                                 \
      unsigned int val = (x);                                           \
      int ern = CONF_SC_TYPE_RET_OK;                                    \
      Conf_token save;                                                  \
                                                                        \
      save = *token;                                                    \
      if (!opt_serv_sc_make_uint(conf, token, &val))                    \
      {                                                                 \
        ern = CONF_SC_TYPE_RET_ERR_PARSE;                               \
        *token = save;                                                  \
        conf_parse_token(conf, token);                                  \
      }                                                                 \
      OPT_SERV_X_SYM__NUM_BEG(x)

#define OPT_SERV_X_SYM_SINGLE_ULONG_BEG(x) do {                         \
      unsigned long val = 0;                                            \
      int ern = 0;                                                      \
                                                                        \
      ern = conf_sc_token_parse_ulong(conf, token, &val);               \
      OPT_SERV_X_SYM__NUM_BEG(x)

#define OPT_SERV_X_SYM_ULONG_BEG(x) do {                                \
      unsigned long val = (x);                                          \
      int ern = CONF_SC_TYPE_RET_OK;                                    \
      Conf_token save;                                                  \
                                                                        \
      save = *token;                                                    \
      if (!opt_serv_sc_make_ulong(conf, token, &val))                   \
      {                                                                 \
        ern = CONF_SC_TYPE_RET_ERR_PARSE;                               \
        *token = save;                                                  \
        conf_parse_token(conf, token);                                  \
      }                                                                 \
      OPT_SERV_X_SYM__NUM_BEG(x)

#define OPT_SERV_X_SYM_SINGLE_UINTMAX_BEG(x) do {                       \
      uintmax_t val = 0;                                                \
      int ern = 0;                                                      \
                                                                        \
      ern = conf_sc_token_parse_uintmax(conf, token, &val);             \
      OPT_SERV_X_SYM__NUM_BEG(x)

#define OPT_SERV_X_SYM_UINTMAX_BEG(x) do {                              \
      uintmax_t val = (x);                                              \
      int ern = CONF_SC_TYPE_RET_OK;                                    \
      Conf_token save;                                                  \
                                                                        \
      save = *token;                                                    \
      if (!opt_serv_sc_make_uintmax(conf, token, &val))                 \
      {                                                                 \
        ern = CONF_SC_TYPE_RET_ERR_PARSE;                               \
        *token = save;                                                  \
        conf_parse_token(conf, token);                                  \
      }                                                                 \
      OPT_SERV_X_SYM__NUM_BEG(x)

#define OPT_SERV_X_SYM_NUM_END()                                        \
        else return (FALSE);                                            \
      }                                                                 \
    } while (FALSE)

#define OPT_SERV_X__ESC_VSTR(x, p, l) do {                              \
      if ((token->type == CONF_TOKEN_TYPE_QUOTE_ESC_D) ||               \
          (token->type == CONF_TOKEN_TYPE_QUOTE_ESC_DDD) ||             \
          (token->type == CONF_TOKEN_TYPE_QUOTE_ESC_S) ||               \
          (token->type == CONF_TOKEN_TYPE_QUOTE_ESC_SSS) ||             \
          FALSE)                                                        \
        if (!conf_sc_conv_unesc((x), p, l, NULL))                       \
          return (FALSE);                                               \
    } while (FALSE)

#define OPT_SERV_X__SINGLE_VSTR(x, p, l) do {                           \
      if (conf_sc_token_sub_vstr(conf, token, x, p, l))                 \
        return (FALSE);                                                 \
                                                                        \
      if ((x)->conf->malloc_bad)                                        \
        return (FALSE);                                                 \
      OPT_SERV_X__ESC_VSTR(x, p, token->u.node->len);                   \
    } while (FALSE)

#define OPT_SERV_X_SINGLE_VSTR(x) OPT_SERV_X__SINGLE_VSTR(x, 1, (x)->len)

#define OPT_SERV_X__VSTR(o, x, p, l) do {                       \
      if (!opt_serv_sc_make_str(o, conf, token, x, p, l))       \
        return (FALSE);                                         \
    } while (FALSE)

#define OPT_SERV_X_VSTR(o, x) OPT_SERV_X__VSTR(o, x, 1, (x)->len)

#define OPT_SERV_X_EQ(x) do {                                           \
      if (conf_sc_token_parse_eq(conf, token, (x), 1, (x)->len, matches)) \
        return (FALSE);                                                 \
    } while (FALSE)

#define OPT_SERV_X_CSTR_EQ(x) do {                                      \
      if (conf_sc_token_parse_cstr_eq(conf, token, (x), matches))       \
        return (FALSE);                                                 \
    } while (FALSE)

#define OPT_SERV_SC_MATCH_INIT(x, y) do {                               \
      unsigned int match_init__depth = token->depth_num;                \
                                                                        \
      if (!opt_serv_match_init(x, conf, token))                         \
        return (FALSE);                                                 \
                                                                        \
      while (conf_token_list_num(token, match_init__depth))             \
      {                                                                 \
        CONF_SC_PARSE_DEPTH_TOKEN_RET(conf, token, match_init__depth, FALSE); \
        CONF_SC_TOGGLE_CLIST_VAR(clist);                                \
        if (y) continue;                                                \
                                                                        \
        return (FALSE);                                                 \
      }                                                                 \
    } while (FALSE)

#ifndef CONF_FULL_STATIC
# define OPT_SERV_SC_RESOLVE_UID(opts)                  \
    opt_serv_sc_resolve_uid(opts, program_name, usage)
# define OPT_SERV_SC_RESOLVE_GID(opts)                  \
    opt_serv_sc_resolve_gid(opts, program_name, usage)
#else
# define OPT_SERV_SC_RESOLVE_UID(opts)
# define OPT_SERV_SC_RESOLVE_GID(opts)
#endif



#endif

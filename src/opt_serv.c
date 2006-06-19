#define _GNU_SOURCE 1 /* strsignal() */

#include "opt_serv.h"

#define EX_UTILS_NO_FUNCS 1
#include "ex_utils.h"

#include "opt_policy.h"

#include "mk.h"

#include "opt_conf.h"

#include <stddef.h> /* offsetof */

#include <sys/resource.h>
#include <signal.h>

#ifndef CONF_FULL_STATIC
# include <pwd.h>
# include <grp.h>
# include <sys/types.h>
#endif

#ifndef HAVE_STRSIGNAL
# define strsignal(x) ""
#endif

#ifdef RLIMIT_AS /* not sure how portable this one is,
                  * modern stuff seems to have it */
# define USE_RLIMIT_AS TRUE
#else
# define USE_RLIMIT_AS FALSE
# define RLIMIT_AS 0
#endif

#include <syslog.h>

static Vlg *vlg = NULL;


/* only called the first time, so that it can easily be used from req conf */
int opt_serv_sc_append_hostname(Vstr_base *s1, size_t pos)
{
  static char buf[256];
  static size_t len = 0;

  if (!len)
  {
    if (gethostname(buf, sizeof(buf)) == -1)
      err(EXIT_FAILURE, "gethostname");
  
    buf[sizeof(buf) - 1] = 0;
    len = strlen(buf);
  }
  
  return (vstr_add_ptr(s1, pos, buf, len));
}
static int opt_serv__init_append_hostname(void)
{
  Vstr_base *tmp = vstr_make_base(NULL);

  if (!tmp)
    return (FALSE);

  opt_serv_sc_append_hostname(tmp, 0); /* ignore error */
  
  vstr_free_base(tmp);

  return (TRUE);
}

int opt_serv_sc_append_cwd(Vstr_base *s1, size_t pos)
{
  static size_t sz = PATH_MAX;
  char *ptr = MK(sz);
  int ret = FALSE;

  if (ptr)
  {
    const size_t maxsz = 8 * PATH_MAX; /* FIXME: config. */
    char *tmp = NULL;
    
    tmp = getcwd(ptr, sz);
    while (!tmp && (errno == ERANGE) && (sz < maxsz))
    {
      sz += PATH_MAX;
      if (!MV(ptr, tmp, sz))
        break;
      tmp = getcwd(ptr, sz);
    }
  
    if (!tmp) 
      ret = vstr_add_cstr_ptr(s1, pos, "/");
    else
      ret = vstr_add_cstr_buf(s1, pos, tmp);
  }
  
  F(ptr);
  
  return (ret);
}

static int opt_serv_sc_append_env(Vstr_base *s1, size_t pos,
                                  Conf_parse *conf, Conf_token *token)
{
  const Vstr_sect_node *pv = NULL;
  const char *env_name = NULL;
  const char *env_data = NULL;
  
  CONF_SC_PARSE_TOP_TOKEN_RET(conf, token, FALSE);
  if (!(pv = conf_token_value(token)))
    return (FALSE);
  
  if (!(env_name = vstr_export_cstr_ptr(conf->data, pv->pos, pv->len)))
    return (FALSE);
  
  env_data = getenv(env_name);
  if (!env_data) env_data = "";
  
  return (vstr_add_cstr_buf(s1, pos, env_data));
}

#ifdef CONF_FULL_STATIC /* just ignore it, if using full-static */
# define OPT_SERV_SC_APPEND_HOMEDIR(w, x, y, z) CONF_SC_PARSE_TOP_TOKEN_RET(conf, token, FALSE)
#else
static int opt_serv_sc_append_homedir(Vstr_base *s1, size_t pos,
                                      Conf_parse *conf, Conf_token *token)
{
  const Vstr_sect_node *pv = NULL;
  const char *usr_name = NULL;
  const char *usr_data = "";
  struct passwd *pw = NULL;
  
  CONF_SC_PARSE_TOP_TOKEN_RET(conf, token, FALSE);
  if (!(pv = conf_token_value(token)))
    return (FALSE);
  if (!(usr_name = vstr_export_cstr_ptr(conf->data, pv->pos, pv->len)))
    return (FALSE);
  
  if ((pw = getpwnam(usr_name)))
    usr_data = pw->pw_dir;
  
  return (vstr_add_cstr_buf(s1, pos, usr_data));
}
# define OPT_SERV_SC_APPEND_HOMEDIR(w, x, y, z) \
    opt_serv_sc_append_homedir(w, x, y, z)
#endif


int opt_serv_sc_tst(Conf_parse *conf, Conf_token *token,
                    int *matches, int prev_match,
                    int (*tst_func)(Conf_parse *, Conf_token *,
                                    int *, int, void *), void *data)
{
  if (0) { }
  
  else if (OPT_SERV_SYM_EQ("else")  || OPT_SERV_SYM_EQ("ELSE"))
    *matches = !prev_match;
  else if (OPT_SERV_SYM_EQ("true")  || OPT_SERV_SYM_EQ("TRUE"))
    *matches = TRUE;
  else if (OPT_SERV_SYM_EQ("false") || OPT_SERV_SYM_EQ("FALSE"))
    *matches = FALSE;
  
  else if (OPT_SERV_SYM_EQ("not") || OPT_SERV_SYM_EQ("NOT") ||
           OPT_SERV_SYM_EQ("!"))
  {
    CONF_SC_PARSE_TOP_TOKEN_RET(conf, token, FALSE);
    if (!(*tst_func)(conf, token, matches, prev_match, data))
      return (FALSE);
    *matches = !*matches;
  }
  else if (OPT_SERV_SYM_EQ("or") || OPT_SERV_SYM_EQ("OR") ||
           OPT_SERV_SYM_EQ("||"))
  {
    unsigned int depth = token->depth_num;

    while (conf_token_list_num(token, depth))
    {
      int or_matches = TRUE;
    
      CONF_SC_PARSE_DEPTH_TOKEN_RET(conf, token, depth, FALSE);
      if (!(*tst_func)(conf, token, &or_matches, prev_match, data))
        return (FALSE);

      if (or_matches)
      {
        int ret = conf_parse_end_token(conf, token, depth);
        ASSERT(ret);
        return (TRUE);
      }
    }

    *matches = FALSE;
  }
  else if (OPT_SERV_SYM_EQ("and") || OPT_SERV_SYM_EQ("AND") ||
           OPT_SERV_SYM_EQ("&&"))
  {
    unsigned int depth = token->depth_num;

    while (conf_token_list_num(token, depth))
    {
      CONF_SC_PARSE_DEPTH_TOKEN_RET(conf, token, depth, FALSE);
      if (!(*tst_func)(conf, token, matches, prev_match, data))
        return (FALSE);

      if (!*matches)
      {
        int ret = conf_parse_end_token(conf, token, depth);
        ASSERT(ret);
        return (TRUE);
      }
    }
  }
  
  else
    return (FALSE);
  
  return (TRUE);
}

#define OPT_SERV__IOLIM_VAL(x) do {                                     \
                                                                        \
      OPT_SERV_X_SYM_ULONG_BEG(x);                                      \
      else if (OPT_SERV_SYM_EQ("<unlimited>")) (x) = 0;                 \
      else if (OPT_SERV_SYM_EQ("<default>"))   (x) = 0;                 \
      OPT_SERV_X_SYM_NUM_END();                                         \
    } while (FALSE)

static int opt_serv__conf_main_policy_d1(Opt_serv_policy_opts *opts,
                                         Conf_parse *conf, Conf_token *token,
                                         int clist)
{
  unsigned int dummy;
  
  if (0) { }
  else if (OPT_SERV_SYM_EQ("match-init"))
    OPT_SERV_SC_MATCH_INIT(opts->beg,
                           opt_serv__conf_main_policy_d1(opts, conf, token,
                                                         clist));
  
  else if (OPT_SERV_SYM_EQ("timeout"))
  {
    CONF_SC_MAKE_CLIST_BEG(timeout, clist);
    
    else if (OPT_SERV_SYM_EQ("idle"))
      OPT_SERV_X_UINT(opts->idle_timeout);
    else if (OPT_SERV_SYM_EQ("total"))
      OPT_SERV_X_SINGLE_UINT(dummy);
  
    CONF_SC_MAKE_CLIST_END();
  }
  else if (OPT_SERV_SYM_EQ("instant-close"))
    OPT_SERV_X_TOGGLE(opts->use_insta_close);
  else if (OPT_SERV_SYM_EQ("lingering-close"))
    OPT_SERV_X_NEG_TOGGLE(opts->use_insta_close);
  else if (OPT_SERV_SYM_EQ("limit"))
  {
    CONF_SC_MAKE_CLIST_BEG(limit, clist);
    
    else if (OPT_SERV_SYM_EQ("connections"))
      OPT_SERV_X_UINT(opts->max_connections);
    else if (OPT_SERV_SYM_EQ("io"))
    {
      unsigned int clist_ioo = FALSE; /* io outer */
      unsigned int clist_ioi = FALSE; /* io inner */
      
      CONF_SC_MAKE_CLIST_BEG(limit_ioo, clist_ioo);
      
      else if (OPT_SERV_SYM_EQ("policy-process/s") ||
               OPT_SERV_SYM_EQ("policy-process-per-second"))
      {
        CONF_SC_MAKE_CLIST_BEG(limit_ioi, clist_ioi);
        
        else if (OPT_SERV_SYM_EQ("read") || OPT_SERV_SYM_EQ("recv"))
          OPT_SERV__IOLIM_VAL(opts->io_limit.io_r_max);
        else if (OPT_SERV_SYM_EQ("write") || OPT_SERV_SYM_EQ("send"))
          OPT_SERV__IOLIM_VAL(opts->io_limit.io_w_max);
        
        CONF_SC_MAKE_CLIST_END();      
      }
      else if (OPT_SERV_SYM_EQ("policy-connection/s") ||
               OPT_SERV_SYM_EQ("policy-connection-per-second"))
      {
        CONF_SC_MAKE_CLIST_BEG(limit_ioi, clist_ioi);
        
        else if (OPT_SERV_SYM_EQ("read") || OPT_SERV_SYM_EQ("recv"))
          OPT_SERV__IOLIM_VAL(opts->io_nslimit.io_r_max);
        else if (OPT_SERV_SYM_EQ("write") || OPT_SERV_SYM_EQ("send"))
          OPT_SERV__IOLIM_VAL(opts->io_nslimit.io_w_max);
        
        CONF_SC_MAKE_CLIST_END();      
      }
      
      CONF_SC_MAKE_CLIST_END();    
    }
  
    CONF_SC_MAKE_CLIST_END();
  }
  else
    return (FALSE);
  
  return (TRUE);
}

static int opt_serv__conf_main_policy(Opt_serv_opts *opts,
                                      Conf_parse *conf, Conf_token *token)
{
  Opt_serv_policy_opts *popts = NULL;
  Conf_token *ntoken = NULL;
  unsigned int cur_depth = opt_policy_sc_conf_parse(opts, conf, token,
                                                    &popts, &ntoken);
  
  if (!cur_depth)
    return (FALSE);
  
  do
  {
    int clist = FALSE;
    
    CONF_SC_MAKE_CLIST_MID(cur_depth, clist);
    
    else if (opt_serv__conf_main_policy_d1(popts, conf, token, clist))
    { }
    
    CONF_SC_MAKE_CLIST_END();
  } while (ntoken &&
           (cur_depth = opt_policy_sc_conf_parse(opts, conf, token,
                                                 &popts, &ntoken)));
  
  return (TRUE);
}

static int opt_serv__match_init_tst_d1(struct Opt_serv_opts *,
                                       Conf_parse *, Conf_token *,
                                       int *, int);
static int opt_serv__match_init_tst_op_d1(Conf_parse *conf, Conf_token *token,
                                          int *matches, int prev_match,
                                          void *passed_data)
{
  struct Opt_serv_opts *opts = passed_data;

  return (opt_serv__match_init_tst_d1(opts, conf, token, matches, prev_match));
}

static int opt_serv__match_init_tst_d1(struct Opt_serv_opts *opts,
                                       Conf_parse *conf, Conf_token *token,
                                       int *matches, int prev_match)
{
  int clist = FALSE;
  
  ASSERT(matches);
  
  CONF_SC_TOGGLE_CLIST_VAR(clist);

  if (0) {}

  else if (OPT_SERV_SYM_EQ("version<=") || OPT_SERV_SYM_EQ("vers<="))
  {
    OPT_SERV_X_SINGLE_VSTR(conf->tmp);
    *matches = (vstr_cmp_vers_buf(conf->tmp, 1, conf->tmp->len,
                                  opts->vers_cstr, opts->vers_len) >= 0);
  }
  else if (OPT_SERV_SYM_EQ("version>=") || OPT_SERV_SYM_EQ("vers>="))
  {
    OPT_SERV_X_SINGLE_VSTR(conf->tmp);
    *matches = (vstr_cmp_vers_buf(conf->tmp, 1, conf->tmp->len,
                                  opts->vers_cstr, opts->vers_len) <= 0);
  }
  else if (OPT_SERV_SYM_EQ("version-eq") || OPT_SERV_SYM_EQ("vers=="))
  {
    OPT_SERV_X_SINGLE_VSTR(conf->tmp);
    *matches = (vstr_cmp_vers_buf(conf->tmp, 1, conf->tmp->len,
                                  opts->vers_cstr, opts->vers_len) == 0);
  }

  else if (OPT_SERV_SYM_EQ("name-eq") || OPT_SERV_SYM_EQ("name=="))
  {
    OPT_SERV_X_SINGLE_VSTR(conf->tmp);
    *matches = vstr_cmp_buf_eq(conf->tmp, 1, conf->tmp->len,
                               opts->name_cstr, opts->name_len);
  }

  else if (OPT_SERV_SYM_EQ("hostname-eq") ||
           OPT_SERV_SYM_EQ("hostname=="))
  {
    size_t lpos = 0;
    
    OPT_SERV_X_SINGLE_VSTR(conf->tmp);

    lpos = conf->tmp->len;
    if (!opt_serv_sc_append_hostname(conf->tmp, lpos))
      return (FALSE);
    
    if (lpos == conf->tmp->len)
      *matches = !!conf->tmp->len; /* if they are both blank, they match */
    else
    {
      size_t len = vstr_sc_posdiff(lpos + 1, conf->tmp->len);
      *matches = vstr_cmp_case_eq(conf->tmp, 1, lpos, conf->tmp, lpos + 1, len);
    }
  }

  else if (OPT_SERV_SYM_EQ("uid-eq") ||
           OPT_SERV_SYM_EQ("uid=="))
  {
    unsigned int dummy = 0;
    OPT_SERV_X_SINGLE_UINT(dummy);
    *matches = (dummy == getuid());
  }
  else if (OPT_SERV_SYM_EQ("euid-eq") ||
           OPT_SERV_SYM_EQ("euid=="))
  {
    unsigned int dummy = 0;
    OPT_SERV_X_SINGLE_UINT(dummy);
    *matches = (dummy == geteuid());
  }

  else if (OPT_SERV_SYM_EQ("debug"))
    *matches = COMPILE_DEBUG;
  
  else
    return (opt_serv_sc_tst(conf, token, matches, prev_match,
                            opt_serv__match_init_tst_op_d1, opts));

  return (TRUE);
}

int opt_serv_match_init(struct Opt_serv_opts *opts,
                        Conf_parse *conf, Conf_token *token)
{
  static int prev_match = TRUE;
  int matches = TRUE;
  unsigned int depth = token->depth_num;

  CONF_SC_PARSE_SLIST_DEPTH_TOKEN_RET(conf, token, depth, FALSE);
  ++depth;
  while (conf_token_list_num(token, depth))
  {
    CONF_SC_PARSE_DEPTH_TOKEN_RET(conf, token, depth, FALSE);

    if (!opt_serv__match_init_tst_d1(opts, conf, token, &matches, prev_match))
      return (FALSE);

    if (!matches)
      conf_parse_end_token(conf, token, depth - 1);
  }

  prev_match = matches;
  
  return (TRUE);
}

#define OPT_SERV__RLIM_VAL(x, y) do {                                   \
      (y) = TRUE;                                                       \
                                                                        \
      OPT_SERV_X_SYM_ULONG_BEG(x);                                      \
      else if (OPT_SERV_SYM_EQ("<infinity>"))  (x) = RLIM_INFINITY;     \
      else if (OPT_SERV_SYM_EQ("<unlimited>")) (x) = RLIM_INFINITY;     \
      else if (OPT_SERV_SYM_EQ("<default>"))   (y) = FALSE;             \
      OPT_SERV_X_SYM_NUM_END();                                         \
    } while (FALSE)


#define OPT_SERV__TMP_EQ(x) vstr_cmp_cstr_eq(conf->tmp, 1, conf->tmp->len, x)

static int opt_serv__conf_d1(struct Opt_serv_opts *opts,
                             Conf_parse *conf, Conf_token *token,
                             int clist)
{
  if (0) { }

  else if (OPT_SERV_SYM_EQ("match-init"))
    OPT_SERV_SC_MATCH_INIT(opts, opt_serv__conf_d1(opts, conf, token, clist));
  
  else if (OPT_SERV_SYM_EQ("policy"))
  {
    if (!opt_serv__conf_main_policy(opts, conf, token))
      return (FALSE);
  }
  
  else if (OPT_SERV_SYM_EQ("chroot"))
    return (opt_serv_sc_make_static_path(opts, conf, token, opts->chroot_dir));
  else if (OPT_SERV_SYM_EQ("cntl-file") ||
           OPT_SERV_SYM_EQ("control-file"))
    return (opt_serv_sc_make_static_path(opts, conf, token, opts->cntl_file));
  else if (OPT_SERV_SYM_EQ("daemonize") || OPT_SERV_SYM_EQ("daemonise"))
    OPT_SERV_X_TOGGLE(opts->become_daemon);
  else if (OPT_SERV_SYM_EQ("drop-privs"))
  {
    unsigned int depth = token->depth_num;
    int val = opts->drop_privs;
    int ern = conf_sc_token_parse_toggle(conf, token, &val);
    unsigned int num = conf_token_list_num(token, token->depth_num);
    
    if (ern == CONF_SC_TYPE_RET_ERR_NO_MATCH)
      return (FALSE);
    if (!val && num)
      return (FALSE);

    opts->drop_privs = val;
    CONF_SC_MAKE_CLIST_MID(depth, clist);

    else if (OPT_SERV_SYM_EQ("uid"))
      OPT_SERV_X_SINGLE_UINT(opts->priv_uid);
    else if (OPT_SERV_SYM_EQ("usrname") ||
             OPT_SERV_SYM_EQ("username"))
      OPT_SERV_X_VSTR(opts, opts->vpriv_uid);
    else if (OPT_SERV_SYM_EQ("gid"))
      OPT_SERV_X_SINGLE_UINT(opts->priv_gid);
    else if (OPT_SERV_SYM_EQ("grpname") ||
             OPT_SERV_SYM_EQ("groupname"))
      OPT_SERV_X_VSTR(opts, opts->vpriv_gid);
    else if (OPT_SERV_SYM_EQ("keep-CAP_FOWNER") ||
             OPT_SERV_SYM_EQ("keep-cap-fowner"))
      OPT_SERV_X_TOGGLE(opts->keep_cap_fowner);

    CONF_SC_MAKE_CLIST_END();
  }
  else if (OPT_SERV_SYM_EQ("dumpable"))
    OPT_SERV_X_TOGGLE(opts->make_dumpable);
  else if (OPT_SERV_SYM_EQ("listen"))
  {
    Opt_serv_addr_opts *addr = opt_serv_make_addr(opts);
    CONF_SC_MAKE_CLIST_BEG(listen, clist);

    else if (!addr) return (FALSE);
    
    else if (OPT_SERV_SYM_EQ("defer-accept"))
      OPT_SERV_X_UINT(addr->defer_accept);
    else if (OPT_SERV_SYM_EQ("port"))
      OPT_SERV_X_UINT(addr->tcp_port);
    else if (OPT_SERV_SYM_EQ("addr") || OPT_SERV_SYM_EQ("address"))
      OPT_SERV_X_VSTR(opts, addr->ipv4_address);
    else if (OPT_SERV_SYM_EQ("queue-length"))
    {
      OPT_SERV_X_SYM_UINT_BEG(addr->q_listen_len);
      else if (OPT_SERV_SYM_EQ("<max>")) addr->q_listen_len = SOMAXCONN;
      OPT_SERV_X_SYM_NUM_END();
    }
    else if (OPT_SERV_SYM_EQ("filter"))
    {
      if (!opt_serv_sc_make_static_path(opts, conf, token,
                                        addr->acpt_filter_file))
        return (FALSE);
    }
    else if (OPT_SERV_SYM_EQ("max-connections"))
      OPT_SERV_X_UINT(addr->max_connections);

    CONF_SC_MAKE_CLIST_END();
  }
  else if (OPT_SERV_SYM_EQ("parent-death-signal"))
    OPT_SERV_X_TOGGLE(opts->use_pdeathsig);
  else if (OPT_SERV_SYM_EQ("pid-file"))
    return (opt_serv_sc_make_static_path(opts, conf, token, opts->pid_file));
  else if (OPT_SERV_SYM_EQ("processes") ||
           OPT_SERV_SYM_EQ("procs"))
  {
    OPT_SERV_X_SYM_UINT_BEG(opts->num_procs);
    
    else if (OPT_SERV_SYM_EQ("<sysconf-number-processors-configured>") ||
             OPT_SERV_SYM_EQ("<sysconf-num-procs-configured>") ||
             OPT_SERV_SYM_EQ("<sysconf-num-procs-conf>"))
      opts->num_procs = sysconf(_SC_NPROCESSORS_CONF);
    else if (OPT_SERV_SYM_EQ("<sysconf-number-processors-online>") ||
             OPT_SERV_SYM_EQ("<sysconf-num-procs-online>") ||
             OPT_SERV_SYM_EQ("<sysconf-num-procs-onln>"))
      opts->num_procs = sysconf(_SC_NPROCESSORS_ONLN);
    
    OPT_SERV_X_SYM_NUM_END();    
  }
  else if (OPT_SERV_SYM_EQ("logging"))
  {
    CONF_SC_MAKE_CLIST_BEG(logging_main, clist);
    
    else if (OPT_SERV_SYM_EQ("syslog"))
    {
      CONF_SC_MAKE_CLIST_BEG(logging_syslog, clist);
      else if (OPT_SERV_SYM_EQ("facility"))
      {
        OPT_SERV_X_SINGLE_VSTR(conf->tmp);
        if (0) { }
        
        else if (OPT_SERV__TMP_EQ("AUTHPRIV") ||
                 OPT_SERV__TMP_EQ("AUTH"))
          opts->syslog_facility = LOG_AUTHPRIV;
        else if (OPT_SERV__TMP_EQ("CRON"))   opts->syslog_facility = LOG_CRON;
        else if (OPT_SERV__TMP_EQ("DAEMON")) opts->syslog_facility = LOG_DAEMON;
        else if (OPT_SERV__TMP_EQ("FTP"))    opts->syslog_facility = LOG_FTP;
        else if (OPT_SERV__TMP_EQ("LOCAL"))
        {
          unsigned int num = 0;
          
          OPT_SERV_X_SINGLE_UINT(num);
          switch (num)
          {
            default: return (FALSE);
            case 0: opts->syslog_facility = LOG_LOCAL0;
            case 1: opts->syslog_facility = LOG_LOCAL1;
            case 2: opts->syslog_facility = LOG_LOCAL2;
            case 3: opts->syslog_facility = LOG_LOCAL3;
            case 4: opts->syslog_facility = LOG_LOCAL4;
            case 5: opts->syslog_facility = LOG_LOCAL5;
            case 6: opts->syslog_facility = LOG_LOCAL6;
            case 7: opts->syslog_facility = LOG_LOCAL7;
          }
        }
        else if (OPT_SERV__TMP_EQ("LOCAL0")) opts->syslog_facility = LOG_LOCAL0;
        else if (OPT_SERV__TMP_EQ("LOCAL1")) opts->syslog_facility = LOG_LOCAL1;
        else if (OPT_SERV__TMP_EQ("LOCAL2")) opts->syslog_facility = LOG_LOCAL2;
        else if (OPT_SERV__TMP_EQ("LOCAL3")) opts->syslog_facility = LOG_LOCAL3;
        else if (OPT_SERV__TMP_EQ("LOCAL4")) opts->syslog_facility = LOG_LOCAL4;
        else if (OPT_SERV__TMP_EQ("LOCAL5")) opts->syslog_facility = LOG_LOCAL5;
        else if (OPT_SERV__TMP_EQ("LOCAL6")) opts->syslog_facility = LOG_LOCAL6;
        else if (OPT_SERV__TMP_EQ("LOCAL7")) opts->syslog_facility = LOG_LOCAL7;
        else if (OPT_SERV__TMP_EQ("LPR"))    opts->syslog_facility = LOG_LPR;
        else if (OPT_SERV__TMP_EQ("MAIL"))   opts->syslog_facility = LOG_MAIL;
        else if (OPT_SERV__TMP_EQ("NEWS"))   opts->syslog_facility = LOG_NEWS;
        else if (OPT_SERV__TMP_EQ("USER"))   opts->syslog_facility = LOG_USER;
        else if (OPT_SERV__TMP_EQ("UUCP"))   opts->syslog_facility = LOG_UUCP;
        
        else
          return (FALSE);

      }
      CONF_SC_MAKE_CLIST_END();
    }
    
    CONF_SC_MAKE_CLIST_END();
  }
  else if (OPT_SERV_SYM_EQ("resource-limits") ||
           OPT_SERV_SYM_EQ("rlimit"))
  {
    CONF_SC_MAKE_CLIST_BEG(rlimit, clist);

    else if (OPT_SERV_SYM_EQ("AS")     || OPT_SERV_SYM_EQ("address-space"))
      OPT_SERV__RLIM_VAL(opts->rlim_as_num, opts->rlim_as_call);
    else if (OPT_SERV_SYM_EQ("CORE")   || OPT_SERV_SYM_EQ("core"))
      OPT_SERV__RLIM_VAL(opts->rlim_core_num, opts->rlim_core_call);
    else if (OPT_SERV_SYM_EQ("NOFILE") || OPT_SERV_SYM_EQ("fd-num") ||
             OPT_SERV_SYM_EQ("file-descriptor-number"))
      OPT_SERV__RLIM_VAL(opts->rlim_file_num, opts->rlim_file_call);
      
    CONF_SC_MAKE_CLIST_END();
  }
  /*  else if (OPT_SERV_SYM_EQ("priority"))
      OPT_SERV_X_UINT(opts->sys_priority); */
  else if (OPT_SERV_SYM_EQ("cache-limits"))
  {
    CONF_SC_MAKE_CLIST_BEG(cache_limits, clist);
    
    else if (OPT_SERV_SYM_EQ("spare-vstr-bases"))
      OPT_SERV_X_UINT(opts->max_spare_bases);
    else if (OPT_SERV_SYM_EQ("spare-vstr-nodes-buf"))
      OPT_SERV_X_UINT(opts->max_spare_buf_nodes);
    else if (OPT_SERV_SYM_EQ("spare-vstr-nodes-ptr"))
      OPT_SERV_X_UINT(opts->max_spare_ptr_nodes);
    else if (OPT_SERV_SYM_EQ("spare-vstr-nodes-ref"))
      OPT_SERV_X_UINT(opts->max_spare_ref_nodes);
    
    CONF_SC_MAKE_CLIST_END();
  }
  else if (OPT_SERV_SYM_EQ("limit"))
  {
    CONF_SC_MAKE_CLIST_BEG(limit, clist);
    
    else if (OPT_SERV_SYM_EQ("io"))
    {
      unsigned int clist_ioo = FALSE; /* io outer */
      unsigned int clist_ioi = FALSE; /* io inner */
      
      CONF_SC_MAKE_CLIST_BEG(limit_ioo, clist_ioo);
      
      else if (OPT_SERV_SYM_EQ("process/s") ||
               OPT_SERV_SYM_EQ("process-per-second"))
      {
        CONF_SC_MAKE_CLIST_BEG(limit_ioi, clist_ioi);
        
        else if (OPT_SERV_SYM_EQ("read") || OPT_SERV_SYM_EQ("recv"))
          OPT_SERV__IOLIM_VAL(opts->io_limit.io_r_max);
        else if (OPT_SERV_SYM_EQ("write") || OPT_SERV_SYM_EQ("send"))
          OPT_SERV__IOLIM_VAL(opts->io_limit.io_w_max);
        
        CONF_SC_MAKE_CLIST_END();      
      }
      else if (OPT_SERV_SYM_EQ("policy-process/s") ||
               OPT_SERV_SYM_EQ("policy-process-per-second"))
      {
        Opt_serv_policy_opts *popts = NULL;
        
        if (!(popts = opt_policy_find(opts, conf, token)))
          return (FALSE);
        
        CONF_SC_MAKE_CLIST_BEG(limit_ioi, clist_ioi);
        
        else if (OPT_SERV_SYM_EQ("read") || OPT_SERV_SYM_EQ("recv"))
          OPT_SERV__IOLIM_VAL(popts->io_limit.io_r_max);
        else if (OPT_SERV_SYM_EQ("write") || OPT_SERV_SYM_EQ("send"))
          OPT_SERV__IOLIM_VAL(popts->io_limit.io_w_max);
        
        CONF_SC_MAKE_CLIST_END();      
      }
      else if (OPT_SERV_SYM_EQ("policy-connection/s") ||
               OPT_SERV_SYM_EQ("policy-connection-per-second"))
      {
        Opt_serv_policy_opts *popts = NULL;
        
        if (!(popts = opt_policy_find(opts, conf, token)))
          return (FALSE);
        
        CONF_SC_MAKE_CLIST_BEG(limit_ioi, clist_ioi);
        
        else if (OPT_SERV_SYM_EQ("read") || OPT_SERV_SYM_EQ("recv"))
          OPT_SERV__IOLIM_VAL(popts->io_nslimit.io_r_max);
        else if (OPT_SERV_SYM_EQ("write") || OPT_SERV_SYM_EQ("send"))
          OPT_SERV__IOLIM_VAL(popts->io_nslimit.io_w_max);
        
        CONF_SC_MAKE_CLIST_END();      
      }
      else if (OPT_SERV_SYM_EQ("connection/s") ||
               OPT_SERV_SYM_EQ("connection-per-second"))
      {
        CONF_SC_MAKE_CLIST_BEG(limit_ioi, clist_ioi);
        
        else if (OPT_SERV_SYM_EQ("read") || OPT_SERV_SYM_EQ("recv"))
          OPT_SERV__IOLIM_VAL(opts->io_nslimit.io_r_max);
        else if (OPT_SERV_SYM_EQ("write") || OPT_SERV_SYM_EQ("send"))
          OPT_SERV__IOLIM_VAL(opts->io_nslimit.io_w_max);
        
        CONF_SC_MAKE_CLIST_END();
      }
      
      CONF_SC_MAKE_CLIST_END();    
    }
  
    CONF_SC_MAKE_CLIST_END();
  }
  
  else
    return (FALSE);
  
  return (TRUE);
}
#undef OPT_SERV__RLIM_VAL

int opt_serv_conf(struct Opt_serv_opts *opts,
                  Conf_parse *conf, Conf_token *token)
{
  unsigned int cur_depth = token->depth_num;
  int clist = FALSE;
  
  ASSERT(opts && conf && token);

  if (!conf_token_cmp_sym_cstr_eq(conf, token, "org.and.daemon-conf-1.0"))
    return (FALSE);
  
  CONF_SC_MAKE_CLIST_MID(cur_depth, clist);
  
  else if (opt_serv__conf_d1(opts, conf, token, clist))
  { }
  
  CONF_SC_MAKE_CLIST_END();
  
  /* And they all live together ... dum dum */
  if (conf->data->conf->malloc_bad)
    return (FALSE);

  return (TRUE);
}

int opt_serv_conf_parse_cstr(Vstr_base *out,
                             Opt_serv_opts *opts, const char *data)
{
  Conf_parse *conf    = conf_parse_make(NULL);
  Conf_token token[1] = {CONF_TOKEN_INIT};

  ASSERT(opts && data);
  
  if (!conf)
    goto conf_malloc_fail;
  
  if (!vstr_add_cstr_ptr(conf->data, conf->data->len,
                         "(org.and.daemon-conf-1.0 "))
    goto read_malloc_fail;
  if (!vstr_add_cstr_ptr(conf->data, conf->data->len, data))
    goto read_malloc_fail;
  if (!vstr_add_cstr_ptr(conf->data, conf->data->len,
                         ")"))
    goto read_malloc_fail;

  if (!conf_parse_lex(conf, 1, conf->data->len))
    goto conf_fail;

  if (!conf_parse_token(conf, token))
    goto conf_fail;
    
  if ((token->type != CONF_TOKEN_TYPE_CLIST) || (token->depth_num != 1))
    goto conf_fail;
    
  if (!conf_parse_token(conf, token))
    goto conf_fail;

  ASSERT(conf_token_cmp_sym_cstr_eq(conf, token, "org.and.daemon-conf-1.0"));
  
  if (!opt_serv_conf(opts, conf, token))
    goto conf_fail;
  if (token->num != conf->sects->num)
    goto conf_fail;

  conf_parse_free(conf);
  return (TRUE);
  
 conf_fail:
  conf_parse_backtrace(out, data, conf, token);
 read_malloc_fail:
  conf_parse_free(conf);
 conf_malloc_fail:
  return (FALSE);
}

int opt_serv_conf_parse_file(Vstr_base *out,
                             Opt_serv_opts *opts, const char *fname)
{
  Conf_parse *conf    = conf_parse_make(NULL);
  Conf_token token[1] = {CONF_TOKEN_INIT};

  ASSERT(opts && fname);
  
  if (!conf)
    goto conf_malloc_fail;
  
  if (!vstr_sc_read_len_file(conf->data, 0, fname, 0, 0, NULL))
    goto read_malloc_fail;

  if (!conf_parse_lex(conf, 1, conf->data->len))
    goto conf_fail;

  while (conf_parse_token(conf, token))
  {
    if ((token->type != CONF_TOKEN_TYPE_CLIST) || (token->depth_num != 1))
      goto conf_fail;

    if (!conf_parse_token(conf, token))
      goto conf_fail;
    
    if (!conf_token_cmp_sym_cstr_eq(conf, token, "org.and.daemon-conf-1.0"))
      goto conf_fail;
  
    if (!opt_serv_conf(opts, conf, token))
      goto conf_fail;
  }

  conf_parse_free(conf);
  return (TRUE);
  
 conf_fail:
  conf_parse_backtrace(out, fname, conf, token);
  errno = 0;
 read_malloc_fail:
  if (errno && out) /* can't find config. file */
    vstr_add_fmt(out, out->len, "open(%s): %m", fname);
  conf_parse_free(conf);
 conf_malloc_fail:
  return (FALSE);
}

void opt_serv_conf_free_beg(struct Opt_serv_opts *opts)
{
  Opt_serv_addr_opts *scan = NULL;
  
  if (!opts)
    return;
  
  vstr_free_base(opts->pid_file);         opts->pid_file         = NULL;
  vstr_free_base(opts->cntl_file);        opts->cntl_file        = NULL;
  vstr_free_base(opts->chroot_dir);       opts->chroot_dir       = NULL;
  vstr_free_base(opts->vpriv_uid);        opts->vpriv_uid        = NULL;
  vstr_free_base(opts->vpriv_gid);        opts->vpriv_gid        = NULL;

  scan = opts->addr_beg;
  opts->addr_beg = NULL;
  while (scan)
  {
    Opt_serv_addr_opts *scan_next = scan->next;
    
    vstr_free_base(scan->acpt_filter_file);
    vstr_free_base(scan->ipv4_address);
    F(scan);

    scan = scan_next;
  }
}

void opt_serv_conf_free_end(struct Opt_serv_opts *opts)
{
  if (!opts)
    return;

  ASSERT( opts->ref_io_limit);
  vstr_ref_del(opts->ref_io_limit);
  ASSERT(!opts->ref_io_limit);
}

static void opt_serv__io_lim_ref_cb(struct Vstr_ref *ref)
{
  Opt_serv_opts *opts = NULL;
  struct Evnt_limit *lim = NULL;

  if (!ref)
    return;
  
  lim = ref->ptr;
  ASSERT(lim);
  
  /* ISO C magic, converts a ptr to io_limit into a pointer to opts */
  opts = (Opt_serv_opts *)(((char *)lim) - offsetof(Opt_serv_opts, io_limit));
  opts->ref_io_limit = NULL; /* more magic */
}

int opt_serv_conf_init(Opt_serv_opts *opts)
{
  struct Opt_serv_policy_opts *popts = NULL;
  Opt_serv_addr_opts *addr = MK(sizeof(Opt_serv_addr_opts));
  
  ASSERT(opts && opts->make_policy && opts->copy_policy);

  if (!addr)
    goto mk_addr_fail;

  if (!opt_serv__init_append_hostname())
    goto mk_append_hostname_fail;
  
  if (!(popts = (*opts->make_policy)(opts)))
    goto mk_policy_fail;

  opts->def_policy = popts;
  vstr_add_cstr_ptr(popts->policy_name, 0, OPT_POLICY_CONF_DEF_POLICY_NAME);

  if (popts->policy_name->conf->malloc_bad)
    goto policy_init_fail;

  opts->pid_file         = vstr_make_base(NULL);
  opts->cntl_file        = vstr_make_base(NULL);
  opts->chroot_dir       = vstr_make_base(NULL);
  opts->vpriv_uid        = vstr_make_base(NULL);
  opts->vpriv_gid        = vstr_make_base(NULL);
  addr->acpt_filter_file = vstr_make_base(NULL);
  addr->ipv4_address     = vstr_make_base(NULL);
  opts->ref_io_limit     = vstr_ref_make_ptr(&opts->io_limit,
                                             opt_serv__io_lim_ref_cb);
    
  if (!opts->pid_file         ||
      !opts->cntl_file        ||
      !opts->chroot_dir       ||
      !opts->vpriv_uid        ||
      !opts->vpriv_gid        ||
      !addr->acpt_filter_file ||
      !addr->ipv4_address     ||
      !opts->ref_io_limit     ||
      FALSE)
    goto opts_init_fail;

  addr->next = NULL;
  
  addr->tcp_port        = 0;
  addr->defer_accept    = OPT_SERV_CONF_DEF_TCP_DEFER_ACCEPT;
  addr->q_listen_len    = OPT_SERV_CONF_DEF_Q_LISTEN_LEN;
  addr->max_connections = OPT_SERV_CONF_DEF_MAX_CONNECTIONS;
  
  opts->addr_beg = addr;

  opts->no_conf_listen = TRUE;
  
  if (!opts->ref_io_limit) /* we can't have this succeed, while others fail */
    goto opts_init_fail;
  
  return (TRUE);

 opts_init_fail:
  opt_serv_conf_free_beg(opts);
  opt_serv_conf_free_end(opts);
 policy_init_fail:
  vstr_ref_del(popts->ref);
 mk_policy_fail:
 mk_append_hostname_fail:
  F(addr);
 mk_addr_fail:
  return (FALSE);
}

#define OPT_SERV_ADDR_DUP_VSTR(x)                                       \
    vstr_dup_vstr(opts->addr_beg-> x ->conf ,                           \
                  opts->addr_beg-> x , 1, opts->addr_beg-> x ->len,     \
                  VSTR_TYPE_SUB_BUF_REF)
Opt_serv_addr_opts *opt_serv_make_addr(Opt_serv_opts *opts)
{
  Opt_serv_addr_opts *addr = NULL;

  ASSERT(opts && opts->addr_beg);
  
  if (opts->no_conf_listen)
  { /* use the initial one to start with */
    opts->no_conf_listen = FALSE;
    return (opts->addr_beg);
  }

  /* duplicate the currnet one */
  if (!(addr = MK(sizeof(Opt_serv_addr_opts))))
    goto mk_addr_fail;
    
  addr->acpt_filter_file = OPT_SERV_ADDR_DUP_VSTR(acpt_filter_file);
  addr->ipv4_address     = OPT_SERV_ADDR_DUP_VSTR(ipv4_address);
  
  if (!addr->acpt_filter_file ||
      !addr->ipv4_address     ||
      FALSE)
    goto addr_init_fail;
  
  addr->next = NULL;
  
  addr->tcp_port        = opts->addr_beg->tcp_port;
  addr->defer_accept    = opts->addr_beg->defer_accept;
  addr->q_listen_len    = opts->addr_beg->q_listen_len;
  addr->max_connections = opts->addr_beg->max_connections;

  addr->next = opts->addr_beg;
  opts->addr_beg = addr;

  return (addr);

 addr_init_fail:
  F(addr);
 mk_addr_fail:
  return (FALSE);
}

void opt_serv_logger(Vlg *passed_vlg)
{
  vlg = passed_vlg;
}

void opt_serv_sc_drop_privs(Opt_serv_opts *opts)
{
  if (setgroups(1, &opts->priv_gid) == -1)
    vlg_err(vlg, EXIT_FAILURE, "setgroups(%ld): %m\n", (long)opts->priv_gid);
      
  if (setgid(opts->priv_gid) == -1)
    vlg_err(vlg, EXIT_FAILURE, "setgid(%ld): %m\n", (long)opts->priv_gid);
  
  if (setuid(opts->priv_uid) == -1)
    vlg_err(vlg, EXIT_FAILURE, "setuid(%ld): %m\n", (long)opts->priv_uid);
}

static void opt_serv__sc_rlim_num(const char *name, int resource,
                                  unsigned int num)
{
  struct rlimit rlim[1];
    
  if (getrlimit(resource, rlim) == -1)
    vlg_err(vlg, EXIT_FAILURE, "getrlimit(RLIMIT_%s): %m\n", name);


  if (num == RLIM_INFINITY) /* only attempt upwards, if we are privilaged */
  {
    if ((rlim->rlim_max != RLIM_INFINITY) && !getuid())
      rlim->rlim_max = num;
  }
  else
  {
    if ((num > rlim->rlim_max) && !getuid())
      rlim->rlim_max = num;
  
    if (num < rlim->rlim_max) /* can always do this ? */
      rlim->rlim_max = num;
  }
  
  rlim->rlim_cur = rlim->rlim_max; /* upgrade soft to hard */
  
  if (setrlimit(resource, rlim) == -1)
    vlg_err(vlg, EXIT_FAILURE, "setrlimit(RLIMIT_%s): %m\n", name);
}

void opt_serv_sc_rlim_as_num(unsigned int rlim_as_num)
{
  if (USE_RLIMIT_AS)
    opt_serv__sc_rlim_num("AS", RLIMIT_AS, rlim_as_num);
}

void opt_serv_sc_rlim_core_num(unsigned int rlim_core_num)
{
  opt_serv__sc_rlim_num("CORE", RLIMIT_CORE, rlim_core_num);
}

void opt_serv_sc_rlim_file_num(unsigned int rlim_file_num)
{
  opt_serv__sc_rlim_num("NOFILE", RLIMIT_NOFILE, rlim_file_num);
}

int opt_serv_sc_acpt_end(const Opt_serv_policy_opts *popts,
                         struct Evnt *from_evnt, struct Evnt *evnt)
{
  Acpt_listener *acpt_listener = (Acpt_listener *)from_evnt;
  unsigned int acpt_num = acpt_listener->ref->ref - 1;  /* ref +1 for itself */
  unsigned int acpt_max = acpt_listener->max_connections;

  vlg_dbg1(vlg, "acpt: %u/%u\n", acpt_num, acpt_max);
  
  if (acpt_max && (acpt_num >= acpt_max))
  {
    vlg_dbg1(vlg, "ACPT DEL ($<sa:%p>,%u,%u)\n", EVNT_SA(from_evnt),
             acpt_num, acpt_max);
    evnt_wait_cntl_del(from_evnt, POLLIN);
  }
  
  if (popts->max_connections && (evnt_num_all() > popts->max_connections))
  {
    vlg_info(vlg, "LIMIT-BLOCKED from[$<sa:%p>]: policy $<vstr.all:%p>\n",
             EVNT_SA(evnt), popts->policy_name);
    return (FALSE);
  }
  
  vlg_info(vlg, "CONNECT from[$<sa:%p>]\n", EVNT_SA(evnt));
  
  return (TRUE);
}

void opt_serv_sc_free_beg(struct Evnt *evnt, const char *info_rep)
{
  if (EVNT_ACPT_EXISTS(evnt) && EVNT_ACPT_DATA(evnt)->evnt)
  {
    Acpt_data *acpt_data = EVNT_ACPT_DATA(evnt);
    Acpt_listener *acpt_listener = (Acpt_listener *)acpt_data->evnt;
    unsigned int acpt_num = acpt_listener->ref->ref - 1;
    unsigned int acpt_max = acpt_listener->max_connections;
  
    if (acpt_max && (acpt_num <= acpt_max)) /* note that we are going to -1 */
    {
      vlg_dbg1(vlg, "ACPT ADD ($<sa:%p>,%u,%u)\n", EVNT_SA(acpt_data->evnt),
               acpt_num, acpt_max);
      evnt_wait_cntl_add(acpt_data->evnt, POLLIN);
    }
    
    evnt_stats_add(acpt_data->evnt, evnt);
  }

  if (evnt->flag_fully_acpt)
    evnt_vlg_stats_info(evnt, info_rep);
}

#define OPT_SERV__SIG_OR_ERR(x)                 \
    if (sigaction(x, &sa, NULL) == -1)          \
      err(EXIT_FAILURE, "signal(%d:%s)", x, strsignal(x))

static void opt_serv__sig_crash(int s_ig_num)
{
  vlg_sig_abort(vlg, "SIG[%d]: %s\n", s_ig_num, strsignal(s_ig_num));
}

static void opt_serv__sig_raise_cont(int s_ig_num)
{
  struct sigaction sa;
  
  if (sigemptyset(&sa.sa_mask) == -1)
    err(EXIT_FAILURE, "signal init");

  sa.sa_flags   = SA_RESTART;
  sa.sa_handler = SIG_DFL;
  OPT_SERV__SIG_OR_ERR(s_ig_num);

  vlg_sig_warn(vlg, "SIG[%d]: %s\n", s_ig_num, strsignal(s_ig_num));
  raise(s_ig_num);
}

static void opt_serv__sig_cont(int s_ig_num)
{
  if (0) /* s_ig_num == SIGCONT) */
  {
    struct sigaction sa;
  
    if (sigemptyset(&sa.sa_mask) == -1)
      err(EXIT_FAILURE, "signal init");

    sa.sa_flags   = SA_RESTART;
    sa.sa_handler = opt_serv__sig_raise_cont;
    OPT_SERV__SIG_OR_ERR(SIGTSTP);
  }
  
  vlg_sig_info(vlg, "SIG[%d]: %s\n", s_ig_num, strsignal(s_ig_num));
}

static void opt_serv__sig_child(int s_ig_num)
{
  ASSERT(s_ig_num == SIGCHLD);
  evnt_child_exited = TRUE;
}

void opt_serv_sc_signals(void)
{
  struct sigaction sa;
  
  if (sigemptyset(&sa.sa_mask) == -1)
    err(EXIT_FAILURE, "signal init %s", "sigemptyset");
  
  /* don't use SA_RESTART ... */
  sa.sa_flags   = 0;
  /* ignore it... we don't have a use for it */
  sa.sa_handler = SIG_IGN;
  
  OPT_SERV__SIG_OR_ERR(SIGPIPE);

  sa.sa_handler = opt_serv__sig_crash;
  
  OPT_SERV__SIG_OR_ERR(SIGSEGV);
  OPT_SERV__SIG_OR_ERR(SIGBUS);
  OPT_SERV__SIG_OR_ERR(SIGILL);
  OPT_SERV__SIG_OR_ERR(SIGFPE);
  OPT_SERV__SIG_OR_ERR(SIGXFSZ);

  sa.sa_flags   = SA_RESTART;
  sa.sa_handler = opt_serv__sig_child;
  OPT_SERV__SIG_OR_ERR(SIGCHLD);
  
  sa.sa_flags   = SA_RESTART;
  sa.sa_handler = opt_serv__sig_cont; /* print, and do nothing */
  
  OPT_SERV__SIG_OR_ERR(SIGUSR1);
  OPT_SERV__SIG_OR_ERR(SIGUSR2);
  OPT_SERV__SIG_OR_ERR(SIGHUP);
  OPT_SERV__SIG_OR_ERR(SIGCONT);
  
  sa.sa_handler = opt_serv__sig_raise_cont; /* queue print, and re-raise */
  
  OPT_SERV__SIG_OR_ERR(SIGTSTP);
  OPT_SERV__SIG_OR_ERR(SIGTERM);
}
#undef SERV__SIG_OR_ERR

void opt_serv_sc_check_children(void)
{
  if (evnt_child_exited)
  {
    vlg_warn(vlg, "Child exited.\n");
    evnt_acpt_close_all();
    evnt_scan_q_close();
    evnt_child_exited = FALSE;
  }
}

void opt_serv_sc_cntl_resources(const Opt_serv_opts *opts)
{ /* cap the amount of "wasted" resources we're using */
  
  vstr_cntl_conf(NULL, VSTR_CNTL_CONF_SET_NUM_RANGE_SPARE_BASE,
                 0, opts->max_spare_bases);

  vstr_cntl_conf(NULL, VSTR_CNTL_CONF_SET_NUM_RANGE_SPARE_BUF,
                 0, opts->max_spare_buf_nodes);
  vstr_cntl_conf(NULL, VSTR_CNTL_CONF_SET_NUM_RANGE_SPARE_PTR,
                 0, opts->max_spare_ptr_nodes);
  vstr_cntl_conf(NULL, VSTR_CNTL_CONF_SET_NUM_RANGE_SPARE_REF,
                 0, opts->max_spare_ref_nodes);
}

/* into conf->tmp */
static int opt_serv__build_str(struct Opt_serv_opts *
                               COMPILE_ATTR_UNUSED(opts),
                               Conf_parse *conf, Conf_token *token,
                               int doing_init)
{
  unsigned int cur_depth = token->depth_num;
  int clist = FALSE;
  
  vstr_del(conf->tmp, 1, conf->tmp->len);
  while (conf_token_list_num(token, cur_depth))
  {
    CONF_SC_PARSE_TOP_TOKEN_RET(conf, token, FALSE);
    CONF_SC_TOGGLE_CLIST_VAR(clist);
    
    if (0) { }
    
    else if (OPT_SERV_SYM_EQ("ENV")   || OPT_SERV_SYM_EQ("ENVIRONMENT") ||
             OPT_SERV_SYM_EQ("<ENV>") || OPT_SERV_SYM_EQ("<ENVIRONMENT>"))
    {
      if (!opt_serv_sc_append_env(conf->tmp, conf->tmp->len, conf, token))
        return (FALSE);
    }
    else if (doing_init &&
             (OPT_SERV_SYM_EQ("HOME") || OPT_SERV_SYM_EQ("<HOME>")))
    {
      if (!OPT_SERV_SC_APPEND_HOMEDIR(conf->tmp, conf->tmp->len, conf, token))
        return (FALSE);
    }
    else if (OPT_SERV_SYM_EQ("<hostname>"))
      opt_serv_sc_append_hostname(conf->tmp, conf->tmp->len);
    else if (OPT_SERV_SYM_EQ("<cwd>"))
      opt_serv_sc_append_cwd(conf->tmp, conf->tmp->len);
    else if (!clist)
    { /* unknown symbol or string */
      size_t pos = conf->tmp->len + 1;
      const Vstr_sect_node *pv = conf_token_value(token);
      
      if (!pv || !vstr_add_vstr(conf->tmp, conf->tmp->len,
                                conf->data, pv->pos, pv->len,
                                VSTR_TYPE_ADD_BUF_REF))
        return (FALSE);
      
      OPT_SERV_X__ESC_VSTR(conf->tmp, pos, pv->len);
    }
    else
      return (FALSE);
  }
  
  return (!conf->tmp->conf->malloc_bad);
}

static int opt_serv__sc_make_str(struct Opt_serv_opts *opts,
                                 Conf_parse *conf, Conf_token *token,
                                 Vstr_base *s1, size_t pos, size_t len,
                                 int doing_init)
{
  int clist = FALSE;

  ASSERT(s1 != conf->tmp);
  
  CONF_SC_PARSE_TOP_TOKEN_RET(conf, token, FALSE);
  CONF_SC_TOGGLE_CLIST_VAR(clist);

  if (0) { }
  
  else if (OPT_SERV_SYM_EQ("<none>") || OPT_SERV_SYM_EQ("<empty>"))
  {
    return (vstr_del(s1, pos, len));
  }
  else if (OPT_SERV_SYM_EQ("assign") || OPT_SERV_SYM_EQ("="))
  {
    if (!opt_serv__build_str(opts, conf, token, doing_init))
      return (FALSE);
    
    return (vstr_sub_vstr(s1, pos, len,
                          conf->tmp, 1, conf->tmp->len, VSTR_TYPE_SUB_BUF_REF));
  }
  else if (OPT_SERV_SYM_EQ("append") || OPT_SERV_SYM_EQ("+=") ||
           OPT_SERV_SYM_EQ(".=") || OPT_SERV_SYM_EQ(">>="))
  {
    if (!opt_serv__build_str(opts, conf, token, doing_init))
      return (FALSE);

    return (vstr_add_vstr(s1, vstr_sc_poslast(pos, len),
                          conf->tmp, 1, conf->tmp->len, VSTR_TYPE_ADD_BUF_REF));
  }
  else if (OPT_SERV_SYM_EQ("prepend") || OPT_SERV_SYM_EQ("<<="))
  {
    if (!opt_serv__build_str(opts, conf, token, doing_init))
      return (FALSE);

    return (vstr_add_vstr(s1, pos - 1,
                          conf->tmp, 1, conf->tmp->len, VSTR_TYPE_ADD_BUF_REF));
  }
  else if (!clist)
  {
    const Vstr_sect_node *pv = conf_token_value(token);
      
    if (!pv || !vstr_sub_vstr(s1, pos, len, conf->data, pv->pos, pv->len,
                              VSTR_TYPE_SUB_BUF_REF))
      return (FALSE);
    OPT_SERV_X__ESC_VSTR(s1, pos, pv->len);

    return (TRUE);
  }

  return (FALSE);  
}

int opt_serv_sc_make_str(struct Opt_serv_opts *opts,
                         Conf_parse *conf, Conf_token *token,
                         Vstr_base *s1, size_t pos, size_t len)
{
  return (opt_serv__sc_make_str(opts, conf, token, s1, pos, len, FALSE));
}

int opt_serv_sc_make_static_path(struct Opt_serv_opts *opts,
                                 Conf_parse *conf, Conf_token *token,
                                 Vstr_base *s1)
{
  return (opt_serv__sc_make_str(opts, conf, token, s1, 1, s1->len, TRUE));
}

static int opt_serv__build_uintmax(Conf_parse *conf, Conf_token *token,
                                   uintmax_t num, uintmax_t *ret)
{
  ASSERT(ret);
  
  OPT_SERV_X_SYM_SINGLE_UINTMAX_BEG(*ret);

  else if (OPT_SERV_SYM_EQ("<num>")) *ret = num;

  OPT_SERV_X_SYM_NUM_END();
  
  return (TRUE);
}

int opt_serv_sc_make_uintmax(Conf_parse *conf, Conf_token *token,
                             uintmax_t *num)
{
  OPT_SERV_X_SYM_SINGLE_UINTMAX_BEG(*num);

  else if (OPT_SERV_SYM_EQ("none")   || OPT_SERV_SYM_EQ("zero")   ||
           OPT_SERV_SYM_EQ("NONE")   || OPT_SERV_SYM_EQ("ZERO")   ||
           OPT_SERV_SYM_EQ("<none>") || OPT_SERV_SYM_EQ("<zero>") ||
           OPT_SERV_SYM_EQ("<NONE>") || OPT_SERV_SYM_EQ("<ZERO>"))
  {
    *num = 0;
  }
  else if (OPT_SERV_SYM_EQ("assign") || OPT_SERV_SYM_EQ("="))
  {
    if (!opt_serv__build_uintmax(conf, token, *num, num))
      return (FALSE);
  }
  else if (OPT_SERV_SYM_EQ("add") || OPT_SERV_SYM_EQ("+="))
  {
    uintmax_t tmp = 0;
    
    if (!opt_serv__build_uintmax(conf, token, *num, &tmp))
      return (FALSE);

    if ((tmp + *num) < tmp)
      return (FALSE);
    
    *num += tmp;
  }
  else if (OPT_SERV_SYM_EQ("remove") || OPT_SERV_SYM_EQ("-="))
  {
    uintmax_t tmp = 0;
    
    if (!opt_serv__build_uintmax(conf, token, *num, &tmp))
      return (FALSE);

    if (tmp > *num)
      return (FALSE);
    
    *num -= tmp;
  }
  else if (OPT_SERV_SYM_EQ("multiply") || OPT_SERV_SYM_EQ("*="))
  {
    uintmax_t tmp = 0;
    
    if (!opt_serv__build_uintmax(conf, token, *num, &tmp))
      return (FALSE);

    /* FIXME: this doesn't actually work, but it's better than nothing */
    if ((tmp * *num) < tmp)
      return (FALSE);
    
    *num *= tmp;
  }
  else if (OPT_SERV_SYM_EQ("divide") || OPT_SERV_SYM_EQ("/="))
  {
    uintmax_t tmp = 0;
    
    if (!opt_serv__build_uintmax(conf, token, *num, &tmp))
      return (FALSE);

    if (!tmp)
      return (FALSE);
    
    *num /= tmp;
  }
  else if (OPT_SERV_SYM_EQ("modulus") || OPT_SERV_SYM_EQ("%="))
  {
    uintmax_t tmp = 0;
    
    if (!opt_serv__build_uintmax(conf, token, *num, &tmp))
      return (FALSE);

    if (!tmp)
      return (FALSE);
    
    *num %= tmp;
  }
  
  OPT_SERV_X_SYM_NUM_END();

  return (TRUE);  
}

int opt_serv_sc_make_uint(Conf_parse *conf, Conf_token *token,
                          unsigned int *num)
{

  uintmax_t tmp = *num;

  if (!opt_serv_sc_make_uintmax(conf, token, &tmp))
    return (FALSE);

  if (tmp > UINT_MAX)
    return (FALSE);
  *num = tmp;

  return (TRUE);
}

int opt_serv_sc_make_ulong(Conf_parse *conf, Conf_token *token,
                           unsigned long *num)
{

  uintmax_t tmp = *num;

  if (!opt_serv_sc_make_uintmax(conf, token, &tmp))
    return (FALSE);

  if (tmp > ULONG_MAX)
    return (FALSE);
  *num = tmp;

  return (TRUE);
}

#ifndef CONF_FULL_STATIC
void opt_serv_sc_resolve_uid(struct Opt_serv_opts *opts,
                             const char *program_name,
                             void (*usage)(const char *, int, const char *))
{
  const char *name  = NULL;
  struct passwd *pw = NULL;
  
  if (!opts->vpriv_uid->len)
    return;
  
  OPT_SC_EXPORT_CSTR(name, opts->vpriv_uid, TRUE, "privilage uid");
  
  if (!(pw = getpwnam(name)))
  {
    Vstr_base *s1 = vstr_make_base(NULL);
    const char *msg = NULL;
    
    if (s1 &&
        vstr_add_fmt(s1, s1->len, " Username -- %s -- can't be found.\n",
                     name) &&
        (msg = vstr_export_cstr_ptr(s1, 1, s1->len)))
      usage(program_name, EXIT_FAILURE, msg);
    usage(program_name, EXIT_FAILURE, " Username can't be found.\n");
  }
  
  opts->priv_uid = pw->pw_uid;
}

void opt_serv_sc_resolve_gid(struct Opt_serv_opts *opts,
                             const char *program_name,
                             void (*usage)(const char *, int, const char *))
{
  const char *name = NULL;
  struct group *gr = NULL;

  if (!opts->vpriv_gid->len)
    return;
  
  OPT_SC_EXPORT_CSTR(name, opts->vpriv_gid, FALSE, "privilage gid");
  
  if (!(gr = getgrnam(name)))
  {
    Vstr_base *s1 = vstr_make_base(NULL);
    const char *msg = NULL;
    
    if (s1 &&
        vstr_add_fmt(s1, s1->len, " Groupname -- %s -- can't be found.\n",
                     name) &&
        (msg = vstr_export_cstr_ptr(s1, 1, s1->len)))
      usage(program_name, EXIT_FAILURE, msg);
    usage(program_name, EXIT_FAILURE, " Groupname can't be found.\n");
  }

  opts->priv_gid = gr->gr_gid;
}
#endif

int opt_serv_sc_config_dir(Vstr_base *s1, void *data, const char *dir,
                           int (*func)(Vstr_base *, void *, const char *))
{
  struct dirent **dents = NULL;
  int num = -1;
  int scan = 0;
  int ret = TRUE;
  Vstr_base *bld = vstr_make_base(s1->conf);

  if (!bld || bld->conf->malloc_bad)
  {
    errno = ENOMEM;
    goto fail;
  }

  num = opt_conf_sc_scan_dir(dir, &dents);
  if (num == -1)
    goto fail;

  /* *******************************************************************
   * These free's are for malloc's done inside scandir, so we __MUST__
   * use the normal free().
   * ***************************************************************** */
  while (scan < num)
  {
    if (ret)
    { /* create the full path... */
      const char *fname = NULL;
      const struct dirent *dent = dents[scan];
      
      vstr_del(bld, 1, bld->len);
      vstr_add_cstr_ptr(bld, bld->len, dir);
      vstr_add_cstr_ptr(bld, bld->len, "/");
      vstr_add_ptr(bld, bld->len, dent->d_name, _D_EXACT_NAMLEN(dent));

      if (bld->conf->malloc_bad)
      {
        bld->conf->malloc_bad = FALSE;
        ret = FALSE;
      }
      
      if (ret && !(fname = vstr_export_cstr_ptr(bld, 1, bld->len)))
        ret = FALSE;
      if (ret && !(*func)(s1, data, fname))
        ret = FALSE;
    }
    
    free(dents[scan]);
    ++scan;
  }

  free(dents);
  vstr_free_base(bld);
  return (ret);

 fail:
  vstr_add_fmt(s1, s1->len, "scandir(%s): %m", dir);
  vstr_free_base(bld);
  return (FALSE);
}

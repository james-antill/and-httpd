#ifndef OPT_POLICY_H
#define OPT_POLICY_H

#include "opt_serv.h"

#include <netinet/in.h>

#define OPT_POLICY_CONF_DEF_POLICY_NAME "<default>"

typedef struct Opt_policy_ipv4
{
  unsigned char ipv4[4];
  unsigned int cidr; 
} Opt_policy_ipv4;

extern void opt_policy_exit(Opt_serv_policy_opts *);
extern int opt_policy_init(Opt_serv_opts *, Opt_serv_policy_opts *);
extern Opt_serv_policy_opts *opt_policy_make(Opt_serv_opts *);
extern int opt_policy_copy(Opt_serv_policy_opts *,
                           const Opt_serv_policy_opts *);

extern Opt_serv_policy_opts *opt_policy_find(Opt_serv_opts *,
                                             const Conf_parse *, Conf_token *);

extern void opt_policy_add(Opt_serv_opts *, Opt_serv_policy_opts *);
   
extern int opt_policy_ipv4_make(Conf_parse *, Conf_token *,
                                unsigned int, struct sockaddr *, int *);
extern int opt_policy_ipv4_cidr_eq(Opt_policy_ipv4 *, struct sockaddr *);


extern Opt_serv_policy_opts *opt_policy_sc_conf_make(Opt_serv_opts *,
                                                     const Conf_parse *,
                                                     const Conf_token *,
                                                     const Vstr_sect_node *);
extern unsigned int opt_policy_sc_conf_parse(Opt_serv_opts *,
                                             const Conf_parse *, Conf_token *,
                                             Opt_serv_policy_opts **);
extern void opt_policy_sc_all_ref_del(Opt_serv_opts *);


#if !defined(OPT_POLICY_COMPILE_INLINE)
# if ! COMPILE_DEBUG
#  define OPT_POLICY_COMPILE_INLINE 1
# else
#  define OPT_POLICY_COMPILE_INLINE 0
# endif
#endif

#if defined(VSTR_AUTOCONF_HAVE_INLINE) && OPT_POLICY_COMPILE_INLINE

#if COMPILE_DEBUG
# define OPT_POLICY__ASSERT ASSERT
#else
# define OPT_POLICY__ASSERT(x)
#endif

#define OPT_POLICY__TRUE  1
#define OPT_POLICY__FALSE 0

extern inline int opt_policy_copy(Opt_serv_policy_opts *dst,
                                  const Opt_serv_policy_opts *src)
{
  memcpy(&dst->io_limit,   &src->io_limit,   sizeof(struct Evnt_limit));
  memcpy(&dst->io_nslimit, &src->io_nslimit, sizeof(struct Evnt_limit));
  
  dst->idle_timeout    = src->idle_timeout;
  dst->max_timeout     = src->max_timeout;
  dst->max_connections = src->max_connections;

  dst->use_insta_close = src->use_insta_close;

  return (OPT_POLICY__TRUE);
}

extern inline Opt_serv_policy_opts *opt_policy_find(Opt_serv_opts *beg_opts,
                                                    const Conf_parse *conf,
                                                    Conf_token *token)
{
  const Vstr_sect_node *val = conf_token_value(token);
  Opt_serv_policy_opts *opts = NULL;
  
  if (!val)
    return (NULL);

  opts = beg_opts->def_policy;

  if (vstr_cmp_cstr_eq(conf->data, val->pos, val->len, "<default>"))
    return (opts);
  
  while ((opts = opts->next))
  {
    Vstr_base *tmp = opts->policy_name;
    int cmp = 0;
    
    OPT_POLICY__ASSERT(!opts->next ||
                       (tmp->len < opts->next->policy_name->len) ||
                       ((tmp->len == opts->next->policy_name->len) &&
                        vstr_cmp(tmp, 1, tmp->len,
                                 opts->next->policy_name, 1,
                                 opts->next->policy_name->len) < 0));
    
    if (val->len > tmp->len)
      continue;
    if (val->len < tmp->len)
      break;
    cmp = vstr_cmp(conf->data, val->pos, val->len, tmp, 1, tmp->len);
    if (!cmp)
      return (opts);
    if (cmp < 0)
      break;
  }
  
  return (NULL);
}

#endif

#endif

#ifndef MATCH_CON_H
#define MATCH_CON_H 1

#define HTTPD_CONF_MAIN_MATCH_CON  1
#define HTTPD_CONF_MAIN_MATCH_REQ  2
#define HTTPD_CONF_MAIN_MATCH_RESP 3

#define HTTPD_POLICY_CON_POLICY 3
#define HTTPD_POLICY_REQ_POLICY 4

#define HTTPD_POLICY_CLIENT_IPV4_CIDR_EQ 5
#define HTTPD_POLICY_SERVER_IPV4_CIDR_EQ 6


static inline int httpd__match_iter_beg(Conf_parse *conf, Conf_token *token,
                                        Vstr_ref    **ret_ref,
                                        unsigned int *ret_num)
    COMPILE_ATTR_NONNULL_A() COMPILE_ATTR_WARN_UNUSED_RET();
static inline int httpd__match_iter_beg(Conf_parse *conf, Conf_token *token,
                                        Vstr_ref    **ret_ref,
                                        unsigned int *ret_num)
{
  *ret_ref = NULL;
  *ret_num = 0;
  
  if (!token->num)
    return (FALSE);

  *ret_ref = conf_token_get_user_value(conf, token, ret_num);

  return (TRUE);
}

static inline int httpd__match_iter_nxt(Conf_parse *conf, Conf_token *token,
                                        Vstr_ref    **ret_ref,
                                        unsigned int *ret_num)
    COMPILE_ATTR_NONNULL_A() COMPILE_ATTR_WARN_UNUSED_RET();

static inline int httpd__match_iter_nxt(Conf_parse *conf, Conf_token *token,
                                        Vstr_ref    **ret_ref,
                                        unsigned int *ret_num)
{
  Conf_token *update = NULL;

  if (!*ret_num)
    token->num = 0;
  else
  {
    if (*ret_ref)
    {
      update = (*ret_ref)->ptr;
      *token = *update;
      if (update->num == *ret_num)
        update = NULL;
    }
    
    if (!conf_parse_num_token(conf, token, *ret_num))
      token = NULL;

    if (update && token)
      *update = *token;
  }
  
  vstr_ref_del(*ret_ref); *ret_ref = NULL;

  if (!token)
    return (FALSE);
  
  return (httpd__match_iter_beg(conf, token, ret_ref, ret_num));
}

static inline const Httpd_policy_opts *httpd__policy_build(struct Con *con,
                                                           Conf_parse *conf,
                                                           Conf_token *token,
                                                           unsigned int utype)
{
  Opt_serv_policy_opts *policy = NULL;
  Vstr_ref *ref = NULL;
  Conf_token save;

  save = *token;
  CONF_SC_PARSE_TOP_TOKEN_RET(conf, token, FALSE);
  if (!(policy = opt_policy_conf_find(con->policy->s->beg, conf, token)))
    return (NULL);
  
  ref = policy->ref;
  if (!conf_token_set_user_value(conf, &save, utype, ref, token->num))
    return (NULL);
  
  return ((const Httpd_policy_opts *)policy);
}


#endif

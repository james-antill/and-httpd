
#include "httpd.h"
#include "httpd_policy.h"

#define EX_UTILS_NO_FUNCS 1
#include "ex_utils.h"

#include "mk.h"

#include "match_con.h"



static int httpd__policy_connection_tst_d1(struct Con *,
                                           Conf_parse *, Conf_token *,
                                           int *, int);

static int httpd__policy_connection_tst_op_d1(Conf_parse *conf,
                                              Conf_token *token,
                                              int *matches, int prev_match,
                                              void *con)
{
  return (httpd__policy_connection_tst_d1(con, conf, token,
                                          matches, prev_match));
}


static int httpd__policy_connection_tst_d1(struct Con *con,
                                           Conf_parse *conf, Conf_token *token,
                                           int *matches, int prev_match)
{
  int clist = FALSE;
  
  ASSERT(con);  
  ASSERT(matches);
  
  CONF_SC_TOGGLE_CLIST_VAR(clist);

  if (token->type >= CONF_TOKEN_TYPE_USER_BEG)
  {
    unsigned int type = token->type - CONF_TOKEN_TYPE_USER_BEG;
    unsigned int nxt = 0;
    Vstr_ref *ref = conf_token_get_user_value(conf, token, &nxt);
    
    switch (type)
    {
      case HTTPD_POLICY_CLIENT_IPV4_CIDR_EQ:
      {
        struct sockaddr *sa = CON_CEVNT_SA(con);
        *matches = httpd_policy_ipv4_cidr_eq(con, NULL, ref->ptr, sa);
      }
      break;
        
      case HTTPD_POLICY_SERVER_IPV4_CIDR_EQ:
      {
        struct sockaddr *sa = CON_SEVNT_SA(con);
        *matches = httpd_policy_ipv4_cidr_eq(con, NULL, ref->ptr, sa);
      }
      break;
        
      default:
        vstr_ref_del(ref);
        return (FALSE);
    }

    vstr_ref_del(ref);
    if (nxt)
      return (conf_parse_num_token(conf, token, nxt));
  }
  
  else if (OPT_SERV_SYM_EQ("policy-eq") || OPT_SERV_SYM_EQ("policy=="))
    OPT_SERV_X_EQ(con->policy->s->policy_name);
  else if (OPT_SERV_SYM_EQ("tag-eq") || OPT_SERV_SYM_EQ("tag=="))
    OPT_SERV_X_EQ(con->tag);
  else if (OPT_SERV_SYM_EQ("client-ipv4-cidr-eq") ||
           OPT_SERV_SYM_EQ("client-ipv4-cidr=="))
    return (httpd_policy_ipv4_make(con, NULL, conf, token,
                                   HTTPD_POLICY_CLIENT_IPV4_CIDR_EQ,
                                   CON_CEVNT_SA(con), matches));
  else if (OPT_SERV_SYM_EQ("server-ipv4-cidr-eq") ||
           OPT_SERV_SYM_EQ("server-ipv4-cidr=="))
    return (httpd_policy_ipv4_make(con, NULL, conf, token,
                                   HTTPD_POLICY_SERVER_IPV4_CIDR_EQ,
                                   CON_SEVNT_SA(con), matches));
  else if (OPT_SERV_SYM_EQ("server-ipv4-port-eq") ||
           OPT_SERV_SYM_EQ("server-ipv4-port=="))
  {
    struct sockaddr *sa   = CON_SEVNT_SA(con);
    unsigned int tst_port = 0;

    OPT_SERV_X_SINGLE_UINT(tst_port);

    if (sa->sa_family != AF_INET)
      *matches = FALSE;
    else
    {
      struct sockaddr_in *sin = CON_SEVNT_SA_IN4(con);
      *matches = tst_port == ntohs(sin->sin_port);
    }
  }
  
  else
    return (opt_serv_sc_tst(conf, token, matches, prev_match,
                            httpd__policy_connection_tst_op_d1, con));

  return (TRUE);
}

static int httpd__policy_connection_d1(struct Con *con,
                                       Conf_parse *conf, Conf_token *token,
                                       int *stop)
{
  int clist = FALSE;
  
  CONF_SC_TOGGLE_CLIST_VAR(clist);

  if (token->type >= CONF_TOKEN_TYPE_USER_BEG)
  {
    unsigned int type = token->type - CONF_TOKEN_TYPE_USER_BEG;
    unsigned int nxt = 0;
    Vstr_ref *ref = conf_token_get_user_value(conf, token, &nxt);

    switch (type)
    {
      case HTTPD_POLICY_CON_POLICY:
        httpd_policy_change_con(con, ref->ptr);
        break;
        
      default:
        vstr_ref_del(ref);
        return (FALSE);
    }

    vstr_ref_del(ref);
    if (nxt)
      return (conf_parse_num_token(conf, token, nxt));
  }
  
  else if (OPT_SERV_SYM_EQ("<close>"))
  {
    evnt_close(con->evnt);
    return (TRUE);
  }
  else if (OPT_SERV_SYM_EQ("<stop>"))
  {
    *stop = TRUE;
    return (TRUE);
  }
  else if (OPT_SERV_SYM_EQ("policy"))
  {
    const Httpd_policy_opts *policy = NULL;

    if (!(policy = httpd__policy_build(con, conf, token,
                                       HTTPD_POLICY_CON_POLICY)))
      return (FALSE);
    httpd_policy_change_con(con, policy);
  }
  else if (OPT_SERV_SYM_EQ("tag"))
    OPT_SERV_X_VSTR(con->policy->s->beg, con->tag);
  else if (OPT_SERV_SYM_EQ("Vary:_*"))
    OPT_SERV_X_TOGGLE(con->vary_star);
  
  else
    return (FALSE);
  
  return (TRUE);
}

static int httpd__policy_connection_d0(struct Con *con,
                                       Conf_parse *conf, Conf_token *token,
                                       int *stop)
{
  static int prev_match = TRUE;
  unsigned int depth = token->depth_num;
  int matches = TRUE;

  if (token->type != CONF_TOKEN_TYPE_SLIST)
    return (FALSE);

  while (conf_token_list_num(token, depth))
  {
    CONF_SC_PARSE_DEPTH_TOKEN_RET(conf, token, depth, FALSE);

    if (!httpd__policy_connection_tst_d1(con, conf, token,
                                         &matches, prev_match))
      return (FALSE);

    if (!matches)
    {
      prev_match = FALSE;
      return (TRUE);
    }
  }
  --depth;

  prev_match = TRUE;
  
  while (conf_token_list_num(token, depth))
  {
    CONF_SC_PARSE_DEPTH_TOKEN_RET(conf, token, depth, FALSE);
    
    if (!httpd__policy_connection_d1(con, conf, token, stop))
      return (FALSE);
    if (*stop || con->evnt->flag_q_closed) /* don't do anything else */
      return (TRUE);
  }

  return (TRUE);
}

int httpd_policy_connection(struct Con *con,
                            Conf_parse *conf, const Conf_token *beg_token)
{
  Conf_token token[1];
  Vstr_ref *ref = NULL;
  unsigned int num = 0;
  
  if (!beg_token->num) /* not been parsed */
    return (TRUE);
  
  *token = *beg_token;
  if (!httpd__match_iter_beg(conf, token, &ref, &num))
    return (TRUE);
  
  do
  {
    int stop = FALSE;

    conf_parse_num_token(conf, token, token->num);
    assert(token->type == (CONF_TOKEN_TYPE_USER_BEG+HTTPD_CONF_MAIN_MATCH_CON));
    
    while (token->type != CONF_TOKEN_TYPE_SLIST)
      conf_parse_token(conf, token);
    
    if (!httpd__policy_connection_d0(con, conf, token, &stop))
      goto conf_fail;
    if (stop || con->evnt->flag_q_closed) /* don't do anything else */
      break;
  } while (httpd__match_iter_nxt(conf, token, &ref, &num));

  vstr_ref_del(ref);
  vstr_del(conf->tmp, 1, conf->tmp->len);
  return (TRUE);

 conf_fail:
  vstr_ref_del(ref);
  vstr_del(conf->tmp, 1, conf->tmp->len);
  conf_parse_backtrace(conf->tmp, "<policy-connection>", conf, token);
  return (FALSE);
}

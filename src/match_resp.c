
#include "httpd.h"
#include "httpd_policy.h"

#define EX_UTILS_NO_FUNCS 1
#include "ex_utils.h"

#include "mk.h"

#include "match_req.h"

/* fwd reference */
static int httpd_match_response_tst_d1(struct Con *, Httpd_req_data *,
                                       Conf_parse *, Conf_token *, int *, int);

static int httpd__match_response_tst_op_d1(Conf_parse *conf, Conf_token *token,
                                           int *matches, int prev_match,
                                           void *passed_data)
{
  struct Httpd__policy_req_tst_data *data = passed_data;
  struct Con     *con = data->con;
  Httpd_req_data *req = data->req;

  return (httpd_match_response_tst_d1(con, req, conf, token,
                                      matches, prev_match));
}

static int httpd_match_response_tst_d1(struct Con *con, Httpd_req_data *req,
                                       Conf_parse *conf, Conf_token *token,
                                       int *matches, int prev_match)
{
  int clist = FALSE;
  struct Httpd__policy_req_tst_data data[1];        
  
  ASSERT(con && req);  
  ASSERT(matches);
  
  CONF_SC_TOGGLE_CLIST_VAR(clist); /* note this doesn't get passed to reqeust */

  data->con = con;
  data->req = req;  
  
  if (token->type >= CONF_TOKEN_TYPE_USER_BEG)
  {
    unsigned int type = token->type - CONF_TOKEN_TYPE_USER_BEG;
    unsigned int nxt = 0;
    Vstr_ref *ref = conf_token_get_user_value(conf, token, &nxt);
    
    switch (type)
    {
      /* all handled by match_req atm. */
      default:
        vstr_ref_del(ref);
        return (httpd_match_request_tst_d1(con, req, conf, token,
                                           matches, prev_match,
                                           httpd__match_response_tst_op_d1,
                                           data));
    }

    vstr_ref_del(ref);
    if (nxt)
      return (conf_parse_num_token(conf, token, nxt));
  }

  else if (OPT_SERV_SYM_EQ("error-response-code-eq") ||
           OPT_SERV_SYM_EQ("error-response-code=="))
  {
    unsigned int tmp = 0;

    OPT_SERV_X_SYM_UINT_BEG(tmp); /* only ones allowed via. match-response */
    else if (OPT_SERV_SYM_EQ("<bad>"))                tmp = 400;
    else if (OPT_SERV_SYM_EQ("<bad-request>"))        tmp = 400;
    /*    else if (OPT_SERV_SYM_EQ("<unauthorized>"))       tmp = 401; */
    else if (OPT_SERV_SYM_EQ("<forbidden>"))          tmp = 403;
    else if (OPT_SERV_SYM_EQ("<not-found>"))          tmp = 404;
    /*    else if (OPT_SERV_SYM_EQ("<Method-Not-Allowed>")) tmp = 405; */
    else if (OPT_SERV_SYM_EQ("<not-acceptable>"))     tmp = 406;
    else if (OPT_SERV_SYM_EQ("<gone>"))               tmp = 410;
    OPT_SERV_X_SYM_NUM_END();

    *matches = tmp == req->req_error_code;
  }
  else if (OPT_SERV_SYM_EQ("error-response-detail-eq") ||
           OPT_SERV_SYM_EQ("error-response-detail=="))
    OPT_SERV_X_CSTR_EQ(req->req_error_xmsg);
  else if (OPT_SERV_SYM_EQ("error-user-initiated-eq") ||
           OPT_SERV_SYM_EQ("error-user-initiated=="))
  {
    unsigned int tmp = 0;

    OPT_SERV_X_TOGGLE(tmp);

    *matches = tmp == req->req_user_return_error_code;
  }
  else
    return (httpd_match_request_tst_d1(con, req, conf, token,
                                       matches, prev_match,
                                       httpd__match_response_tst_op_d1, data));

  return (TRUE);
}

static int httpd__policy_response_d0(struct Con *con, struct Httpd_req_data *req,
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

    if (!httpd_match_response_tst_d1(con, req, conf, token,
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

    /* request and response can/should be able to do the same things */
    if (!httpd__policy_request_d1(con, req, conf, token, stop))
      return (FALSE);
    if (*stop || con->evnt->flag_q_closed) /* don't do anything else */
      return (TRUE);
  }

  return (TRUE);
}

int httpd_policy_response(struct Con *con, struct Httpd_req_data *req,
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
    assert(token->type == (CONF_TOKEN_TYPE_USER_BEG +
                           HTTPD_CONF_MAIN_MATCH_RESP));
    
    while (token->type != CONF_TOKEN_TYPE_SLIST)
      conf_parse_token(conf, token);
    
    if (!httpd__policy_response_d0(con, req, conf, token, &stop))
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
  if (!req->user_return_error_code)
  {
    conf_parse_backtrace(conf->tmp, "<policy-response>", conf, token);
    HTTPD_ERR(req, 503); /* do this, or not ? */
  }
  return (FALSE);
}


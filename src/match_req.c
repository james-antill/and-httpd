
#include "httpd.h"
#include "httpd_policy.h"

#define EX_UTILS_NO_FUNCS 1
#include "ex_utils.h"

#include "mk.h"

#include "match_req.h"

static int httpd__match_request_tst_op_d1(Conf_parse *conf, Conf_token *token,
                                          int *matches, int prev_match,
                                          void *passed_data)
{
  struct Httpd__policy_req_tst_data *data = passed_data;

  return (httpd_match_request_tst_d1(data->con, data->req, conf, token,
                                     matches, prev_match,
                                     httpd__match_request_tst_op_d1, data));
}

int httpd_match_request_sc_tst_d1(struct Con *con, Httpd_req_data *req,
                                  Conf_parse *conf, Conf_token *token,
                                  int *matches, int prev_match)
{
  struct Httpd__policy_req_tst_data data[1];        
  
  data->con = con;
  data->req = req;
  
  return (httpd_match_request_tst_d1(con, req, conf, token,
                                     matches, prev_match,
                                     httpd__match_request_tst_op_d1, data));
}

/* match tokens against a passed in header */
static int httpd_match__req_hdr(Httpd_req_data *req,
                                Conf_parse *conf, Conf_token *token,
                                const Vstr_base *s1, size_t pos, size_t len,
                                int flags)
{
  if (!conf_token_list_num(token, token->depth_num))
    return (!!pos); /* does the header exist */

  CONF_SC_PARSE_TOP_TOKEN_RET(conf, token, FALSE);

  /* FIXME: add [] tests for search etc.? */
  
  switch (flags)
  {
    case HTTPD_MATCH__TYPE_REQ_HDR_IM:
    case HTTPD_MATCH__TYPE_REQ_HDR_INM: /* disallow weak etag's? */
    {
      const Vstr_sect_node *val = conf_token_value(token);
  
      return (val && httpd_match_etags(req, conf->data, val->pos, val->len,
                                       s1, pos, len, TRUE));
    }
    case HTTPD_MATCH__TYPE_REQ_HDR_EQ:
      return (conf_token_cmp_val_eq(conf, token, s1, pos, len));
    case HTTPD_MATCH__TYPE_REQ_HDR_CASE_EQ:
      return (conf_token_cmp_case_val_eq(conf, token, s1, pos, len));
    case HTTPD_MATCH__TYPE_REQ_HDR_AE:
      http_parse_accept_encoding(req, TRUE);

      if (0) { }
      else if (conf_token_cmp_val_cstr_eq(conf, token, "identity"))
        return (!!req->content_enc_identity);
      else if (conf_token_cmp_val_cstr_eq(conf, token, "gzip"))
        return (!!req->content_enc_gzip);
      else if (conf_token_cmp_val_cstr_eq(conf, token, "bzip2"))
        return (!!req->content_enc_bzip2);

      return (FALSE);
  }

  ASSERT_NOT_REACHED();
  
  return (FALSE);
}

int httpd_match_request_tst_d1(struct Con *con, Httpd_req_data *req,
                               Conf_parse *conf, Conf_token *token,
                               int *matches, int prev_match,
                               int (*tst_func)(Conf_parse *, Conf_token *,
                                               int *, int, void *),
                               void *data)
{
  Vstr_base *http_data = con->evnt->io_r;
  Vstr_base *http_multi_data = req->http_hdrs->multi->comb;
  int clist = FALSE;
  
  ASSERT(con && req);  
  ASSERT(matches);
  
  CONF_SC_TOGGLE_CLIST_VAR(clist);

  if (token->type >= CONF_TOKEN_TYPE_USER_BEG)
  {
    unsigned int type = token->type - CONF_TOKEN_TYPE_USER_BEG;
    unsigned int nxt = 0;
    Vstr_ref *ref = conf_token_get_user_value(conf, token, &nxt);
    
    switch (type)
    {
      case HTTPD_POLICY_REQ_PATH_BEG:
      case HTTPD_POLICY_REQ_PATH_END:
      case HTTPD_POLICY_REQ_PATH_EQ:
        
      case HTTPD_POLICY_REQ_NAME_BEG:
      case HTTPD_POLICY_REQ_NAME_END:
      case HTTPD_POLICY_REQ_NAME_EQ:
        
      case HTTPD_POLICY_REQ_BWEN_BEG:
      case HTTPD_POLICY_REQ_BWEN_END:
      case HTTPD_POLICY_REQ_BWEN_EQ:
        
      case HTTPD_POLICY_REQ_BWES_BEG:
      case HTTPD_POLICY_REQ_BWES_END:
      case HTTPD_POLICY_REQ_BWES_EQ:
        
      case HTTPD_POLICY_REQ_EXTN_BEG:
      case HTTPD_POLICY_REQ_EXTN_END:
      case HTTPD_POLICY_REQ_EXTN_EQ:
        
      case HTTPD_POLICY_REQ_EXTS_BEG:
      case HTTPD_POLICY_REQ_EXTS_END:
      case HTTPD_POLICY_REQ_EXTS_EQ:
      {
        size_t pos = 1;
        size_t len = req->fname->len;
        unsigned int lim = httpd_policy_path_req2lim(type);

        vstr_ref_add(ref);
        *matches = httpd_policy_path_lim_eq(req->fname, &pos, &len, lim,
                                            req->vhost_prefix_len, ref);
      }
      break;
      
      case HTTPD_POLICY_CLIENT_IPV4_CIDR_EQ:
      {
        struct sockaddr *sa = CON_CEVNT_SA(con);
        *matches = httpd_policy_ipv4_cidr_eq(con, req, ref->ptr, sa);
      }
      break;
        
      case HTTPD_POLICY_SERVER_IPV4_CIDR_EQ:
      {
        struct sockaddr *sa = CON_SEVNT_SA(con);
        *matches = httpd_policy_ipv4_cidr_eq(con, req, ref->ptr, sa);
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

  else if (OPT_SERV_SYM_EQ("connection-policy-eq") ||
           OPT_SERV_SYM_EQ("connection-policy=="))
    OPT_SERV_X_EQ(con->policy->s->policy_name);
  else if (OPT_SERV_SYM_EQ("policy-eq") || OPT_SERV_SYM_EQ("policy=="))
    OPT_SERV_X_EQ(req->policy->s->policy_name);
  else if (OPT_SERV_SYM_EQ("connection-tag-eq") ||
           OPT_SERV_SYM_EQ("connection-tag=="))
    OPT_SERV_X_EQ(con->tag);
  else if (OPT_SERV_SYM_EQ("tag-eq") || OPT_SERV_SYM_EQ("tag=="))
    OPT_SERV_X_EQ(req->tag);
  else if (OPT_SERV_SYM_EQ("client-ipv4-cidr-eq") ||
           OPT_SERV_SYM_EQ("client-ipv4-cidr==")) /* NOTE: need ipv6 */
    return (httpd_policy_ipv4_make(con, req, conf, token,
                                   HTTPD_POLICY_CLIENT_IPV4_CIDR_EQ,
                                   CON_CEVNT_SA(con), matches));
  else if (OPT_SERV_SYM_EQ("server-ipv4-cidr-eq") ||
           OPT_SERV_SYM_EQ("server-ipv4-cidr==")) /* NOTE: need ipv6 */
    return (httpd_policy_ipv4_make(con, req, conf, token,
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
  else if (OPT_SERV_SYM_EQ("server-ipv6-port-eq") ||
           OPT_SERV_SYM_EQ("server-ipv6-port=="))
  {
    struct sockaddr *sa   = CON_SEVNT_SA(con);
    unsigned int tst_port = 0;

    OPT_SERV_X_SINGLE_UINT(tst_port);

    if (sa->sa_family != AF_INET6)
      *matches = FALSE;
    else
    {
      struct sockaddr_in6 *sin6 = CON_SEVNT_SA_IN6(con);
      *matches = tst_port == ntohs(sin6->sin6_port);
    }
  }
  else if (OPT_SERV_SYM_EQ("protect-vary") || OPT_SERV_SYM_EQ("save-vary"))
  {
    unsigned int depth = token->depth_num;
    int con_vary_star = con->vary_star;
    int req_vary_star = req->vary_star;
    int req_vary_a    = req->vary_a;
    int req_vary_ac   = req->vary_ac;
    int req_vary_ae   = req->vary_ae;
    int req_vary_al   = req->vary_al;
    int req_vary_rf   = req->vary_rf;
    int req_vary_ua   = req->vary_ua;
    int req_vary_ims  = req->vary_ims;
    int req_vary_ius  = req->vary_ius;
    int req_vary_ir   = req->vary_ir;
    int req_vary_im   = req->vary_im;
    int req_vary_inm  = req->vary_inm;
    int req_vary_xm   = req->vary_xm;

    ASSERT(*matches);
    while (*matches && conf_token_list_num(token, depth))
    {
      CONF_SC_PARSE_DEPTH_TOKEN_RET(conf, token, depth, FALSE);

      if (!httpd_match_request_tst_d1(con, req, conf, token,
                                      matches, prev_match, tst_func, data))
        return (FALSE);
    }
    
    con->vary_star = con_vary_star;
    req->vary_star = req_vary_star;
    req->vary_a    = req_vary_a;
    req->vary_ac   = req_vary_ac;
    req->vary_ae   = req_vary_ae;
    req->vary_al   = req_vary_al;
    req->vary_rf   = req_vary_rf;
    req->vary_ua   = req_vary_ua;
    req->vary_ims  = req_vary_ims;
    req->vary_ius  = req_vary_ius;
    req->vary_ir   = req_vary_ir;
    req->vary_im   = req_vary_im;
    req->vary_inm  = req_vary_inm;
    req->vary_xm   = req_vary_xm;
  }
  else if (OPT_SERV_SYM_EQ("Accept-Encoding:"))
  { /* in theory could call http_parse_accept_encoding() and make sure
     * they are allowing gzip ... but non-zero len is probably fine for now */
    Vstr_sect_node *h_ae = req->http_hdrs->multi->hdr_accept_encoding;

    req->vary_ae = TRUE;
    *matches = httpd_match__req_hdr(req, conf, token,
                                    http_multi_data, h_ae->pos, h_ae->len,
                                    HTTPD_MATCH__TYPE_REQ_HDR_AE);
  }
  else if (OPT_SERV_SYM_EQ("If-Modified-Since:"))
  {
    Vstr_sect_node *h_ims = req->http_hdrs->hdr_if_modified_since;

    req->vary_ims = TRUE;
    *matches = httpd_match__req_hdr(req, conf, token,
                                    http_data, h_ims->pos, h_ims->len,
                                    HTTPD_MATCH__TYPE_REQ_HDR_EQ);
  }
  else if (OPT_SERV_SYM_EQ("If-Unmodified-Since:"))
  {
    Vstr_sect_node *h_ius = req->http_hdrs->hdr_if_unmodified_since;

    req->vary_ius = TRUE;
    *matches = httpd_match__req_hdr(req, conf, token,
                                    http_data, h_ius->pos, h_ius->len,
                                    HTTPD_MATCH__TYPE_REQ_HDR_EQ);
  }
  else if (OPT_SERV_SYM_EQ("If-Range:"))
  {
    Vstr_sect_node *h_ir = req->http_hdrs->hdr_if_range;

    req->vary_ir = TRUE;
    *matches = httpd_match__req_hdr(req, conf, token,
                                    http_data, h_ir->pos, h_ir->len,
                                    HTTPD_MATCH__TYPE_REQ_HDR_EQ);
  }
  else if (OPT_SERV_SYM_EQ("If-Match:"))
  {
    Vstr_sect_node *h_im = req->http_hdrs->multi->hdr_if_match;

    req->vary_im = TRUE;
    *matches = httpd_match__req_hdr(req, conf, token,
                                    http_multi_data, h_im->pos, h_im->len,
                                    HTTPD_MATCH__TYPE_REQ_HDR_IM);
  }
  else if (OPT_SERV_SYM_EQ("If-None-Match:"))
  {
    Vstr_sect_node *h_inm = req->http_hdrs->multi->hdr_if_none_match;

    req->vary_inm = TRUE;
    *matches = httpd_match__req_hdr(req, conf, token,
                                    http_multi_data, h_inm->pos, h_inm->len,
                                    HTTPD_MATCH__TYPE_REQ_HDR_INM);
  }
  else if (OPT_SERV_SYM_EQ("X-Moz:"))
  { /* in theory could call http_parse_accept_encoding() and make sure
     * they are allowing gzip ... but non-zero len is probably fine for now */
    Vstr_sect_node *h_xm = req->http_hdrs->hdr_x_moz;

    req->vary_xm = TRUE;
    *matches = httpd_match__req_hdr(req, conf, token,
                                    http_data, h_xm->pos, h_xm->len,
                                    HTTPD_MATCH__TYPE_REQ_HDR_EQ);
  }
  else if (OPT_SERV_SYM_EQ("Host:") ||
           /* compat */
           OPT_SERV_SYM_EQ("hostname-eq") || OPT_SERV_SYM_EQ("hostname=="))
  { /* doesn't do escaping because DNS is ASCII */
    Vstr_sect_node *h_h = req->http_hdrs->hdr_host;
    Vstr_base *d_h      = req->policy->default_hostname;

    if (h_h->len)
      *matches = httpd_match__req_hdr(req, conf, token,
                                      http_data, h_h->pos, h_h->len,
                                      HTTPD_MATCH__TYPE_REQ_HDR_CASE_EQ);
    else
      *matches = httpd_match__req_hdr(req, conf, token,
                                      d_h, 1, d_h->len,
                                      HTTPD_MATCH__TYPE_REQ_HDR_CASE_EQ);
  }
  else if (OPT_SERV_SYM_EQ("port-eq") || OPT_SERV_SYM_EQ("port=="))
  {
    Vstr_sect_node *h_h = req->http_hdrs->hdr_host;
    unsigned int tmp = 0;
    
    OPT_SERV_X_SINGLE_UINT(tmp);

    if (h_h->len)
      *matches = tmp == req->http_host_port;
    else
    { /* FIXME: ipv6 */
      struct sockaddr_in *sinv4 = EVNT_ACPT_SA_IN4(con->evnt);
      
      ASSERT(sinv4->sin_family == AF_INET);
      *matches = tmp == ntohs(sinv4->sin_port);
    }
  }
  else if (OPT_SERV_SYM_EQ("User-Agent:") ||
           /* compat */
           OPT_SERV_SYM_EQ("user-agent-eq") || OPT_SERV_SYM_EQ("UA-eq") ||
           OPT_SERV_SYM_EQ("user-agent==") || OPT_SERV_SYM_EQ("UA=="))
  { /* doesn't do escaping because URLs are ASCII */
    Vstr_sect_node *h_ua = req->http_hdrs->hdr_ua;

    req->vary_ua = TRUE;
    *matches = httpd_match__req_hdr(req, conf, token,
                                    http_data, h_ua->pos, h_ua->len,
                                    HTTPD_MATCH__TYPE_REQ_HDR_EQ);
  }
  else if (OPT_SERV_SYM_EQ("user-agent-search-eq") || /* required compat */
           OPT_SERV_SYM_EQ("user-agent-search==") ||
           OPT_SERV_SYM_EQ("user-agent-srch-eq") ||
           OPT_SERV_SYM_EQ("user-agent-srch==") ||
           OPT_SERV_SYM_EQ("UA-srch-eq") ||
           OPT_SERV_SYM_EQ("UA-srch=="))
  { /* doesn't do escaping because URLs are ASCII */
    Vstr_sect_node *h_ua = req->http_hdrs->hdr_ua;

    req->vary_ua = TRUE;
    CONF_SC_PARSE_TOP_TOKEN_RET(conf, token, FALSE);
    *matches = !!conf_token_srch_val(conf, token, http_data,
                                     h_ua->pos, h_ua->len);
  }
  else if (OPT_SERV_SYM_EQ("Referer:")    || OPT_SERV_SYM_EQ("Referrer:") ||
           /* compat */
           OPT_SERV_SYM_EQ("referrer-eq") || OPT_SERV_SYM_EQ("referer-eq") ||
           OPT_SERV_SYM_EQ("referrer==")  || OPT_SERV_SYM_EQ("referer=="))
  { /* doesn't do escaping because URLs are ASCII */
    Vstr_sect_node *h_ref = req->http_hdrs->hdr_referer;

    req->vary_rf = TRUE;
    *matches = httpd_match__req_hdr(req, conf, token,
                                    http_data, h_ref->pos, h_ref->len,
                                    HTTPD_MATCH__TYPE_REQ_HDR_CASE_EQ);
  }
  else if (OPT_SERV_SYM_EQ("referrer-beg") || OPT_SERV_SYM_EQ("referer-beg"))
    /* required compat */
  { /* doesn't do escaping because URLs are ASCII */
    Vstr_sect_node *h_ref = req->http_hdrs->hdr_referer;

    req->vary_rf = TRUE;
    CONF_SC_PARSE_TOP_TOKEN_RET(conf, token, FALSE);
    *matches = conf_token_cmp_case_val_beg_eq(conf, token, http_data,
                                              h_ref->pos, h_ref->len);
  }
  else if (OPT_SERV_SYM_EQ("referrer-search-eq") || /* required compat */
           OPT_SERV_SYM_EQ("referrer-search==") ||
           OPT_SERV_SYM_EQ("referrer-srch-eq") ||
           OPT_SERV_SYM_EQ("referrer-srch==") ||
           OPT_SERV_SYM_EQ("referer-search-eq") ||
           OPT_SERV_SYM_EQ("referer-search==") ||
           OPT_SERV_SYM_EQ("referer-srch-eq") ||
           OPT_SERV_SYM_EQ("referer-srch=="))
  { /* doesn't do escaping because URLs are ASCII */
    Vstr_sect_node *h_ref = req->http_hdrs->hdr_referer;

    req->vary_rf = TRUE;
    CONF_SC_PARSE_TOP_TOKEN_RET(conf, token, FALSE);
    *matches = !!conf_token_srch_case_val(conf, token,
                                          http_data, h_ref->pos, h_ref->len);
  }
  else if (OPT_SERV_SYM_EQ("http-0.9-eq") || OPT_SERV_SYM_EQ("http-0.9==") ||
           OPT_SERV_SYM_EQ("http-vers-eq-0.9") ||
           OPT_SERV_SYM_EQ("http-vers==0.9") ||
           OPT_SERV_SYM_EQ("http-version-eq-0.9") ||
           OPT_SERV_SYM_EQ("http-version==0.9"))
    *matches =  req->ver_0_9;
  else if (OPT_SERV_SYM_EQ("http-1.0-eq") || OPT_SERV_SYM_EQ("http-1.0==") ||
           OPT_SERV_SYM_EQ("http-vers-eq-1.0") ||
           OPT_SERV_SYM_EQ("http-vers==1.0") ||
           OPT_SERV_SYM_EQ("http-version-eq-1.0") ||
           OPT_SERV_SYM_EQ("http-version==1.0"))
    *matches = !req->ver_0_9 && !req->ver_1_1;
  else if (OPT_SERV_SYM_EQ("http-1.1-eq") || OPT_SERV_SYM_EQ("http-1.1==") ||
           OPT_SERV_SYM_EQ("http-vers-eq-1.1") ||
           OPT_SERV_SYM_EQ("http-vers==1.1") ||
           OPT_SERV_SYM_EQ("http-version-eq-1.1") ||
           OPT_SERV_SYM_EQ("http-version==1.1"))
  {
    *matches = req->ver_1_1;
    ASSERT(!req->ver_0_9 || !*matches);
  }
  else if (OPT_SERV_SYM_EQ("http-vers>=1.0") ||
           OPT_SERV_SYM_EQ("http-version>=1.0"))
    *matches = !req->ver_0_9;
  else if (OPT_SERV_SYM_EQ("http-vers>1.0") ||
           OPT_SERV_SYM_EQ("http-version>1.0") ||
           OPT_SERV_SYM_EQ("http-vers>=1.1") ||
           OPT_SERV_SYM_EQ("http-version>=1.1"))
  {
    *matches = HTTPD_VER_1_x(req);
    ASSERT(!req->ver_0_9 || !*matches);
  }
  else if (OPT_SERV_SYM_EQ("http-vers>1.1") ||
           OPT_SERV_SYM_EQ("http-vers>=1.2"))
  {
    *matches = req->ver_1_x;
    ASSERT(!req->ver_0_9 || !*matches);
  }
  else if (OPT_SERV_SYM_EQ("method-eq") || OPT_SERV_SYM_EQ("method=="))
  { /* doesn't do escaping because methods are ASCII */
    Vstr_sect_node *meth = VSTR_SECTS_NUM(req->sects, 1);
    
    CONF_SC_PARSE_TOP_TOKEN_RET(conf, token, FALSE);
    *matches = conf_token_cmp_val_eq(conf, token,
                                     http_data, meth->pos, meth->len);
  }
  else if (OPT_SERV_SYM_EQ("tm-dow-eq") || OPT_SERV_SYM_EQ("tm-dow=="))
  { /* so we can do msff :) */
    Opt_serv_opts *opts = req->policy->s->beg;
    Httpd_opts *hopts = (Httpd_opts *)opts;
    const struct tm *tm = date_gmtime(hopts->date, req->now);
    int tmp = 0;

    if (!tm) return (FALSE);

    req->vary_star = TRUE;
    OPT_SERV_X_SINGLE_UINT(tmp);
    *matches = tmp == tm->tm_wday;
  }
  else if (OPT_SERV_SYM_EQ("content-lang-eq") ||
           OPT_SERV_SYM_EQ("content-language-eq") ||
           OPT_SERV_SYM_EQ("content-lang==") ||
           OPT_SERV_SYM_EQ("content-language=="))
  {
    req->vary_al = TRUE;
    CONF_SC_PARSE_TOP_TOKEN_RET(conf, token, FALSE);
    if (!req->content_language_vs1)
      *matches = conf_token_cmp_val_eq(conf, token, conf->tmp, 1, 0);
    else
      *matches = conf_token_cmp_val_eq(conf, token,
                                       HTTP__XTRA_HDR_PARAMS(req,
                                                             content_language));
  }
  else if (OPT_SERV_SYM_EQ("content-lang-ext-eq") ||
           OPT_SERV_SYM_EQ("content-language-extension-eq") ||
           OPT_SERV_SYM_EQ("content-lang-ext==") ||
           OPT_SERV_SYM_EQ("content-language-extension=="))
  {
    req->vary_al = TRUE;
    CONF_SC_PARSE_TOP_TOKEN_RET(conf, token, FALSE);
    if (!req->ext_vary_al_vs1)
      *matches = conf_token_cmp_val_eq(conf, token, conf->tmp, 1, 0);
    else
      *matches = conf_token_cmp_val_eq(conf, token,
                                       HTTP__XTRA_HDR_PARAMS(req, ext_vary_al));
  }
  else if (OPT_SERV_SYM_EQ("content-type-eq") ||
           OPT_SERV_SYM_EQ("content-type=="))
  {
    req->vary_a = TRUE;
    CONF_SC_PARSE_TOP_TOKEN_RET(conf, token, FALSE);
    if (!req->content_type_vs1)
      *matches = conf_token_cmp_val_eq(conf, token, conf->tmp, 1, 0);
    else
      *matches = conf_token_cmp_val_eq(conf, token,
                                       HTTP__XTRA_HDR_PARAMS(req,
                                                             content_type));
  }
  else if (OPT_SERV_SYM_EQ("content-type-ext-eq") ||
           OPT_SERV_SYM_EQ("content-type-extension-eq") ||
           OPT_SERV_SYM_EQ("content-type-ext==") ||
           OPT_SERV_SYM_EQ("content-type-extension=="))
  {    
    req->vary_a = TRUE;
    CONF_SC_PARSE_TOP_TOKEN_RET(conf, token, FALSE);
    if (!req->ext_vary_a_vs1)
      *matches = conf_token_cmp_val_eq(conf, token, conf->tmp, 1, 0);
    else
      *matches = conf_token_cmp_val_eq(conf, token,
                                       HTTP__XTRA_HDR_PARAMS(req, ext_vary_a));
  }
  else
  { /* spend time doing path/name/extn/bnwe */
    Vstr_ref *ref = NULL;
    unsigned int type = 0;
    unsigned int lim  = 0;
    size_t pos = 1;
    size_t len = req->fname->len;
    
    if (0) { }
    else if (OPT_SERV_SYM_EQ("path-beg"))
      type = HTTPD_POLICY_REQ_PATH_BEG;
    else if (OPT_SERV_SYM_EQ("path-end"))
      type = HTTPD_POLICY_REQ_PATH_END;
    else if (OPT_SERV_SYM_EQ("path-eq") || OPT_SERV_SYM_EQ("path=="))
      type = HTTPD_POLICY_REQ_PATH_EQ;
    else if (OPT_SERV_SYM_EQ("basename-beg"))
      type = HTTPD_POLICY_REQ_NAME_BEG;
    else if (OPT_SERV_SYM_EQ("basename-end"))
      type = HTTPD_POLICY_REQ_NAME_END;
    else if (OPT_SERV_SYM_EQ("basename-eq") || OPT_SERV_SYM_EQ("basename=="))
      type = HTTPD_POLICY_REQ_NAME_EQ;
    else if (OPT_SERV_SYM_EQ("extension-beg"))
      type = HTTPD_POLICY_REQ_EXTN_BEG;
    else if (OPT_SERV_SYM_EQ("extension-end"))
      type = HTTPD_POLICY_REQ_EXTN_END;
    else if (OPT_SERV_SYM_EQ("extension-eq") || OPT_SERV_SYM_EQ("extension=="))
      type = HTTPD_POLICY_REQ_EXTN_EQ;
    else if (OPT_SERV_SYM_EQ("extensions-beg"))
      type = HTTPD_POLICY_REQ_EXTS_BEG;
    else if (OPT_SERV_SYM_EQ("extensions-end"))
      type = HTTPD_POLICY_REQ_EXTS_END;
    else if (OPT_SERV_SYM_EQ("extensions-eq") ||
             OPT_SERV_SYM_EQ("extensions=="))
      type = HTTPD_POLICY_REQ_EXTS_EQ;
    else if (OPT_SERV_SYM_EQ("basename-without-extension-beg"))
      type = HTTPD_POLICY_REQ_BWEN_BEG;
    else if (OPT_SERV_SYM_EQ("basename-without-extension-end"))
      type = HTTPD_POLICY_REQ_BWEN_END;
    else if (OPT_SERV_SYM_EQ("basename-without-extension-eq") ||
             OPT_SERV_SYM_EQ("basename-without-extension=="))
      type = HTTPD_POLICY_REQ_BWEN_EQ;
    else if (OPT_SERV_SYM_EQ("basename-without-extensions-beg"))
      type = HTTPD_POLICY_REQ_BWES_BEG;
    else if (OPT_SERV_SYM_EQ("basename-without-extensions-end"))
      type = HTTPD_POLICY_REQ_BWES_END;
    else if (OPT_SERV_SYM_EQ("basename-without-extensions-eq") ||
             OPT_SERV_SYM_EQ("basename-without-extensions=="))
      type = HTTPD_POLICY_REQ_BWES_EQ;
    else
      return (opt_serv_sc_tst(conf, token, matches, prev_match,
                              tst_func, data));

    ASSERT(type);
    
    if (!httpd_policy_path_make(con, req, conf, token, type, &ref))
    {
      vstr_ref_del(ref);
      return (FALSE);
    }
    
    lim = httpd_policy_path_req2lim(type);
    *matches = httpd_policy_path_lim_eq(req->fname, &pos, &len, lim,
                                        req->vhost_prefix_len, ref);
  }

  return (TRUE);
}

int httpd__policy_request_d1(struct Con *con, Httpd_req_data *req,
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
        
      case HTTPD_POLICY_REQ_POLICY:
        httpd_policy_change_req(con, req, ref->ptr);
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
  else if (OPT_SERV_SYM_EQ("connection-policy"))
  {
    const Httpd_policy_opts *policy = NULL;

    if (!(policy = httpd__policy_build(con, conf, token,
                                       HTTPD_POLICY_CON_POLICY)))
      return (FALSE);
    httpd_policy_change_con(con, policy);
  }
  else if (OPT_SERV_SYM_EQ("policy"))
  {
    const Httpd_policy_opts *policy = NULL;

    if (!(policy = httpd__policy_build(con, conf, token,
                                       HTTPD_POLICY_REQ_POLICY)))
      return (FALSE);
    httpd_policy_change_req(con, req, policy);
  }
  else if (OPT_SERV_SYM_EQ("connection-tag"))
    OPT_SERV_X_VSTR(req->policy->s->beg, con->tag);
  else if (OPT_SERV_SYM_EQ("tag"))
    OPT_SERV_X_VSTR(req->policy->s->beg, req->tag);
  else if (OPT_SERV_SYM_EQ("org.and.httpd-conf-req-1.0") ||
           OPT_SERV_SYM_EQ("org.and.jhttpd-conf-req-1.0"))
  {
    Httpd_opts *opts = (Httpd_opts *)con->policy->s->beg;
    return (httpd_conf_req_d0(con, req, /* server beg time is "close enough" */
                              opts->beg_time, conf, token));
  }
  else
    return (FALSE);
  
  return (TRUE);
}

static int httpd__policy_request_d0(struct Con *con, struct Httpd_req_data *req,
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

    if (!httpd_match_request_sc_tst_d1(con, req, conf, token,
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
    
    if (!httpd__policy_request_d1(con, req, conf, token, stop))
      return (FALSE);
    if (*stop || con->evnt->flag_q_closed) /* don't do anything else */
      return (TRUE);
  }

  return (TRUE);
}

int httpd_policy_request(struct Con *con, struct Httpd_req_data *req,
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
    assert(token->type == (CONF_TOKEN_TYPE_USER_BEG+HTTPD_CONF_MAIN_MATCH_REQ));
    
    while (token->type != CONF_TOKEN_TYPE_SLIST)
      conf_parse_token(conf, token);
    
    if (!httpd__policy_request_d0(con, req, conf, token, &stop))
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
    conf_parse_backtrace(conf->tmp, "<policy-request>", conf, token);
    HTTPD_ERR(req, 503);
  }
  return (FALSE);
}


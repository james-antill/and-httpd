
#include "httpd.h"
#include "httpd_policy.h"

#include <err.h>

#define EX_UTILS_NO_USE_INIT  1
#define EX_UTILS_NO_USE_EXIT  1
#define EX_UTILS_NO_USE_LIMIT 1
#define EX_UTILS_NO_USE_INPUT 1
#define EX_UTILS_NO_USE_BLOCK 1
#define EX_UTILS_NO_USE_PUT   1
#define EX_UTILS_NO_USE_BLOCKING_OPEN 1
#define EX_UTILS_RET_FAIL     1
#include "ex_utils.h"

#define HTTPD_CONF_REQ__X_CONTENT_SINGLE_VSTR(x) do {                   \
      if (!httpd__conf_req_single_str(req, conf, token,                 \
                                      &req-> x ## _vs1,                 \
                                      &req-> x ## _pos,                 \
                                      &req-> x ## _len))                \
        return (FALSE);                                                 \
    } while (FALSE)

#define HTTPD_CONF_REQ__X_CONTENT_VSTR(x) do {                          \
      if (!httpd__conf_req_make_str(req, conf, token,                   \
                                    &req-> x ## _vs1,                   \
                                    &req-> x ## _pos,                   \
                                    &req-> x ## _len))                  \
        return (FALSE);                                                 \
    } while (FALSE)



#define HTTPD_CONF_REQ__TYPE_BUILD_PATH_SKIP   0
#define HTTPD_CONF_REQ__TYPE_BUILD_PATH_ASSIGN 1
#define HTTPD_CONF_REQ__TYPE_BUILD_PATH_APPEND 2

static int httpd__conf_req_single_str(Httpd_req_data *req,
                                      Conf_parse *conf, Conf_token *token,
                                      const Vstr_base **s1,
                                      size_t *pos, size_t *len)
{
  Vstr_base *xs1 = req->xtra_content;
  
  ASSERT(s1 && pos && len);
  ASSERT((*s1 == xs1) || !*s1);

  /* always delete, so don't call http_req_xtra_content() as it might do a
     copy */
  if (!req->xtra_content && !(req->xtra_content = vstr_make_base(NULL)))
    return (FALSE);
  xs1 = req->xtra_content;

  if (*len && (vstr_sc_poslast(*pos, *len) == xs1->len))
    vstr_del(req->xtra_content, *pos, *len);
  
  *pos = xs1->len;
  *len = 0;
  if (conf_sc_token_app_vstr(conf, token, xs1, s1, pos, len))
    return (FALSE);

  if ((token->type == CONF_TOKEN_TYPE_QUOTE_ESC_D) ||
      (token->type == CONF_TOKEN_TYPE_QUOTE_ESC_DDD) ||
      (token->type == CONF_TOKEN_TYPE_QUOTE_ESC_S) ||
      (token->type == CONF_TOKEN_TYPE_QUOTE_ESC_SSS) ||
      FALSE)
    if (!*s1 || !conf_sc_conv_unesc(xs1, *pos, *len, len))
      return (FALSE);
  
  return (TRUE);
}

/* if we aren't the last string in the XTRA_CONTENT, copy to the last bit
 * Then pass the last bit to make_str */
static int httpd__conf_req_make_str(Httpd_req_data *req,
                                    Conf_parse *conf, Conf_token *token,
                                    const Vstr_base **s1,
                                    size_t *pos, size_t *len)
{
  Opt_serv_opts *opts = req->policy->s->beg;
  size_t xpos = 0;

  if (!(xpos = http_req_xtra_content(req, *s1, *pos, len)))
    return (FALSE);
  
  if (!opt_serv_sc_make_str(opts, conf, token, req->xtra_content, xpos, *len))
    return (FALSE);
  
  *s1  = req->xtra_content;
  *pos = xpos;
  *len = (req->xtra_content->len - xpos) + 1;

  return (TRUE);
}


static void httpd__conf_req_reset_expires(struct Httpd_req_data *req,
                                          unsigned int off)
{
  Vstr_base *s1 = req->xtra_content;
  size_t pos = req->expires_pos;
  size_t len = req->expires_len;
  Opt_serv_opts *opts = req->policy->s->beg;
  Date_store *date = ((Httpd_opts *)opts)->date;
  
  ASSERT(vstr_sc_poslast(pos, len) == s1->len);

  if (off > (60 * 60 * 24 * 365))
    off = (60 * 60 * 24 * 365);
  
  if (vstr_sub_cstr_buf(s1, pos, len, date_rfc1123(date, req->now + off)))
    req->expires_len = vstr_sc_posdiff(pos, s1->len);
}

static void httpd__conf_req_reset_cache_control(struct Httpd_req_data *req,
                                                unsigned int val)
{
  Vstr_base *s1 = req->xtra_content;
  size_t pos = req->cache_control_pos;
  size_t len = req->cache_control_len;
  
  ASSERT(pos && len);
  ASSERT(vstr_sc_poslast(pos, len) == s1->len);
  
  if (val > (60 * 60 * 24 * 365))
    val = (60 * 60 * 24 * 365);
  
  if (vstr_add_fmt(s1, pos - 1, "max-age=%u", val))
  {
    vstr_sc_reduce(s1, 1, s1->len, len);
    req->cache_control_len = vstr_sc_posdiff(pos, s1->len);
  }
}

static int httpd__build_path(struct Con *con, Httpd_req_data *req,
                             const Conf_parse *conf, Conf_token *token,
                             Vstr_base *s1, size_t pos, size_t len,
                             unsigned int lim, int full, Vstr_ref *ref,
                             int uri_fname, int *type)
{
  int dummy_type;
  int clist = FALSE;

  if (!type) type = &dummy_type;
  *type = HTTPD_CONF_REQ__TYPE_BUILD_PATH_SKIP;
  
  if (uri_fname)
  {
    int slash_dot_safe = FALSE;

    if (req->chk_encoded_slash && req->chk_encoded_dot)
      slash_dot_safe = TRUE;
    if (!httpd_policy_uri_lim_eq(s1, &pos, &len, lim, slash_dot_safe, ref))
    {
      int ret = conf_parse_end_token(conf, token, conf_token_at_depth(token));
      ASSERT(ret);
      return (TRUE);
    }
  }
  else
  {
    size_t vhost_len = req->vhost_prefix_len;
  
    if (!httpd_policy_path_lim_eq(s1, &pos, &len, lim, vhost_len, ref))
    {
      int ret = conf_parse_end_token(conf, token, conf_token_at_depth(token));
      ASSERT(ret);
      return (TRUE);
    }
    
    if (full && vhost_len)
    { /* don't want to keep the vhost data */
      if (lim != HTTPD_POLICY_PATH_LIM_NONE)
        pos -= vhost_len;
      else
        len -= vhost_len;
      
      ASSERT(req->fname == s1);
      vstr_del(req->fname, 1, vhost_len);
      req->vhost_prefix_len = 0;
    }
  }
  *type = HTTPD_CONF_REQ__TYPE_BUILD_PATH_ASSIGN;
  
  CONF_SC_TOGGLE_CLIST_VAR(clist);
  
  if (0) { }
  
  else if (OPT_SERV_SYM_EQ("assign") || OPT_SERV_SYM_EQ("="))
  {
    if (!httpd_policy_build_path(con, req, conf, token, NULL, NULL))
      return (FALSE);

    if (!vstr_sub_vstr(s1, pos, len,
                       conf->tmp, 1, conf->tmp->len, VSTR_TYPE_SUB_BUF_REF))
      return (FALSE);
  }
  else if (OPT_SERV_SYM_EQ("append") || OPT_SERV_SYM_EQ("+=") ||
           OPT_SERV_SYM_EQ(".=") || OPT_SERV_SYM_EQ(">>="))
  {
    *type = HTTPD_CONF_REQ__TYPE_BUILD_PATH_APPEND;
  
    if (!httpd_policy_build_path(con, req, conf, token, NULL, NULL))
      return (FALSE);

    return (vstr_add_vstr(s1, vstr_sc_poslast(pos, len),
                          conf->tmp, 1, conf->tmp->len, VSTR_TYPE_ADD_BUF_REF));
  }
  else if (OPT_SERV_SYM_EQ("prepend") || OPT_SERV_SYM_EQ("<<="))
  {
    *type = HTTPD_CONF_REQ__TYPE_BUILD_PATH_APPEND;
  
    if (!httpd_policy_build_path(con, req, conf, token, NULL, NULL))
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

    goto fin_overwrite;
  }    
  else
    return (FALSE);

 fin_overwrite:
  if (lim == HTTPD_POLICY_PATH_LIM_NONE)
    req->vhost_prefix_len = 0; /* replaced everything */

  return (TRUE);
}

static int httpd__meta_build_path(struct Con *con, Httpd_req_data *req,
                                  Conf_parse *conf, Conf_token *token,
                                  int *full, int *canon,
                                  unsigned int *lim, Vstr_ref **ret_ref)
{
  unsigned int depth = token->depth_num;

  ASSERT(ret_ref && !*ret_ref);
  
  if (token->type != CONF_TOKEN_TYPE_SLIST)
    return (TRUE);

  while (conf_token_list_num(token, depth))
  {
    int clist = FALSE;
    
    CONF_SC_PARSE_DEPTH_TOKEN_RET(conf, token, depth, TRUE);
    CONF_SC_TOGGLE_CLIST_VAR(clist);

    if (0) { }
    else if (full && (OPT_SERV_SYM_EQ("skip-virtual-hosts") ||
                      OPT_SERV_SYM_EQ("skip-vhosts")))
      OPT_SERV_X_TOGGLE(*full);
    else if (canon && (OPT_SERV_SYM_EQ("make-abs-url") ||
                       OPT_SERV_SYM_EQ("make-absolute-url")))
      OPT_SERV_X_TOGGLE(*canon);
    else if (full && OPT_SERV_SYM_EQ("skip-document-root"))
      OPT_SERV_X_TOGGLE(req->skip_document_root);
    else if (OPT_SERV_SYM_EQ("limit"))
    {
      CONF_SC_PARSE_TOP_TOKEN_RET(conf, token, FALSE);

      vstr_ref_del(*ret_ref); *ret_ref = NULL;
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
            *lim = httpd_policy_path_req2lim(type);
            break;

          default:
            vstr_ref_del(ref);
            return (FALSE);
        }
        *ret_ref = ref;
        if (nxt && !conf_parse_num_token(conf, token, nxt))
          return (FALSE);
      }
  
      else if (OPT_SERV_SYM_EQ("<none>") || OPT_SERV_SYM_EQ("none"))
        *lim = HTTPD_POLICY_PATH_LIM_NONE;
      else if (OPT_SERV_SYM_EQ("<path>") || OPT_SERV_SYM_EQ("path"))
        *lim = HTTPD_POLICY_PATH_LIM_PATH_FULL;
      else if (OPT_SERV_SYM_EQ("<basename>") || OPT_SERV_SYM_EQ("basename"))
        *lim = HTTPD_POLICY_PATH_LIM_NAME_FULL;
      else if (OPT_SERV_SYM_EQ("<extension>") || OPT_SERV_SYM_EQ("extension"))
        *lim = HTTPD_POLICY_PATH_LIM_EXTN_FULL;
      else if (OPT_SERV_SYM_EQ("<extensions>") || OPT_SERV_SYM_EQ("extensions"))
        *lim = HTTPD_POLICY_PATH_LIM_EXTS_FULL;
      else if (OPT_SERV_SYM_EQ("<basename-without-extension>") ||
               OPT_SERV_SYM_EQ("basename-without-extension"))
        *lim = HTTPD_POLICY_PATH_LIM_BWEN_FULL;
      else if (OPT_SERV_SYM_EQ("<basename-without-extensions>") ||
               OPT_SERV_SYM_EQ("basename-without-extensions"))
        *lim = HTTPD_POLICY_PATH_LIM_BWES_FULL;
      else
      {
        unsigned int type = HTTPD_POLICY_REQ_PATH_BEG;
        
        if (0) { }
        else if (OPT_SERV_SYM_EQ("<path>-beg") || OPT_SERV_SYM_EQ("path-beg"))
          type = HTTPD_POLICY_REQ_PATH_BEG;
        else if (OPT_SERV_SYM_EQ("<path>-end") || OPT_SERV_SYM_EQ("path-end"))
          type = HTTPD_POLICY_REQ_PATH_END;
        else if (OPT_SERV_SYM_EQ("<path>-eq") || OPT_SERV_SYM_EQ("path-eq") ||
                 OPT_SERV_SYM_EQ("<path>==") || OPT_SERV_SYM_EQ("path=="))
          type = HTTPD_POLICY_REQ_PATH_EQ;
        else if (OPT_SERV_SYM_EQ("<basename>-beg") ||
                 OPT_SERV_SYM_EQ("basename-beg") ||
                 OPT_SERV_SYM_EQ("<basename>==") ||
                 OPT_SERV_SYM_EQ("basename=="))
          type = HTTPD_POLICY_REQ_NAME_BEG;
        else if (OPT_SERV_SYM_EQ("<basename>-end") ||
                 OPT_SERV_SYM_EQ("basename-end"))
          type = HTTPD_POLICY_REQ_NAME_END;
        else if (OPT_SERV_SYM_EQ("<basename>-eq") ||
                 OPT_SERV_SYM_EQ("basename-eq") ||
                 OPT_SERV_SYM_EQ("<basename>==") ||
                 OPT_SERV_SYM_EQ("basename=="))
          type = HTTPD_POLICY_REQ_NAME_EQ;
        else if (OPT_SERV_SYM_EQ("<extension>-beg") ||
                 OPT_SERV_SYM_EQ("extension-beg"))
          type = HTTPD_POLICY_REQ_EXTN_BEG;
        else if (OPT_SERV_SYM_EQ("<extension>-end") ||
                 OPT_SERV_SYM_EQ("extension-end"))
          type = HTTPD_POLICY_REQ_EXTN_END;
        else if (OPT_SERV_SYM_EQ("<extension>-eq") ||
                 OPT_SERV_SYM_EQ("extension-eq") ||
                 OPT_SERV_SYM_EQ("<extension>==") ||
                 OPT_SERV_SYM_EQ("extension=="))
          type = HTTPD_POLICY_REQ_EXTN_EQ;
        else if (OPT_SERV_SYM_EQ("<extensions>-beg") ||
                 OPT_SERV_SYM_EQ("extensions-beg"))
          type = HTTPD_POLICY_REQ_EXTS_BEG;
        else if (OPT_SERV_SYM_EQ("<extensions>-end") ||
                 OPT_SERV_SYM_EQ("extensions-end"))
          type = HTTPD_POLICY_REQ_EXTS_END;
        else if (OPT_SERV_SYM_EQ("<extensions>-eq") ||
                 OPT_SERV_SYM_EQ("extensions-eq") ||
                 OPT_SERV_SYM_EQ("<extensions>==") ||
                 OPT_SERV_SYM_EQ("extensions=="))
          type = HTTPD_POLICY_REQ_EXTS_EQ;
        else if (OPT_SERV_SYM_EQ("<basename-without-extension>-beg") ||
                 OPT_SERV_SYM_EQ("basename-without-extension-beg"))
          type = HTTPD_POLICY_REQ_BWEN_BEG;
        else if (OPT_SERV_SYM_EQ("<basename-without-extension>-end") ||
                 OPT_SERV_SYM_EQ("basename-without-extension-end"))
          type = HTTPD_POLICY_REQ_BWEN_END;
        else if (OPT_SERV_SYM_EQ("<basename-without-extension>-eq") ||
                 OPT_SERV_SYM_EQ("basename-without-extension-eq") ||
                 OPT_SERV_SYM_EQ("<basename-without-extension>==") ||
                 OPT_SERV_SYM_EQ("basename-without-extension=="))
          type = HTTPD_POLICY_REQ_BWEN_EQ;
        else if (OPT_SERV_SYM_EQ("<basename-without-extensions>-beg") ||
                 OPT_SERV_SYM_EQ("basename-without-extensions-beg"))
          type = HTTPD_POLICY_REQ_BWES_BEG;
        else if (OPT_SERV_SYM_EQ("<basename-without-extensions>-end") ||
                 OPT_SERV_SYM_EQ("basename-without-extensions-end"))
          type = HTTPD_POLICY_REQ_BWES_END;
        else if (OPT_SERV_SYM_EQ("<basename-without-extensions>-eq") ||
                 OPT_SERV_SYM_EQ("basename-without-extensions-eq") ||
                 OPT_SERV_SYM_EQ("<basename-without-extensions>==") ||
                 OPT_SERV_SYM_EQ("basename-without-extensions=="))
          type = HTTPD_POLICY_REQ_BWES_EQ;
        else
          return (FALSE);
        
        if (!httpd_policy_path_make(con, req, conf, token, type, ret_ref))
           return (FALSE);
        
        *lim = httpd_policy_path_req2lim(type);
      }
    }
    else
      return (FALSE);
  }
  
  CONF_SC_PARSE_DEPTH_TOKEN_RET(conf, token, depth - 1, FALSE);
  return (TRUE);
}

static int httpd__content_location_valid(Httpd_req_data *req,
                                         size_t *ret_pos, size_t *ret_len)
{
  *ret_pos = req->content_location_pos;
  *ret_len = req->content_location_len;
  
  *ret_pos = http_req_xtra_content(req, req->xtra_content, *ret_pos, ret_len);

  return (!!*ret_pos);
}

/* we negotiate a few items, and this is the loop for all of them... */
#define HTTPD__NEG_BEG(x)                                               \
    unsigned int depth = token->depth_num;                              \
    unsigned int max_qual  = 0;                                         \
    unsigned int qual_num  = 0;                                         \
    unsigned int neg_count = 0;                                         \
    Conf_token save;                                                    \
                                                                        \
    save = *token;                                                      \
    while (conf_token_list_num(token, depth) &&                         \
           (!(x) || (++neg_count <= (x))))                              \
    {                                                                   \
      unsigned int qual = 0;                                            \
      const Vstr_sect_node *val = NULL;                                 \
                                                                        \
      CONF_SC_PARSE_DEPTH_TOKEN_RET(conf, token, depth, TRUE);          \
      CONF_SC_TOGGLE_CLIST_VAR(clist);                                  \
                                                                        \
      if (!((token->type == CONF_TOKEN_TYPE_QUOTE_D) ||                 \
            (token->type == CONF_TOKEN_TYPE_QUOTE_DDD) ||               \
            (token->type == CONF_TOKEN_TYPE_QUOTE_S) ||                 \
            (token->type == CONF_TOKEN_TYPE_QUOTE_SSS) ||               \
            (token->type == CONF_TOKEN_TYPE_SYMBOL)))                   \
        return (FALSE);                                                 \
                                                                        \
      val = conf_token_value(token)


#define HTTPD__NEG_END()                        \
      if (qual > max_qual)                      \
      {                                         \
        max_qual = qual;                        \
        qual_num = token->num - 1;              \
      }                                         \
                                                                        \
      CONF_SC_PARSE_TOP_TOKEN_RET(conf, token, FALSE);                  \
    }                                                                   \
    if (neg_count)                                                      \
    {                                                                   \
      int ret = conf_parse_end_token(conf, token, depth);               \
      ASSERT(ret);                                                      \
    }                                                                   \
    do { } while (FALSE)


/* match with an 's' is it's > 1, otherwise without ... zero special cased */
#define HTTPD__EXPIRES_CMP(x, y)                                        \
    (((num == 1) &&                                                     \
      vstr_cmp_cstr_eq(HTTP_REQ__CONT_PARAMS(req, x), "<" y ">")) ||     \
     ((num > 1) &&                                                      \
      vstr_cmp_cstr_eq(HTTP_REQ__CONT_PARAMS(req, x), "<" y "s>")))

#define HTTPD__CONF_REDIR(req, code) do {                               \
      if ((req)->direct_uri) {                                          \
        httpd_req_absolute_uri(con, req,                                \
                               (req)->fname, 1, (req)->fname->len);     \
        HTTPD_REDIR_MSG(req, code, "Req conf");                         \
        return (FALSE);                                                 \
      }                                                                 \
    } while (FALSE)

static int httpd__conf_req_d1(struct Con *con, struct Httpd_req_data *req,
                              time_t file_timestamp,
                              Conf_parse *conf, Conf_token *token, int clist)
{
  if (0) { }

  else if (OPT_SERV_SYM_EQ("match-init"))
    OPT_SERV_SC_MATCH_INIT(req->policy->s->beg,
                           httpd__conf_req_d1(con, req, file_timestamp,
                                              conf, token, clist));
  
  else if (OPT_SERV_SYM_EQ("match-request"))
  {
    static unsigned int match_req_rec_depth = 0; /* no inf. recursion */
    static int prev_match = TRUE;
    unsigned int depth = token->depth_num;
    int matches = TRUE;

    if (match_req_rec_depth > 4) /* FIXME: conf */
      return (FALSE);
    
    CONF_SC_PARSE_SLIST_DEPTH_TOKEN_RET(conf, token, depth, FALSE);
    ++depth;
    while (conf_token_list_num(token, depth))
    {
      CONF_SC_PARSE_DEPTH_TOKEN_RET(conf, token, depth, FALSE);
      
      if (!httpd_match_request_sc_tst_d1(con, req, conf, token, &matches,
                                         prev_match))
        return (FALSE);
      
      if (!matches)
        conf_parse_end_token(conf, token, depth - 1);
    }
    --depth;

    prev_match = matches;
    
    while (conf_token_list_num(token, depth))
    {
      int ret = FALSE;
      
      CONF_SC_PARSE_DEPTH_TOKEN_RET(conf, token, depth, FALSE);
      CONF_SC_TOGGLE_CLIST_VAR(clist);

      ++match_req_rec_depth;
      ret = httpd__conf_req_d1(con, req, file_timestamp, conf, token, clist);
      --match_req_rec_depth;
      
      if (!ret)
        return (FALSE);
    }
  }
  
  else if (OPT_SERV_SYM_EQ("return"))
  {
    unsigned int code = 0;
    
    OPT_SERV_X_SYM_UINT_BEG(code);

    else if (OPT_SERV_SYM_EQ("<perm>") ||
             OPT_SERV_SYM_EQ("<perm-redirect>") ||
             OPT_SERV_SYM_EQ("<permanent>") || /* sp is permanent */
             OPT_SERV_SYM_EQ("<permenant>") || /* allow bad sp */
             OPT_SERV_SYM_EQ("<permanent-redirect>") ||
             OPT_SERV_SYM_EQ("<permenant-redirect>"))
      code = 301;
    else if (OPT_SERV_SYM_EQ("<found>"))
      code = 302;
    else if (OPT_SERV_SYM_EQ("<other>") || OPT_SERV_SYM_EQ("<see-other>"))
      code = 303;
    else if (OPT_SERV_SYM_EQ("<tmp>") || OPT_SERV_SYM_EQ("<tmp-redirect>") ||
             OPT_SERV_SYM_EQ("<temp>") ||
             OPT_SERV_SYM_EQ("<temp-redirect>") ||
             OPT_SERV_SYM_EQ("<temporary>") ||
             OPT_SERV_SYM_EQ("<temporary-redirect>"))
      code = 307;
    else if (OPT_SERV_SYM_EQ("<bad>") || OPT_SERV_SYM_EQ("<bad-request>"))
      code = 400;
    else if (OPT_SERV_SYM_EQ("<forbidden>"))
      code = 403;
    else if (OPT_SERV_SYM_EQ("<not-found>"))
      code = 404;
    else if (OPT_SERV_SYM_EQ("<not-acceptable>"))
      code = 406;
    else if (OPT_SERV_SYM_EQ("<gone>"))
      code = 410;
    else if (OPT_SERV_SYM_EQ("<error>") ||
             OPT_SERV_SYM_EQ("<internal-server-error>"))
      code = 500;
    else if (OPT_SERV_SYM_EQ("<service-unavailable>"))
      code = 503;

    OPT_SERV_X_SYM_NUM_END();
    
    req->user_return_error_code = TRUE;
    ASSERT(!req->error_code);
    req->error_code = 0;
    switch (code)
    {
      case 301: HTTPD__CONF_REDIR(req, 301);
      case 302: HTTPD__CONF_REDIR(req, 302);
      case 303: HTTPD__CONF_REDIR(req, 303);
      case 307: HTTPD__CONF_REDIR(req, 307);
      default:
        req->user_return_error_code = FALSE;
        return (FALSE);
        
      case 400: HTTPD_ERR_MSG_RET(req, 400, "Req conf", FALSE);
      case 403: HTTPD_ERR_MSG_RET(req, 403, "Req conf", FALSE);
      case 404: HTTPD_ERR_MSG_RET(req, 404, "Req conf", FALSE);
      case 406: HTTPD_ERR_MSG_RET(req, 406, "Req conf", FALSE);
      case 410: HTTPD_ERR_MSG_RET(req, 410, "Req conf", FALSE);
      case 500: HTTPD_ERR_MSG_RET(req, 500, "Req conf", FALSE);
      case 503: HTTPD_ERR_MSG_RET(req, 503, "Req conf", FALSE);
    }
  }
  else if (OPT_SERV_SYM_EQ("Location:"))
  {
    unsigned int lim = HTTPD_POLICY_PATH_LIM_NONE;
    Vstr_ref *ref = NULL;
    size_t orig_len = 0;
    int bp_type = HTTPD_CONF_REQ__TYPE_BUILD_PATH_SKIP;
    int canon = FALSE;
    
    if (req->direct_filename)
      return (FALSE);
    
    CONF_SC_PARSE_TOP_TOKEN_RET(conf, token, FALSE);
    if (!httpd__meta_build_path(con, req, conf, token,
                                NULL, &canon, &lim, &ref))
    {
      vstr_ref_del(ref);
      return (FALSE);
    }
    if (!req->direct_uri)
    {
      if (lim == HTTPD_POLICY_PATH_LIM_NONE)
        orig_len = req->fname->len; /* don't do more than we need */
      else
      {
        if (!vstr_sub_vstr(req->fname, 1, req->fname->len,
                           con->evnt->io_r, req->path_pos, req->path_len, 0))
        {
          vstr_ref_del(ref);
          return (FALSE);
        }
        req->vhost_prefix_len = 0;
      }
    }
    if (!httpd__build_path(con, req, conf, token,
                           req->fname, 1, req->fname->len,
                           lim, FALSE, ref, TRUE, &bp_type))
      return (FALSE);
    if (!req->direct_uri && (lim == HTTPD_POLICY_PATH_LIM_NONE) &&
        (bp_type != HTTPD_CONF_REQ__TYPE_BUILD_PATH_ASSIGN))
    { /* we needed to do the above sub */
      if (!vstr_sub_vstr(req->fname, 1, orig_len,
                         con->evnt->io_r, req->path_pos, req->path_len, 0))
        return (FALSE);
    }
    req->vhost_prefix_len = 0;
    
    req->direct_uri = TRUE;
    HTTP_REQ__X_HDR_CHK(req->fname, 1, req->fname->len);

    if (canon)
      httpd_req_absolute_uri(con, req, req->fname, 1, req->fname->len);
  }
  else if (OPT_SERV_SYM_EQ("Cache-Control:"))
  { 
    unsigned int num = 1;
    unsigned int tmp = 0;
    Conf_token save = *token;
    int ern = 0;
    
    if ((ern = conf_sc_token_parse_uint(conf, token, &tmp)))
    { /* reset, as though we didn't try */
      *token = save;
      HTTPD_CONF_REQ__X_CONTENT_VSTR(cache_control);
    }
    else if (!(num = tmp))
      return (FALSE);
    else
      HTTPD_CONF_REQ__X_CONTENT_SINGLE_VSTR(cache_control);
    
    if (0) { /* nothing */ }
    else if (HTTPD__EXPIRES_CMP(cache_control, "expire-minute"))
      httpd__conf_req_reset_cache_control(req, (num * 60 *  1));
    else if (HTTPD__EXPIRES_CMP(cache_control, "expire-hour"))
      httpd__conf_req_reset_cache_control(req, (num * 60 * 60));
    else if (HTTPD__EXPIRES_CMP(cache_control, "expire-day"))
      httpd__conf_req_reset_cache_control(req, (num * 60 * 60 * 24));
    else if (HTTPD__EXPIRES_CMP(cache_control, "expire-week"))
      httpd__conf_req_reset_cache_control(req, (num * 60 * 60 * 24 * 7));
    else if (!ern) /* must be one of the above symbols */
      return (FALSE);
    else if (vstr_cmp_cstr_eq(HTTP_REQ__CONT_PARAMS(req, cache_control),
                              "<expires-now>"))
      httpd__conf_req_reset_cache_control(req, 0);
    else if (vstr_cmp_cstr_eq(HTTP_REQ__CONT_PARAMS(req, cache_control),
                              "<expires-never>"))
      httpd__conf_req_reset_cache_control(req, (60 * 60 * 24 * 365));
    else
      HTTP_REQ__X_CONTENT_HDR_CHK(cache_control);
  }
  else if (OPT_SERV_SYM_EQ("Content-Disposition:"))
  {
    HTTPD_CONF_REQ__X_CONTENT_VSTR(content_disposition);
    HTTP_REQ__X_CONTENT_HDR_CHK(content_disposition);
  }
  else if (OPT_SERV_SYM_EQ("Content-Language:"))
  {
    HTTPD_CONF_REQ__X_CONTENT_VSTR(content_language);
    HTTP_REQ__X_CONTENT_HDR_CHK(content_language);
  }
  else if (OPT_SERV_SYM_EQ("Content-Location:"))
  {
    unsigned int lim = HTTPD_POLICY_PATH_LIM_NONE;
    size_t pos = 0;
    size_t len = 0;
    Vstr_ref *ref = NULL;

    if (req->direct_uri || req->direct_filename)
      return (FALSE);

    if (!httpd__content_location_valid(req, &pos, &len))
      return (FALSE);
    
    CONF_SC_PARSE_TOP_TOKEN_RET(conf, token, FALSE);
    if (!httpd__meta_build_path(con, req, conf, token, NULL, NULL, &lim, &ref))
    {
      vstr_ref_del(ref);
      return (FALSE);
    }
    if (!httpd__build_path(con, req, conf, token, req->xtra_content, pos, len,
                           lim, FALSE, ref, TRUE, NULL))
      return (FALSE);
    
    len = vstr_sc_posdiff(pos, req->xtra_content->len);
    
    req->content_location_vs1 = req->xtra_content;
    req->content_location_pos = pos;
    req->content_location_len = len;
    HTTP_REQ__X_CONTENT_HDR_CHK(content_location);
  }
  else if (OPT_SERV_SYM_EQ("Content-MD5:") ||
           OPT_SERV_SYM_EQ("identity/Content-MD5:"))
  {
    req->content_md5_time = file_timestamp;
    HTTPD_CONF_REQ__X_CONTENT_SINGLE_VSTR(content_md5);
    HTTP_REQ__X_CONTENT_HDR_CHK(content_md5);
  }
  else if (OPT_SERV_SYM_EQ("gzip/Content-MD5:"))
  { 
    req->content_md5_time = file_timestamp;
    HTTPD_CONF_REQ__X_CONTENT_SINGLE_VSTR(gzip_content_md5);
    HTTP_REQ__X_CONTENT_HDR_CHK(gzip_content_md5);
  }
  else if (OPT_SERV_SYM_EQ("bzip2/Content-MD5:"))
  { 
    req->content_md5_time = file_timestamp;
    HTTPD_CONF_REQ__X_CONTENT_SINGLE_VSTR(bzip2_content_md5);
    HTTP_REQ__X_CONTENT_HDR_CHK(bzip2_content_md5);
  }
  else if (OPT_SERV_SYM_EQ("Content-Type:"))
  {
    HTTPD_CONF_REQ__X_CONTENT_VSTR(content_type);
    HTTP_REQ__X_CONTENT_HDR_CHK(content_type);
  }
  else if (OPT_SERV_SYM_EQ("ETag:"))
  {
    req->etag_time = file_timestamp;
    HTTPD_CONF_REQ__X_CONTENT_VSTR(etag);
    HTTP_REQ__X_CONTENT_HDR_CHK(etag);
  }
  else if (OPT_SERV_SYM_EQ("Expires:"))
  { /* note that rfc2616 says only go upto a year into the future */
    unsigned int num = 1;
    unsigned int tmp = 0;
    Conf_token save = *token;
    int ern = 0;
    
    if ((ern = conf_sc_token_parse_uint(conf, token, &tmp)))
    { /* reset, as though we didn't try */
      *token = save;
      HTTPD_CONF_REQ__X_CONTENT_VSTR(expires);
    }
    else if (!(num = tmp))
      return (FALSE);
    else
      HTTPD_CONF_REQ__X_CONTENT_SINGLE_VSTR(expires);
    
    /* if we dynamically generate use current timestamp, else filetimestamp */
    req->expires_time = req->now;
    if (0) { /* nothing */ }
    else if (HTTPD__EXPIRES_CMP(expires, "minute"))
      httpd__conf_req_reset_expires(req, (num * 60 *  1));
    else if (HTTPD__EXPIRES_CMP(expires, "hour"))
      httpd__conf_req_reset_expires(req, (num * 60 * 60));
    else if (HTTPD__EXPIRES_CMP(expires, "day"))
      httpd__conf_req_reset_expires(req, (num * 60 * 60 * 24));
    else if (HTTPD__EXPIRES_CMP(expires, "week"))
      httpd__conf_req_reset_expires(req, (num * 60 * 60 * 24 * 7));
    else if (!ern) /* must be one of the above symbols */
      return (FALSE);
    else if (vstr_cmp_cstr_eq(HTTP_REQ__CONT_PARAMS(req, expires), "<now>"))
      httpd__conf_req_reset_expires(req, 0);
    else if (vstr_cmp_cstr_eq(HTTP_REQ__CONT_PARAMS(req, expires), "<never>"))
      httpd__conf_req_reset_expires(req, (60 * 60 * 24 * 365));
    else
    {
      req->expires_time = file_timestamp;
      HTTP_REQ__X_CONTENT_HDR_CHK(expires);
    }
  }
  else if (OPT_SERV_SYM_EQ("Link:")) /* rfc2068 -- old, but still honored */
  {
    HTTPD_CONF_REQ__X_CONTENT_VSTR(link);
    HTTP_REQ__X_CONTENT_HDR_CHK(link);
  }
  else if (OPT_SERV_SYM_EQ("P3P:")) /* http://www.w3.org/TR/P3P/ */
  {
    HTTPD_CONF_REQ__X_CONTENT_VSTR(p3p);
    HTTP_REQ__X_CONTENT_HDR_CHK(p3p);
  }
  else if (OPT_SERV_SYM_EQ("filename"))
  {
    int full = req->skip_document_root;
    unsigned int lim = HTTPD_POLICY_PATH_LIM_NAME_FULL;
    Vstr_ref *ref = NULL;
    
    if (req->direct_uri)
      return (FALSE);
    CONF_SC_PARSE_TOP_TOKEN_RET(conf, token, FALSE);
    if (!httpd__meta_build_path(con, req, conf, token, &full, NULL, &lim, &ref))
    {
      vstr_ref_del(ref);
      return (FALSE);
    }
    if (!httpd__build_path(con, req, conf, token,
                           req->fname, 1, req->fname->len,
                           lim, full, ref, FALSE, NULL))
      return (FALSE);
    if (!req->skip_document_root &&
        !(req->conf_flags & HTTPD_CONF_REQ_FLAGS_PARSE_FILE_DIRECT) &&
        (!req->fname->len || !vstr_cmp_cstr_eq(req->fname, 1, 1, "/")))
      vstr_add_cstr_ptr(req->fname, 0, "/");
    req->direct_filename = TRUE;
  }
  else if (OPT_SERV_SYM_EQ("parse-accept"))
    OPT_SERV_X_TOGGLE(req->parse_accept);
  else if (OPT_SERV_SYM_EQ("parse-accept-language"))
    OPT_SERV_X_TOGGLE(req->parse_accept_language);
  else if (OPT_SERV_SYM_EQ("allow-accept-encoding") ||
           OPT_SERV_SYM_EQ("parse-accept-encoding"))
    OPT_SERV_X_TOGGLE(req->allow_accept_encoding);
  else if (OPT_SERV_SYM_EQ("Vary:_*"))
    OPT_SERV_X_TOGGLE(req->vary_star);
  else if (OPT_SERV_SYM_EQ("Vary:_Accept"))
    OPT_SERV_X_TOGGLE(req->vary_a);
  else if (OPT_SERV_SYM_EQ("Vary:_Accept-Charset"))
    OPT_SERV_X_TOGGLE(req->vary_ac);
  else if (OPT_SERV_SYM_EQ("Vary:_Accept-Encoding")) /* doesn't help */
    OPT_SERV_X_TOGGLE(req->vary_ae);
  else if (OPT_SERV_SYM_EQ("Vary:_Accept-Language"))
    OPT_SERV_X_TOGGLE(req->vary_al);
  else if (OPT_SERV_SYM_EQ("Vary:_Referer") ||
           OPT_SERV_SYM_EQ("Vary:_Referrer"))
    OPT_SERV_X_TOGGLE(req->vary_rf);
  else if (OPT_SERV_SYM_EQ("Vary:_User-Agent"))
    OPT_SERV_X_TOGGLE(req->vary_ua);
  else if (OPT_SERV_SYM_EQ("Vary:_If-Modified-Since"))
    OPT_SERV_X_TOGGLE(req->vary_ims);
  else if (OPT_SERV_SYM_EQ("Vary:_If-Unmodified-Since"))
    OPT_SERV_X_TOGGLE(req->vary_ius);
  else if (OPT_SERV_SYM_EQ("Vary:_If-Range"))
    OPT_SERV_X_TOGGLE(req->vary_ir);
  else if (OPT_SERV_SYM_EQ("Vary:_If-Match"))
    OPT_SERV_X_TOGGLE(req->vary_im);
  else if (OPT_SERV_SYM_EQ("Vary:_If-None-Match"))
    OPT_SERV_X_TOGGLE(req->vary_inm);
  else if (OPT_SERV_SYM_EQ("content-lang-ext") ||
           OPT_SERV_SYM_EQ("content-language-ext") ||
           OPT_SERV_SYM_EQ("content-language-extension"))
    HTTPD_CONF_REQ__X_CONTENT_VSTR(ext_vary_al);
  else if (OPT_SERV_SYM_EQ("content-type-ext") ||
           OPT_SERV_SYM_EQ("content-type-extension"))
    HTTPD_CONF_REQ__X_CONTENT_VSTR(ext_vary_a);
  else if (OPT_SERV_SYM_EQ("content-type-neg") ||
           OPT_SERV_SYM_EQ("content-type-negotiate") ||
           OPT_SERV_SYM_EQ("negotiate-content-type"))
  {
    if (req->neg_content_type_done)
      return (FALSE);
    HTTPD__NEG_BEG(req->policy->max_neg_A_nodes);
    qual = http_parse_accept(req, conf->data, val->pos, val->len);
    HTTPD__NEG_END();    

    req->neg_content_type_done = TRUE;
    req->vary_a = TRUE;
    if (qual_num)
    {
      unsigned int last = token->num;

      req->parse_accept = FALSE;
      *token = save;
      conf_parse_num_token(conf, token, qual_num);
      HTTPD_CONF_REQ__X_CONTENT_SINGLE_VSTR(content_type);
      HTTP_REQ__X_CONTENT_HDR_CHK(content_type);
      HTTPD_CONF_REQ__X_CONTENT_SINGLE_VSTR(ext_vary_a);
      conf_parse_num_token(conf, token, last);
    }
  }
  /*  else if (OPT_SERV_SYM_EQ("negotiate-charset"))
      return (FALSE); */
  else if (OPT_SERV_SYM_EQ("content-lang-neg") ||
           OPT_SERV_SYM_EQ("content-lang-negotiate") ||
           OPT_SERV_SYM_EQ("content-language-negotiate") ||
           OPT_SERV_SYM_EQ("negotiate-content-language"))
  {
    if (req->neg_content_lang_done)
      return (FALSE);
    HTTPD__NEG_BEG(req->policy->max_neg_AL_nodes);
    qual = http_parse_accept_language(req, conf->data, val->pos, val->len);
    HTTPD__NEG_END();

    req->neg_content_lang_done = TRUE;
    req->vary_al = TRUE;
    if (qual_num)
    {
      unsigned int last = token->num;

      req->parse_accept_language = FALSE;
      *token = save;
      conf_parse_num_token(conf, token, qual_num);
      HTTPD_CONF_REQ__X_CONTENT_SINGLE_VSTR(content_language);
      HTTP_REQ__X_CONTENT_HDR_CHK(content_language);
      HTTPD_CONF_REQ__X_CONTENT_SINGLE_VSTR(ext_vary_al);
      conf_parse_num_token(conf, token, last);
    }
  }
  else
    return (FALSE);
  
  return (TRUE);
}
#undef HTTPD__CONF_REDIR
#undef HTTPD__EXPIRES_CMP
#undef HTTPD__NEG_BEG
#undef HTTPD__NEG_END

int httpd_conf_req_d0(struct Con *con, Httpd_req_data *req,
                      time_t timestamp,
                      Conf_parse *conf, Conf_token *token)
{
  unsigned int cur_depth = token->depth_num;
  
  if (!OPT_SERV_SYM_EQ("org.and.httpd-conf-req-1.0") &&
      !OPT_SERV_SYM_EQ("org.and.jhttpd-conf-req-1.0"))
    return (FALSE);
  
  while (conf_token_list_num(token, cur_depth))
  {
    int clist = FALSE;
    
    CONF_SC_PARSE_DEPTH_TOKEN_RET(conf, token, cur_depth, FALSE);
    CONF_SC_TOGGLE_CLIST_VAR(clist);

    if (!httpd__conf_req_d1(con, req, timestamp, conf, token, clist))
      return (FALSE);
  }

  if (req->content_location_vs1)
  { /* absolute URI content-location header */
    size_t pos = 0;
    size_t len = 0;

    if (!httpd__content_location_valid(req, &pos, &len))
      return (FALSE);
    
    httpd_req_absolute_uri(con, req, req->xtra_content, pos, len);
    req->content_location_len = vstr_sc_posdiff(pos, req->xtra_content->len);
  }

  return (TRUE);
}

int httpd_conf_req_parse_file(Conf_parse *conf,
                              struct Con *con, Httpd_req_data *req,
                              size_t del_len)
{
  Conf_token token[1] = {CONF_TOKEN_INIT};
  Vstr_base *fname = req->fname;
  Vstr_base *s1 = NULL;
  const char *fname_cstr = NULL;
  int fd = -1;
  struct stat64 cf_stat[1];
  int open_flags = O_NONBLOCK;

  ASSERT(conf && con && req && fname && (del_len < fname->len));
  
  s1 = conf->tmp;

  if (req->conf_flags & HTTPD_CONF_REQ_FLAGS_PARSE_FILE_DIRECT)
    HTTPD_APP_REF_VSTR(s1, fname, 1, fname->len - del_len);
  else
  {
    Vstr_base *dir = req->policy->req_conf_dir;

    ASSERT(dir);

    if (!dir->len ||
        !req->policy->use_req_conf || req->skip_document_root)
      return (TRUE);
    
    HTTPD_APP_REF_ALLVSTR(s1, dir);
    ASSERT((dir->len   >= 1) && vstr_cmp_cstr_eq(dir,   dir->len, 1, "/"));
    ASSERT((fname->len >= 1) && vstr_cmp_cstr_eq(fname,        1, 1, "/"));
    HTTPD_APP_REF_VSTR(s1, fname, 2, fname->len - (1 + del_len));
  }
  
  if (s1->conf->malloc_bad ||
      !(fname_cstr = vstr_export_cstr_ptr(s1, 1, s1->len)))
    goto read_fail;
  
  if (req->policy->use_noatime)
    open_flags |= O_NOATIME;
    
  fd = io__open(fname_cstr, open_flags);
  if ((fd == -1) && (errno == EISDIR))
    goto fin_dir;

  if ((fd == -1) &&
      ((errno == ENOTDIR) || /* part of path was not a dir */
       (errno == ENAMETOOLONG)))
    goto fin_file; /* ignore these errors, not local users fault */

  if ((fd == -1) && (errno == ENOENT))
    goto fin_ok; /* ignore these errors, not local users fault */

  if (fd == -1)
    goto read_fail; /* this is "bad" */
  
  if (fstat64(fd, cf_stat) == -1)
    goto close_read_fail; /* this is "bad" */
  
  if (S_ISDIR(cf_stat->st_mode))
    goto fin_close_dir; /* ignore */
  
  if (!S_ISREG(cf_stat->st_mode))
    goto close_read_fail; /* this is "bad" */

  if ((cf_stat->st_size < strlen("org.and.httpd-conf-req-1.0")) ||
      (cf_stat->st_size > req->policy->max_req_conf_sz))
    goto close_read_fail; /* this is "bad" */

  s1 = conf->data;
  vstr_del(conf->tmp,  1, conf->tmp->len); /* filename */

  while (cf_stat->st_size > s1->len)
  {
    size_t len = cf_stat->st_size - s1->len;
    
    if (!vstr_sc_read_len_fd(s1, s1->len, fd, len, NULL) ||
        (len == (cf_stat->st_size - s1->len)))
      goto close_read_fail;
  }
  
  close(fd);
    
  if (!conf_parse_lex(conf, 1, conf->data->len))
    goto conf_fail;

  while (conf_parse_token(conf, token))
  {
    if ((token->type != CONF_TOKEN_TYPE_CLIST) || (token->depth_num != 1))
      goto conf_fail;

    if (!conf_parse_token(conf, token))
      goto conf_fail;
    
    if (!conf_token_cmp_sym_cstr_eq(conf, token,
                                    "org.and.httpd-conf-req-1.0") &&
        !conf_token_cmp_sym_cstr_eq(conf, token,
                                    "org.and.jhttpd-conf-req-1.0"))
      goto conf_fail;
  
    if (!httpd_conf_req_d0(con, req, cf_stat->st_mtime, conf, token))
      goto conf_fail;
  }

  /* And they all live together ... dum dum */
  if (conf->data->conf->malloc_bad)
    goto read_fail;

  return (TRUE);

 fin_close_dir:
  close(fd);
 fin_dir:
  req->conf_friendly_file = TRUE;
  if (req->policy->use_secure_dirs &&
      !(req->conf_flags & HTTPD_CONF_REQ_FLAGS_PARSE_FILE_NONMAIN))
  { /* check if conf file exists inside the directory given,
     * so we can re-direct without leaking info. */
    struct stat64 d_stat[1];
    
    vstr_add_cstr_buf(s1, s1->len, "/");
    HTTPD_APP_REF_ALLVSTR(s1, req->policy->dir_filename);
    
    fname_cstr = vstr_export_cstr_ptr(s1, 1, s1->len);
    if (s1->conf->malloc_bad)
      goto read_fail;
    if ((stat64(fname_cstr, d_stat) != -1) && S_ISREG(d_stat->st_mode))
      req->conf_secure_dirs = TRUE;
  }

  ASSERT(s1 == conf->tmp);
  vstr_del(s1, 1, s1->len);
  return (TRUE);
  
 fin_file:
  if (req->policy->use_friendly_dirs &&
      !(req->conf_flags & HTTPD_CONF_REQ_FLAGS_PARSE_FILE_NONMAIN))
  { /* check if conf file exists as a file, so we can re-direct backwards */
    struct stat64 d_stat[1];
    size_t len = vstr_cspn_cstr_chrs_rev(s1, 1, s1->len, "/") + 1;

    if ((len > 1) && (len < (s1->len - req->vhost_prefix_len)))
    { /* must be a filename, can't be toplevel */
      vstr_sc_reduce(s1, 1, s1->len, len);
    
      fname_cstr = vstr_export_cstr_ptr(s1, 1, s1->len);
      if (s1->conf->malloc_bad)
        goto read_fail;
      if ((stat64(fname_cstr, d_stat) != -1) && S_ISREG(d_stat->st_mode))
        req->conf_friendly_dirs = TRUE;
    }
  }
  
 fin_ok:
  ASSERT(s1 == conf->tmp);
  vstr_del(s1, 1, s1->len);
  return (TRUE);

 close_read_fail:
  vstr_del(conf->data, 1, conf->data->len);
  vstr_del(conf->tmp,  1, conf->tmp->len);
  close(fd);
  goto read_fail;
  
 conf_fail:
  vstr_del(conf->tmp,  1, conf->tmp->len);
  if (!req->user_return_error_code &&
      !(req->conf_flags & HTTPD_CONF_REQ_FLAGS_PARSE_FILE_NONMAIN))
    conf_parse_backtrace(conf->tmp, "<conf-request>", conf, token);
 read_fail:
  if (!req->user_return_error_code)
    HTTPD_ERR_MSG(req, 503, "Req conf parse error");
  conf->data->conf->malloc_bad = FALSE;
  return (FALSE);
}

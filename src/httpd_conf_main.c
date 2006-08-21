
#include "httpd.h"
#include "httpd_policy.h"

#define EX_UTILS_NO_FUNCS 1
#include "ex_utils.h"

#include "mk.h"

#include "match_con.h"

#include "base64.h"

static int httpd__conf_main_policy_http_d1(Httpd_policy_opts *opts,
                                           Conf_parse *conf,
                                           Conf_token *token)
{
  int clist = FALSE;
  
  CONF_SC_MAKE_CLIST_BEG(policy_http_d1, clist);
  
  else if (OPT_SERV_SYM_EQ("authorization") || OPT_SERV_SYM_EQ("auth"))
  { /* token is output of: echo -n foo:bar | openssl enc -base64 */
    /* see it with: echo token | openssl enc -d -base64 && echo */
    unsigned int depth = token->depth_num;

    CONF_SC_PARSE_TOP_TOKEN_RET(conf, token, FALSE);

    if (0) { }
    
    else if (OPT_SERV_SYM_EQ("off"))
    {
      vstr_del(opts->auth_realm, 1, opts->auth_realm->len);
      vstr_del(opts->auth_token, 1, opts->auth_token->len);
    }
    else if (OPT_SERV_SYM_EQ("basic-encoded"))
    { /* echo -n foo:bar | openssl enc -base64
         echo Zm9vOmJhcg== | openssl enc -d -base64 && echo */
      CONF_SC_MAKE_CLIST_MID(depth, clist);
      
      else if (OPT_SERV_SYM_EQ("realm"))
        OPT_SERV_X_VSTR(opts->s->beg, opts->auth_realm);
      else if (OPT_SERV_SYM_EQ("token"))
        OPT_SERV_X_VSTR(opts->s->beg, opts->auth_token);
      
      CONF_SC_MAKE_CLIST_END();
    }
    else if (OPT_SERV_SYM_EQ("basic-single"))
    {
      CONF_SC_MAKE_CLIST_MID(depth, clist);
      
      else if (OPT_SERV_SYM_EQ("realm"))
        OPT_SERV_X_VSTR(opts->s->beg, opts->auth_realm);
      else if (OPT_SERV_SYM_EQ("token"))
        OPT_SERV_X_SINGLE_VSTR(conf->tmp);
      
      CONF_SC_MAKE_CLIST_END();

      vstr_del(opts->auth_token, 1, opts->auth_token->len);
      if (!vstr_x_conv_base64_encode(opts->auth_token, 0,
                                     conf->tmp, 1, conf->tmp->len, 0))
        return (FALSE);
    }
    else
      return (FALSE);
  }
  else if (OPT_SERV_SYM_EQ("strictness"))
  {
    CONF_SC_MAKE_CLIST_BEG(http_checks, clist);
    
    else if (OPT_SERV_SYM_EQ("hdrs") || OPT_SERV_SYM_EQ("headers"))
    {
      CONF_SC_MAKE_CLIST_BEG(checks_hdrs, clist);
      
      else if (OPT_SERV_SYM_EQ("allow-dbl") ||
               OPT_SERV_SYM_EQ("allow-double") ||
               OPT_SERV_SYM_EQ("allow-*2"))
        OPT_SERV_X_NEG_TOGGLE(opts->use_hdrs_no_x2);
      else if (OPT_SERV_SYM_EQ("allow-missing-length"))
        OPT_SERV_X_NEG_TOGGLE(opts->use_hdrs_err_411);
      else if (OPT_SERV_SYM_EQ("allow-spaces"))
        OPT_SERV_X_NEG_TOGGLE(opts->use_hdrs_non_spc);
      
      CONF_SC_MAKE_CLIST_END();
    }
    
    else if (OPT_SERV_SYM_EQ("host") || OPT_SERV_SYM_EQ("hostname"))
    {
      CONF_SC_MAKE_CLIST_BEG(checks_host, clist);
      
      else if (OPT_SERV_SYM_EQ("canonize") ||
               OPT_SERV_SYM_EQ("make-canonical"))
        OPT_SERV_X_TOGGLE(opts->use_canonize_host);
      else if (OPT_SERV_SYM_EQ("validation"))
      {
        int use_internal_host_chk = FALSE;
        int use_host_chk          = FALSE;
        int use_host_err_400      = FALSE;
        int validation_done       = FALSE;
        
        CONF_SC_MAKE_CLIST_BEG(checks_host_valid, clist);
        
        else if (OPT_SERV_SYM_EQ("off")  || OPT_SERV_SYM_EQ("false") ||
                 OPT_SERV_SYM_EQ("OFF")  || OPT_SERV_SYM_EQ("FALSE") ||
                 OPT_SERV_SYM_EQ("no")   || OPT_SERV_SYM_EQ("NO") ||
                 OPT_SERV_SYM_EQ("none") || OPT_SERV_SYM_EQ("NONE") ||
                 OPT_SERV_SYM_EQ("0"))
        {
          use_internal_host_chk = FALSE;
          use_host_chk          = FALSE;
          use_host_err_400      = FALSE;
          validation_done       = TRUE;
        }
        else if (OPT_SERV_SYM_EQ("fast") || OPT_SERV_SYM_EQ("internal"))
        {
          use_internal_host_chk = TRUE;
          validation_done       = TRUE;
        }
        else if (OPT_SERV_SYM_EQ("virtual-hosts-default"))
        {
          use_host_chk          = TRUE;
          use_host_err_400      = FALSE;
          validation_done       = TRUE;
        }
        else if (OPT_SERV_SYM_EQ("virtual-hosts-error"))
        {
          use_host_chk          = TRUE;
          use_host_err_400      = TRUE;
          validation_done       = TRUE;
        }
        
        CONF_SC_MAKE_CLIST_END();
        
        if (validation_done)
        {
          opts->use_internal_host_chk = use_internal_host_chk;
          opts->use_host_chk          = use_host_chk;
          opts->use_host_err_400      = use_host_err_400;
        }
      }
      
      CONF_SC_MAKE_CLIST_END();
    }
    
    else if (OPT_SERV_SYM_EQ("allow-HTTP/0.9"))
      OPT_SERV_X_TOGGLE(opts->allow_http_0_9);
    else if (OPT_SERV_SYM_EQ("allow-dot-directory") ||
             OPT_SERV_SYM_EQ("allow-dot-dir") ||
             OPT_SERV_SYM_EQ("allow-.-dir"))
      OPT_SERV_X_NEG_TOGGLE(opts->chk_dot_dir);
    else if (OPT_SERV_SYM_EQ("allow-encoded-slash") ||
             OPT_SERV_SYM_EQ("allow-enc-/"))
      OPT_SERV_X_NEG_TOGGLE(opts->chk_encoded_slash);
    else if (OPT_SERV_SYM_EQ("allow-encoded-dot") ||
             OPT_SERV_SYM_EQ("allow-enc-."))
      OPT_SERV_X_NEG_TOGGLE(opts->chk_encoded_dot);
    else if (OPT_SERV_SYM_EQ("error-406") ||
             OPT_SERV_SYM_EQ("error-not-acceptable") ||
             OPT_SERV_SYM_EQ("error-406-not-acceptable"))
      OPT_SERV_X_TOGGLE(opts->use_err_406);
    else if (OPT_SERV_SYM_EQ("url") || OPT_SERV_SYM_EQ("URL"))
    {
      CONF_SC_MAKE_CLIST_BEG(checks_host, clist);
      
      else if (OPT_SERV_SYM_EQ("remove-fragment"))
        OPT_SERV_X_TOGGLE(opts->remove_url_frag);
      else if (OPT_SERV_SYM_EQ("remove-query"))
        OPT_SERV_X_TOGGLE(opts->remove_url_query);
      
      CONF_SC_MAKE_CLIST_END();
    }
    
    CONF_SC_MAKE_CLIST_END(); /* end of http checks */
  }
  
  else if (OPT_SERV_SYM_EQ("text-plain-redirect"))
    OPT_SERV_X_TOGGLE(opts->use_text_redirect);
  else if (OPT_SERV_SYM_EQ("ETag:"))
  {
    CONF_SC_PARSE_TOP_TOKEN_RET(conf, token, FALSE);

    if (0) { }
    
    else if (OPT_SERV_SYM_EQ("auto-dev-inode-size-mtime"))
      opts->etag_auto_type = HTTPD_ETAG_TYPE_AUTO_DISM;
    else if (OPT_SERV_SYM_EQ("auto-inode-size-mtime"))
      opts->etag_auto_type = HTTPD_ETAG_TYPE_AUTO_ISM;
    else if (OPT_SERV_SYM_EQ("auto-size-mtime"))
      opts->etag_auto_type = HTTPD_ETAG_TYPE_AUTO_SM;
    else if (OPT_SERV_SYM_EQ("auto-off")  || OPT_SERV_SYM_EQ("auto-false") ||
             OPT_SERV_SYM_EQ("auto-no")   || OPT_SERV_SYM_EQ("auto-none"))
      opts->etag_auto_type = HTTPD_ETAG_TYPE_AUTO_NONE;

    else
      return (FALSE);
  }
  else if (OPT_SERV_SYM_EQ("encoded-content-replacement")) /* allow gzip */
    OPT_SERV_X_TOGGLE(opts->use_enc_content_replacement);
  else if (OPT_SERV_SYM_EQ("keep-alive"))
    OPT_SERV_X_TOGGLE(opts->use_keep_alive);
  else if (OPT_SERV_SYM_EQ("keep-alive-1.0"))
    OPT_SERV_X_TOGGLE(opts->use_keep_alive_1_0);
  else if (OPT_SERV_SYM_EQ("keep-alive-hdr") ||
           OPT_SERV_SYM_EQ("keep-alive-header"))
    OPT_SERV_X_TOGGLE(opts->output_keep_alive_hdr);
  else if (OPT_SERV_SYM_EQ("range"))
    OPT_SERV_X_TOGGLE(opts->use_range);
  else if (OPT_SERV_SYM_EQ("range-1.0"))
    OPT_SERV_X_TOGGLE(opts->use_range_1_0);
  else if (OPT_SERV_SYM_EQ("advertise-range"))
    OPT_SERV_X_TOGGLE(opts->use_adv_range);
  else if (OPT_SERV_SYM_EQ("trace-op") || OPT_SERV_SYM_EQ("trace-operation"))
    OPT_SERV_X_TOGGLE(opts->allow_trace_op);
  else if (OPT_SERV_SYM_EQ("url-remove-fragment")) /* compat */
    OPT_SERV_X_TOGGLE(opts->remove_url_frag);
  else if (OPT_SERV_SYM_EQ("url-remove-query")) /* compat */
    OPT_SERV_X_TOGGLE(opts->remove_url_query);
  
  else if (OPT_SERV_SYM_EQ("limit"))
  {
    CONF_SC_MAKE_CLIST_BEG(limit, clist);
    
    else if (OPT_SERV_SYM_EQ("header-size") ||
             OPT_SERV_SYM_EQ("header-sz"))
      OPT_SERV_X_UINT(opts->max_header_sz);
    else if (OPT_SERV_SYM_EQ("requests"))
      OPT_SERV_X_UINT(opts->max_requests);
    else if (OPT_SERV_SYM_EQ("nodes"))
    {
      CONF_SC_MAKE_CLIST_BEG(nodes, clist);
        
      else if (OPT_SERV_SYM_EQ("Accept:"))
        OPT_SERV_X_UINT(opts->max_A_nodes);
      else if (OPT_SERV_SYM_EQ("Accept-Charset:"))
        OPT_SERV_X_UINT(opts->max_AC_nodes);
      else if (OPT_SERV_SYM_EQ("Accept-Encoding:"))
        OPT_SERV_X_UINT(opts->max_AE_nodes);
      else if (OPT_SERV_SYM_EQ("Accept-Language:"))
        OPT_SERV_X_UINT(opts->max_AL_nodes);
      
      else if (OPT_SERV_SYM_EQ("Connection:"))
        OPT_SERV_X_UINT(opts->max_connection_nodes);
      else if (OPT_SERV_SYM_EQ("ETag:"))
        OPT_SERV_X_UINT(opts->max_etag_nodes);      
      else if (OPT_SERV_SYM_EQ("Range:"))
      {
        OPT_SERV_X_UINT(opts->max_range_nodes);
        if (!opts->max_range_nodes)
        {
          opts->use_range     = FALSE;
          opts->use_range_1_0 = FALSE;
        }
      }
      
      CONF_SC_MAKE_CLIST_END();
    }
    
    CONF_SC_MAKE_CLIST_END();
  }
  else if (OPT_SERV_SYM_EQ("Server:") || OPT_SERV_SYM_EQ("server-name"))
    OPT_SERV_X_VSTR(opts->s->beg, opts->server_name);
  
  CONF_SC_MAKE_CLIST_END();
  
  return (TRUE);
}

static int httpd__conf_main_policy_d1(Httpd_policy_opts *opts,
                                      Conf_parse *conf, Conf_token *token,
                                      int clist)
{
  if (0) { }
  
  else if (OPT_SERV_SYM_EQ("match-init"))
    OPT_SERV_SC_MATCH_INIT(opts->s->beg,
                           httpd__conf_main_policy_d1(opts, conf, token,
                                                      clist));
  
  else if (OPT_SERV_SYM_EQ("directory-filename"))
    return (opt_serv_sc_make_static_path(opts->s->beg, conf, token,
                                         opts->dir_filename));
  else if (OPT_SERV_SYM_EQ("document-root") ||
           OPT_SERV_SYM_EQ("doc-root"))
    return (opt_serv_sc_make_static_path(opts->s->beg, conf, token,
                                         opts->document_root));
  else if (OPT_SERV_SYM_EQ("unspecified-hostname"))
    OPT_SERV_X_VSTR(opts->s->beg, opts->default_hostname);
  else if (OPT_SERV_SYM_EQ("MIME/types-default-type"))
    OPT_SERV_X_VSTR(opts->s->beg, opts->mime_types_def_ct);
  else if (OPT_SERV_SYM_EQ("MIME/types-filename-main"))
    return (opt_serv_sc_make_static_path(opts->s->beg, conf, token,
                                         opts->mime_types_main));
  else if (OPT_SERV_SYM_EQ("MIME/types-filename-extra") ||
           OPT_SERV_SYM_EQ("MIME/types-filename-xtra"))
    return (opt_serv_sc_make_static_path(opts->s->beg, conf, token,
                                         opts->mime_types_xtra));
  else if (OPT_SERV_SYM_EQ("request-configuration-directory") ||
           OPT_SERV_SYM_EQ("req-conf-dir"))
    return (opt_serv_sc_make_static_path(opts->s->beg, conf, token,
                                         opts->req_conf_dir));
  else if (OPT_SERV_SYM_EQ("request-error-directory") ||
           OPT_SERV_SYM_EQ("req-err-dir"))
    return (opt_serv_sc_make_static_path(opts->s->beg, conf, token,
                                         opts->req_err_dir));
  else if (OPT_SERV_SYM_EQ("server-name")) /* compat. */
    OPT_SERV_X_VSTR(opts->s->beg, opts->server_name);

  else if (OPT_SERV_SYM_EQ("secure-directory-filename"))
    OPT_SERV_X_TOGGLE(opts->use_secure_dirs);
  else if (OPT_SERV_SYM_EQ("redirect-filename-directory"))
    OPT_SERV_X_TOGGLE(opts->use_friendly_dirs);
  else if (OPT_SERV_SYM_EQ("mmap"))
    OPT_SERV_X_TOGGLE(opts->use_mmap);
  else if (OPT_SERV_SYM_EQ("sendfile"))
    OPT_SERV_X_TOGGLE(opts->use_sendfile);
  else if (OPT_SERV_SYM_EQ("virtual-hosts") ||
           OPT_SERV_SYM_EQ("vhosts") ||
           OPT_SERV_SYM_EQ("virtual-hosts-name") ||
           OPT_SERV_SYM_EQ("vhosts-name"))
    OPT_SERV_X_TOGGLE(opts->use_vhosts_name);
  else if (OPT_SERV_SYM_EQ("public-only"))
    OPT_SERV_X_TOGGLE(opts->use_public_only);
  else if (OPT_SERV_SYM_EQ("posix-fadvise"))
    OPT_SERV_X_TOGGLE(opts->use_posix_fadvise);
  else if (OPT_SERV_SYM_EQ("update-atime"))
    OPT_SERV_X_NEG_TOGGLE(opts->use_noatime);
  else if (OPT_SERV_SYM_EQ("tcp-cork"))
    OPT_SERV_X_TOGGLE(opts->use_tcp_cork);
  else if (OPT_SERV_SYM_EQ("allow-request-configuration"))
    OPT_SERV_X_TOGGLE(opts->use_req_conf);
  else if (OPT_SERV_SYM_EQ("allow-header-splitting"))
    OPT_SERV_X_TOGGLE(opts->allow_hdr_split);
  else if (OPT_SERV_SYM_EQ("allow-header-NIL"))
    OPT_SERV_X_TOGGLE(opts->allow_hdr_nil);
  else if (OPT_SERV_SYM_EQ("unspecified-hostname-append-port"))
    OPT_SERV_X_TOGGLE(opts->add_def_port);

  else if (OPT_SERV_SYM_EQ("limit"))
  {
    CONF_SC_MAKE_CLIST_BEG(limit, clist);
    
    else if (OPT_SERV_SYM_EQ("request-configuration-size") ||
             OPT_SERV_SYM_EQ("request-configuration-sz") ||
             OPT_SERV_SYM_EQ("req-conf-size") ||
             OPT_SERV_SYM_EQ("req-conf-sz"))
      OPT_SERV_X_UINT(opts->max_req_conf_sz);
    else if (OPT_SERV_SYM_EQ("nodes"))
    { /* this limts how much you can have in the configs., not over HTTP */
      CONF_SC_MAKE_CLIST_BEG(nodes, clist);
      
      else if (OPT_SERV_SYM_EQ("Accept:"))
        OPT_SERV_X_UINT(opts->max_neg_A_nodes);
      else if (OPT_SERV_SYM_EQ("Accept-Language:"))
        OPT_SERV_X_UINT(opts->max_neg_AL_nodes);

      CONF_SC_MAKE_CLIST_END();
    }
    
    CONF_SC_MAKE_CLIST_END();
  }

  else if (OPT_SERV_SYM_EQ("HTTP") || OPT_SERV_SYM_EQ("http"))
    return (httpd__conf_main_policy_http_d1(opts, conf, token));
  
  else
    return (FALSE);
  
  return (TRUE);
}

static int httpd__conf_main_policy(Httpd_opts *opts,
                                   Conf_parse *conf, Conf_token *token)
{
  Opt_serv_policy_opts *popts = NULL;
  Conf_token *ntoken = NULL;
  unsigned int cur_depth = opt_policy_sc_conf_parse(opts->s, conf, token,
                                                    &popts, &ntoken);
  
  if (!cur_depth)
    return (FALSE);

  do
  {
    int clist = FALSE;
    
    CONF_SC_MAKE_CLIST_MID(cur_depth, clist);
    
    else if (httpd__conf_main_policy_d1((Httpd_policy_opts *)popts, conf, token,
                                        clist))
    { }
    
    CONF_SC_MAKE_CLIST_END();
  } while (ntoken &&
           (cur_depth = opt_policy_sc_conf_parse(opts->s, conf, token,
                                                 &popts, &ntoken)));
  return (TRUE);
}

typedef struct Httpd__match_uval
{
 Conf_token opt_nxt; /* token first, so we can just use it as that */
 void (*s_cb_func)(Vstr_ref *);
 Vstr_base *name;
} Httpd__match_uval;

static int httpd__match_ref_del_eq(Vstr_base *s1, Vstr_ref *ref)
{
  int eq = FALSE;
  
  if (ref)
  {
    Httpd__match_uval *uval = ref->ptr;
    if (uval->name)
      eq = vstr_cmp_eq(uval->name, 1, uval->name->len, s1, 1, s1->len);
  }

  if (eq)
    vstr_ref_del(ref);

  return (eq);
}

static int httpd__match_find(Conf_parse *conf, Conf_token **token)
{
  Vstr_ref *ref = NULL;
  unsigned int num = 0;
  
  if (!httpd__match_iter_beg(conf, *token, &ref, &num))
    return (FALSE);
  
  do
  {    
    if (httpd__match_ref_del_eq(conf->tmp, ref))
      return (TRUE);
  } while (httpd__match_iter_nxt(conf, *token, &ref, &num));

  return (FALSE);
}

static int httpd__match_find_before(Conf_parse *conf, Conf_token **token)
{
  Vstr_ref *ref = NULL;
  unsigned int num = 0;
  Conf_token prev[1];
  
  if (!httpd__match_iter_beg(conf, *token, &ref, &num))
    return (FALSE);
  
  if (httpd__match_ref_del_eq(conf->tmp, ref))
  {
    *token = NULL;
    return (TRUE);
  }

  *prev = **token;
  while (httpd__match_iter_nxt(conf, *token, &ref, &num))
  {
    if (httpd__match_ref_del_eq(conf->tmp, ref))
    {
      **token = *prev;
      return (TRUE);
    }
    
    *prev = **token; 
  }

  return (FALSE);
}

static void httpd__match_ref_cb(Vstr_ref *ref)
{
  Httpd__match_uval *uval = ref->ptr;

  vstr_free_base(uval->name);
  
  (*uval->s_cb_func)(ref);
}

static int httpd__match_make(Conf_parse *conf, Conf_token *token,
                             unsigned int type,
                             Conf_token *beg, Conf_token *end)
{
  unsigned int outer_depth = token->depth_num;
  int ret = FALSE;
  Vstr_ref *ref  = NULL;
  Conf_token token_srch_tmp = CONF_TOKEN_INIT;
  Conf_token save = CONF_TOKEN_INIT;
  Conf_token *add_beg = end;
  Httpd__match_uval *uval = NULL;
  int auto_reclaim_ref = FALSE;
  
  ASSERT(beg && end && (!beg->num == !end->num));
  
  if (!conf_token_set_user_value(conf, token, type, NULL, 0))
    return (FALSE);

  if (!(ref = vstr_ref_make_malloc(sizeof(Httpd__match_uval))))
    return (FALSE);
  uval = ref->ptr;
  
  uval->name = NULL;
  uval->s_cb_func = ref->func;
  ref->func = httpd__match_ref_cb;
  uval->opt_nxt = save = *token;
  
  ret = conf_token_set_user_value(conf, &save, type, ref, 0);
  ASSERT(ret);

  vstr_ref_del(ref); /* going to use uval/ref later, but that's OK */
    
  CONF_SC_PARSE_TOP_TOKEN_RET(conf, token, FALSE);
  if (token->type != CONF_TOKEN_TYPE_SLIST)
  {
    int clist_name = FALSE;
    int clist_xtra = FALSE;
    unsigned int inner_depth = 0;
    const Vstr_sect_node *pv = NULL;
    
    CONF_SC_TOGGLE_CLIST_VAR(clist_name);

    if (token->type == CONF_TOKEN_TYPE_CLIST)
      goto skip_name;
    
    if (!(pv = conf_token_value(token)))
      return (FALSE);
    
    if (!(uval->name = vstr_make_base(conf->tmp->conf)))
      return (FALSE);

    if (!vstr_add_vstr(uval->name, 0,
                       conf->data, pv->pos, pv->len, VSTR_TYPE_ADD_BUF_REF))
      return (FALSE);

   skip_name:
    inner_depth = token->depth_num;
    CONF_SC_MAKE_CLIST_MID(inner_depth, clist_xtra);

    else if (token->type == CONF_TOKEN_TYPE_SLIST)
      goto skip_position;
    else if (OPT_SERV_SYM_EQ("after")  && beg->num)
    {
      OPT_SERV_X_SINGLE_VSTR(conf->tmp);
      token_srch_tmp = *beg;
      add_beg = &token_srch_tmp;
      if (!httpd__match_find(conf, &add_beg))
        return (FALSE);
    }
    else if (OPT_SERV_SYM_EQ("before") && beg->num)
    {
      OPT_SERV_X_SINGLE_VSTR(conf->tmp);
      token_srch_tmp = *beg;
      add_beg = &token_srch_tmp;
      if (!httpd__match_find_before(conf, &add_beg))
        return (FALSE);
    }
    else if (OPT_SERV_SYM_EQ("end"))
      add_beg = end;
    else if (OPT_SERV_SYM_EQ("beg") || OPT_SERV_SYM_EQ("beginning"))
      add_beg = NULL;
    else if (OPT_SERV_SYM_EQ("<reclaim-memory>"))
      OPT_SERV_X_TOGGLE(auto_reclaim_ref);
      
    CONF_SC_MAKE_CLIST_END();
    
    CONF_SC_PARSE_SLIST_DEPTH_TOKEN_RET(conf, token, outer_depth, FALSE);
  }
 skip_position:
  if ((token->type != CONF_TOKEN_TYPE_SLIST) ||
      (conf_token_at_depth(token) != outer_depth))
    return (FALSE);

  ASSERT(ref);

  if (auto_reclaim_ref && !uval->name)
    ref = NULL;
  
  if (!beg->num)
  {
    ret = conf_token_set_user_value(conf, &save, type, ref, 0);
    ASSERT(ret);    
    *beg = save;
    *end = save;
  }
  else if (!add_beg) /* put before beg */
  {
    ret = conf_token_set_user_value(conf, &save, type, ref, beg->num);
    ASSERT(ret);
    *beg = save;
  }
  else
  {
    Vstr_ref *oref = NULL;
    unsigned int nxt = 0;

    ASSERT(add_beg && ((add_beg->type - CONF_TOKEN_TYPE_USER_BEG) == type));
    ASSERT(add_beg->num != 0);

    oref = conf_token_get_user_value(conf, add_beg, &nxt);
    ASSERT(oref);

    ret = conf_token_set_user_value(conf, &save, type, ref, nxt);
    ASSERT(ret);
    ret = conf_token_set_user_value(conf, add_beg, type, oref, save.num);
    ASSERT(ret);

    if (!nxt) /* put after end */
    {
      ASSERT(add_beg->num == end->num);
      *end = save;
    }
    
    vstr_ref_del(oref);
  }
  
  return (TRUE);
}

static int httpd__conf_main_d1(Httpd_opts *httpd_opts,
                               Conf_parse *conf, Conf_token *token, int clist)
{
  if (OPT_SERV_SYM_EQ("org.and.daemon-conf-1.0"))
  {
    if (!opt_serv_conf(httpd_opts->s, conf, token))
      return (FALSE);
  }
  
  else if (OPT_SERV_SYM_EQ("match-init"))
    OPT_SERV_SC_MATCH_INIT(httpd_opts->s,
                           httpd__conf_main_d1(httpd_opts, conf, token, clist));
  
  else if (OPT_SERV_SYM_EQ("policy"))
  {
    if (!httpd__conf_main_policy(httpd_opts, conf, token))
      return (FALSE);
  }
  
  else if (OPT_SERV_SYM_EQ("match-connection"))
  {
    if (!httpd__match_make(conf, token, HTTPD_CONF_MAIN_MATCH_CON,
                           httpd_opts->match_connection,
                           httpd_opts->tmp_match_connection))
      return (FALSE);
    
    if (!conf_parse_end_token(conf, token, conf_token_at_depth(token)))
      return (FALSE);
  }
  else if (OPT_SERV_SYM_EQ("match-request"))
  {
    if (!httpd__match_make(conf, token, HTTPD_CONF_MAIN_MATCH_REQ,
                           httpd_opts->match_request,
                           httpd_opts->tmp_match_request))
      return (FALSE);
    
    if (!conf_parse_end_token(conf, token, conf_token_at_depth(token)))
      return (FALSE);
  }
  else if (OPT_SERV_SYM_EQ("match-error-response"))
  {
    if (!httpd__match_make(conf, token, HTTPD_CONF_MAIN_MATCH_RESP,
                           httpd_opts->match_response,
                           httpd_opts->tmp_match_response))
      return (FALSE);
    
    if (!conf_parse_end_token(conf, token, conf_token_at_depth(token)))
      return (FALSE);
  }
  
  else
    return (FALSE);
  
  return (TRUE);
}

int httpd_conf_main(Httpd_opts *opts, Conf_parse *conf, Conf_token *token)
{
  unsigned int cur_depth = token->depth_num;
  int clist = FALSE;
  
  if (!OPT_SERV_SYM_EQ("org.and.httpd-conf-main-1.0") &&
      !OPT_SERV_SYM_EQ("org.and.jhttpd-conf-main-1.0"))
    return (FALSE);

  CONF_SC_MAKE_CLIST_MID(cur_depth, clist);

  else if (httpd__conf_main_d1(opts, conf, token, clist))
  { }
  
  CONF_SC_MAKE_CLIST_END();
  
  /* And they all live together ... dum dum */
  if (conf->data->conf->malloc_bad)
    return (FALSE);
  
  return (TRUE);
}

#define HTTPD_CONF__BEG_APP() do {                                      \
      ASSERT(!opts->conf_num || (conf->state == CONF_PARSE_STATE_END)); \
      prev_conf_num = conf->sects->num;                                 \
      /* reinit */                                                      \
      conf->state = CONF_PARSE_STATE_BEG;                               \
    } while (FALSE)

/* restore the previous parsing we've done and skip parsing it again */
#define HTTPD_CONF__END_APP() do {                                      \
      if (opts->conf_num)                                               \
      {                                                                 \
        conf_parse_token(conf, token);                                  \
        conf_parse_num_token(conf, token, prev_conf_num);               \
      }                                                                 \
    } while (FALSE)
    

int httpd_conf_main_parse_cstr(Vstr_base *out,
                               Httpd_opts *opts, const char *data)
{
  Conf_parse *conf    = opts->conf;
  Conf_token token[1] = {CONF_TOKEN_INIT};
  unsigned int prev_conf_num = 0;
  size_t pos = 1;
  size_t len = 0;

  ASSERT(opts && data);

  if (!conf && !(conf = conf_parse_make(NULL)))
    goto conf_malloc_fail;

  pos = conf->data->len + 1;
  if (!vstr_add_cstr_ptr(conf->data, conf->data->len,
                         "(org.and.httpd-conf-main-1.0 "))
    goto read_malloc_fail;
  if (!vstr_add_cstr_ptr(conf->data, conf->data->len, data))
    goto read_malloc_fail;
  if (!vstr_add_cstr_ptr(conf->data, conf->data->len,
                         ")"))
    goto read_malloc_fail;
  len = vstr_sc_posdiff(pos, conf->data->len);

  HTTPD_CONF__BEG_APP();
  
  if (!conf_parse_lex(conf, pos, len))
    goto conf_fail;

  HTTPD_CONF__END_APP();

  if (!conf_parse_token(conf, token))
    goto conf_fail;

  if ((token->type != CONF_TOKEN_TYPE_CLIST) || (token->depth_num != 1))
    goto conf_fail;
    
  if (!conf_parse_token(conf, token))
    goto conf_fail;

  ASSERT(OPT_SERV_SYM_EQ("org.and.httpd-conf-main-1.0"));
  
  if (!httpd_conf_main(opts, conf, token))
    goto conf_fail;

  if (token->num != conf->sects->num)
    goto conf_fail;

  opts->conf = conf;
  opts->conf_num++;
  
  return (TRUE);
  
 conf_fail:
  conf_parse_backtrace(out, data, conf, token);
 read_malloc_fail:
  conf_parse_free(conf);
 conf_malloc_fail:
  return (FALSE);
}

int httpd_conf_main_parse_file(Vstr_base *out,
                               Httpd_opts *opts, const char *fname)
{
  Conf_parse *conf    = opts->conf;
  Conf_token token[1] = {CONF_TOKEN_INIT};
  unsigned int prev_conf_num = 0;
  size_t pos = 1;
  size_t len = 0;
  
  ASSERT(opts && fname);

  if (!conf && !(conf = conf_parse_make(NULL)))
    goto conf_malloc_fail;

  pos = conf->data->len + 1;
  if (!vstr_sc_read_len_file(conf->data, conf->data->len, fname, 0, 0, NULL))
    goto read_malloc_fail;
  len = vstr_sc_posdiff(pos, conf->data->len);

  HTTPD_CONF__BEG_APP();
  
  if (!conf_parse_lex(conf, pos, len))
    goto conf_fail;

  HTTPD_CONF__END_APP();
  
  while (conf_parse_token(conf, token))
  {
    if ((token->type != CONF_TOKEN_TYPE_CLIST) || (token->depth_num != 1))
      goto conf_fail;
    
    if (!conf_parse_token(conf, token))
      goto conf_fail;
    
    if (OPT_SERV_SYM_EQ("org.and.daemon-conf-1.0"))
    {
      if (!opt_serv_conf(opts->s, conf, token))
        goto conf_fail;
    }
    else if (OPT_SERV_SYM_EQ("org.and.httpd-conf-main-1.0") ||
             OPT_SERV_SYM_EQ("org.and.jhttpd-conf-main-1.0"))
    {
      if (!httpd_conf_main(opts, conf, token))
        goto conf_fail;
    }
    else
      goto conf_fail;
    
    opts->conf_num++;
  }

  opts->conf = conf;
  
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

int httpd_sc_conf_main_parse_dir_file(Vstr_base *out, void *opts,
                                      const char *fname)
{
  return (httpd_conf_main_parse_file(out, opts, fname));
}

void httpd_conf_main_free(Httpd_opts *opts)
{
  Opt_serv_policy_opts *scan = opts->s->def_policy;

  while (scan)
  {
    Httpd_policy_opts *tmp = (Httpd_policy_opts *)scan;
    Opt_serv_policy_opts *scan_next = scan->next;
    
    mime_types_exit(tmp->mime_types);
    
    scan = scan_next;
  }
  
  opt_policy_sc_all_ref_del(opts->s);
  conf_parse_free(opts->conf); opts->conf = NULL;
  date_free(opts->date); opts->date = NULL;
  
  opt_serv_conf_free_beg(opts->s);
  opt_serv_conf_free_end(opts->s);
}

int httpd_conf_main_init(Httpd_opts *httpd_opts)
{
  Httpd_policy_opts *opts = NULL;

  if (!opt_serv_conf_init(httpd_opts->s))
    goto opts_init_fail;
  
  opts = (Httpd_policy_opts *)httpd_opts->s->def_policy;
  
  vstr_add_cstr_ptr(opts->server_name,       0, HTTPD_CONF_DEF_SERVER_NAME);
  vstr_add_cstr_ptr(opts->dir_filename,      0, HTTPD_CONF_DEF_DIR_FILENAME);
  vstr_add_cstr_ptr(opts->mime_types_def_ct, 0, HTTPD_CONF_MIME_TYPE_DEF_CT);
  vstr_add_cstr_ptr(opts->mime_types_main,   0, HTTPD_CONF_MIME_TYPE_MAIN);
  vstr_add_cstr_ptr(opts->mime_types_xtra,   0, HTTPD_CONF_MIME_TYPE_XTRA);

  if (!(httpd_opts->date = date_make()))
    goto httpd_init_fail;
  
  if (opts->s->policy_name->conf->malloc_bad)
    goto httpd_init_fail;

  return (TRUE);

 httpd_init_fail:
  httpd_conf_main_free(httpd_opts);
 opts_init_fail:
  return (FALSE);
}

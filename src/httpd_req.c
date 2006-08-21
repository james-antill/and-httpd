/*
 *  Copyright (C) 2004, 2005, 2006  James Antill
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  email: james@and.org
 */
/* main HTTP server request processing */

#define EX_UTILS_NO_FUNCS 1
#include "ex_utils.h"

#include "mk.h"

#include "vlg.h"

#define HTTPD_HAVE_GLOBAL_OPTS 1
#include "httpd.h"
#include "httpd_policy.h"

#include <syslog.h>

#if ! HTTPD_CONF_USE_MIME_XATTR
# define getxattr(w, x, y, z) (errno = ENOSYS, -1)
#else
# include <sys/xattr.h>
#endif

#if ! COMPILE_DEBUG
# define HTTP_CONF_MMAP_LIMIT_MIN (16 * 1024) /* a couple of pages */
# define HTTP_CONF_SAFE_PRINT_REQ TRUE
#else
# define HTTP_CONF_MMAP_LIMIT_MIN 8 /* debug... */
# define HTTP_CONF_SAFE_PRINT_REQ FALSE
#endif
#define HTTP_CONF_MMAP_LIMIT_MAX (50 * 1024 * 1024)

#define HTTPD_CONF_ZIP_LIMIT_MIN 8

#define CLEN COMPILE_STRLEN

/* is the cstr a prefix of the vstr */
#define VPREFIX(vstr, p, l, cstr)                                       \
    (((l) >= CLEN(cstr)) &&                                             \
     vstr_cmp_buf_eq(vstr, p, CLEN(cstr), cstr, CLEN(cstr)))
/* is the cstr a suffix of the vstr */
#define VSUFFIX(vstr, p, l, cstr)                                       \
    (((l) >= CLEN(cstr)) &&                                             \
     vstr_cmp_eod_buf_eq(vstr, p, l, cstr, CLEN(cstr)))

/* is the cstr a prefix of the vstr, no case */
#define VIPREFIX(vstr, p, l, cstr)                                      \
    (((l) >= CLEN(cstr)) &&                                             \
     vstr_cmp_case_buf_eq(vstr, p, CLEN(cstr), cstr, CLEN(cstr)))

/* for simplicity */
#define VEQ(vstr, p, l, cstr)  vstr_cmp_cstr_eq(vstr, p, l, cstr)
#define VIEQ(vstr, p, l, cstr) vstr_cmp_case_cstr_eq(vstr, p, l, cstr)

#define HTTP__HDR_SET(req, h, p, l) do {               \
      (req)-> http_hdrs -> hdr_ ## h ->pos = (p);          \
      (req)-> http_hdrs -> hdr_ ## h ->len = (l);          \
    } while (FALSE)
#define HTTP__HDR_MULTI_SET(req, h, p, l) do {         \
      (req)-> http_hdrs -> multi -> hdr_ ## h ->pos = (p); \
      (req)-> http_hdrs -> multi -> hdr_ ## h ->len = (l); \
    } while (FALSE)

#define HTTP__XTRA_HDR_INIT(x) do {             \
      req-> x ## _vs1 = NULL;                   \
      req-> x ## _pos = 0;                      \
      req-> x ## _len = 0;                      \
    } while (FALSE)

static Vlg *vlg = NULL;

void httpd_req_init(Vlg *passed_vlg)
{
  ASSERT(passed_vlg && !vlg);
  vlg = passed_vlg;
}

void httpd_req_exit(void)
{
  ASSERT(vlg);
  vlg = NULL;
}

Httpd_req_data *http_req_make(struct Con *con)
{
  static Httpd_req_data real_req[1];
  Httpd_req_data *req = real_req;
  const Httpd_policy_opts *policy = NULL;
  
  ASSERT(!req->using_req);

  if (!req->done_once)
  {
    Vstr_conf *conf = NULL;

    if (con)
      conf = con->evnt->io_w->conf;
      
    if (!(req->fname                            = vstr_make_base(conf)) ||
        !(req->http_hdrs->multi->combiner_store = vstr_make_base(conf)) ||
        !(req->sects                            = vstr_sects_make(8)) ||
        !(req->tag                              = vstr_make_base(conf)))
      return (NULL);
    
    req->f_mmap       = NULL;
    req->xtra_content = NULL;
  }

  http_parse_clear_hdrs(req);
  
  req->http_hdrs->multi->comb = con ? con->evnt->io_r : NULL;

  vstr_del(req->fname, 1, req->fname->len);

  req->now = evnt_sc_time();
  
  req->len = 0;

  req->path_pos = 0;
  req->path_len = 0;

  req->error_code = 0;
  req->error_line = "";
  req->error_msg  = "";
  req->error_xmsg = "";
  req->error_len  = 0;

  req->fs_len     = 0;

  req->f_stat_st_size = 0;

  req->sects->num = 0;
  /* f_stat */
  if (con)
    req->orig_io_w_len = con->evnt->io_w->len;

  /* NOTE: These should probably be allocated at init time, depending on the
   * option flags given */
  ASSERT(!req->f_mmap || !req->f_mmap->len);
  if (req->f_mmap)
    vstr_del(req->f_mmap, 1, req->f_mmap->len);
  ASSERT(!req->xtra_content || !req->xtra_content->len);
  if (req->xtra_content)
    vstr_del(req->xtra_content, 1, req->xtra_content->len);
  
  req->vhost_prefix_len = 0;
  
  req->sects->malloc_bad = FALSE;

  req->parsed_content_encoding   = FALSE;
  req->content_encoding_identity = TRUE;
  req->content_encoding_gzip     = FALSE;
  req->content_encoding_bzip2    = FALSE;
  req->content_encoding_xgzip    = FALSE;

  req->user_return_error_code = FALSE;

  req->vary_star = con ? con->vary_star : FALSE;
  req->vary_a    = FALSE;
  req->vary_ac   = FALSE;
  req->vary_ae   = FALSE;
  req->vary_al   = FALSE;
  req->vary_rf   = FALSE;
  req->vary_ua   = FALSE;
  req->vary_ims  = FALSE;
  req->vary_ius  = FALSE;
  req->vary_ir   = FALSE;
  req->vary_im   = FALSE;
  req->vary_inm  = FALSE;
  req->vary_xm   = FALSE;

  req->direct_uri         = FALSE;
  req->direct_filename    = FALSE;
  req->skip_document_root = FALSE;
  
  req->ver_0_9    = FALSE;
  req->ver_1_1    = FALSE;
  req->ver_1_x    = FALSE;
  req->head_op    = FALSE;

  req->chked_encoded_path = FALSE;
  
  req->neg_content_type_done = FALSE;
  req->neg_content_lang_done = FALSE;
      
  req->conf_secure_dirs   = FALSE;
  req->conf_friendly_file = FALSE;
  req->conf_friendly_dirs = FALSE;
  
  req->done_once  = TRUE;
  req->using_req  = TRUE;

  req->malloc_bad = FALSE;

  if (con && !vstr_sub_vstr(req->tag, 1, req->tag->len,
                            con->tag, 1, con->tag->len, VSTR_TYPE_SUB_BUF_REF))
    return (NULL);
  
  if (!con)
    req->policy = NULL;
  else
  {
    policy = con->policy;
    httpd_policy_change_req(con, req, policy);
  }
  
  return (req);
}

void http_req_free(Httpd_req_data *req)
{
  if (!req) /* for if/when move to malloc/free */
    return;

  ASSERT(req->done_once && req->using_req);

  /* we do vstr deletes here to return the nodes back to the pool */
  vstr_del(req->fname, 1, req->fname->len);
  ASSERT(!req->http_hdrs->multi->combiner_store->len);
  if (req->f_mmap)
    vstr_del(req->f_mmap, 1, req->f_mmap->len);

  req->http_hdrs->multi->comb = NULL;

  req->using_req = FALSE;
}

void http_req_exit(void)
{
  Httpd_req_data *req = http_req_make(NULL);
  struct Http_hdrs__multi *tmp = NULL;
  
  if (!req)
    return;

  tmp = req->http_hdrs->multi;
  
  vstr_free_base(req->fname);          req->fname          = NULL;
  vstr_free_base(tmp->combiner_store); tmp->combiner_store = NULL;
  vstr_free_base(req->f_mmap);         req->f_mmap         = NULL;
  vstr_free_base(req->xtra_content);   req->xtra_content   = NULL;
  vstr_sects_free(req->sects);         req->sects          = NULL;
  vstr_free_base(req->tag);            req->tag            = NULL;
  
  req->done_once = FALSE;
  req->using_req = FALSE;
}


void httpd_req_absolute_uri(struct Con *con, Httpd_req_data *req,
                            Vstr_base *lfn, size_t pos, size_t len)
{
  Vstr_base *data = con->evnt->io_r;
  size_t apos = pos - 1;
  size_t alen = lfn->len;
  int has_schema   = TRUE;
  int has_abs_path = TRUE;
  int has_data     = TRUE;
  unsigned int prev_num = 0;
  
  if (!VPREFIX(lfn, pos, len, "http://"))
  {
    has_schema = FALSE;
    if (!VPREFIX(lfn, pos, len, "/")) /* relative pathname */
    {
      if (VPREFIX(lfn, pos, len, "./"))
      {
        has_data = TRUE;
        vstr_del(lfn, pos, CLEN("./")); len -= CLEN("./");
        alen = lfn->len;
      }
      else
      {
        while (VPREFIX(lfn, pos, len, "../"))
        {
          ++prev_num;
          vstr_del(lfn, pos, CLEN("../")); len -= CLEN("../");
        }
        if (prev_num)
          alen = lfn->len;
        else
          has_data = !!lfn->len;
      }
      
      has_abs_path = FALSE;
    }
  }

  if (!has_schema)
  {
    vstr_add_cstr_buf(lfn, apos, "http://");
    apos += lfn->len - alen;
    alen = lfn->len;
    httpd_sc_add_hostname(con, req, lfn, apos);
    apos += lfn->len - alen;
  }
    
  if (!has_abs_path)
  {
    size_t path_len = req->path_len;

    if (has_data || prev_num)
    {
      path_len -= vstr_cspn_cstr_chrs_rev(data, req->path_pos, path_len, "/");
      
      while (path_len && prev_num--)
      {
        path_len -= vstr_spn_cstr_chrs_rev(data,  req->path_pos, path_len, "/");
        path_len -= vstr_cspn_cstr_chrs_rev(data, req->path_pos, path_len, "/");
      }
      if (!path_len) path_len = 1; /* make sure there is a / at the end */
    }

    vstr_add_vstr(lfn, apos, data, req->path_pos, path_len, VSTR_TYPE_ADD_DEF);
  }
}

/* doing http://www.example.com/foo/bar where bar is a dir is bad
   because all relative links will be relative to foo, not bar.
   Also note that location must be "http://www.example.com/foo/bar/" or maybe
   "http:/foo/bar/" (but we don't use the later anymore)
*/
int http_req_chk_dir(struct Con *con, Httpd_req_data *req, const char *xmsg)
{
  Vstr_base *fname = req->fname;
  
  /* fname == what was just passed to open() */
  ASSERT(fname->len);

  if (req->policy->use_secure_dirs && !req->conf_secure_dirs)
  { /* check if file exists before redirecting without leaking info. */
    const char *fname_cstr = NULL;
    struct stat64 d_stat[1];
  
    vstr_add_cstr_buf(fname, fname->len, "/");
    HTTPD_APP_REF_ALLVSTR(fname, req->policy->dir_filename);
    
    fname_cstr = vstr_export_cstr_ptr(fname, 1, fname->len);
    if (fname->conf->malloc_bad)
      return (http_fin_errmem_req(con, req));

    if ((stat64(fname_cstr, d_stat) == -1) || !S_ISREG(d_stat->st_mode))
      HTTPD_ERR_MSG_RET(req, 404, xmsg, http_fin_err_req(con, req));
  }
  
  vstr_del(fname, 1, fname->len);
  httpd_req_absolute_uri(con, req, fname, 1, fname->len);
  
  /* we got:       http://foo/bar/
   * and so tried: http://foo/bar/index.html
   *
   * but foo/bar/index.html is a directory (fun), so redirect to:
   *               http://foo/bar/index.html/
   */
  if (fname->len && (vstr_export_chr(fname, fname->len) == '/'))
    HTTPD_APP_REF_ALLVSTR(fname, req->policy->dir_filename);
  
  vstr_add_cstr_buf(fname, fname->len, "/");
  
  HTTPD_REDIR_MSG(req, 301, "dir -> filename");
  
  if (fname->conf->malloc_bad)
    return (http_fin_errmem_req(con, req));
  
  return (http_fin_err_req(con, req));
}

/* doing http://www.example.com/foo/bar/ when url is really
   http://www.example.com/foo/bar is a very simple mistake, so we almost
   certainly don't want a 404 */
int http_req_chk_file(struct Con *con, Httpd_req_data *req, const char *xmsg)
{
  Vstr_base *fname = req->fname;
  size_t len = 0;
  
  /* fname == what was just passed to open() */
  ASSERT(fname->len);

  if (!req->policy->use_friendly_dirs)
    HTTPD_ERR_MSG_RET(req, 404, xmsg, http_fin_err_req(con, req));
  else if (!req->conf_friendly_dirs)
  { /* check if file exists before redirecting without leaking info. */
    const char *fname_cstr = NULL;
    struct stat64 d_stat[1];
    len = vstr_cspn_cstr_chrs_rev(fname, 1, fname->len, "/") + 1;

    /* must be a filename, can't be toplevel */
    if ((len <= 1) || (len >= (fname->len - req->vhost_prefix_len)))
      HTTPD_ERR_MSG_RET(req, 404, xmsg, http_fin_err_req(con, req));

    vstr_sc_reduce(fname, 1, fname->len, len);
    
    fname_cstr = vstr_export_cstr_ptr(fname, 1, fname->len);
    if (fname->conf->malloc_bad)
      return (http_fin_errmem_req(con, req));    
    if ((stat64(fname_cstr, d_stat) == -1) && !S_ISREG(d_stat->st_mode))
      HTTPD_ERR_MSG_RET(req, 404, xmsg, http_fin_err_req(con, req));
  }
  
  vstr_sub_cstr_ptr(fname, 1, fname->len, "./");
  httpd_req_absolute_uri(con, req, fname, 1, fname->len);
  assert(VSUFFIX(fname, 1, fname->len, "/"));
  vstr_sc_reduce(fname, 1, fname->len, strlen("/"));

  HTTPD_REDIR_MSG(req, 301, "filename -> dir");
  
  if (fname->conf->malloc_bad)
    return (http_fin_errmem_req(con, req));
  
  return (http_fin_err_req(con, req));
}

/* FIXME: maybe should be in the parse section...? */
void http_req_split_method(struct Con *con, struct Httpd_req_data *req)
{
  Vstr_base *s1 = con->evnt->io_r;
  size_t pos = 1;
  size_t len = req->len;
  size_t el = 0;
  size_t skip_len = 0;
  unsigned int orig_num = req->sects->num;
  
  el = vstr_srch_cstr_buf_fwd(s1, pos, len, HTTP_EOL);
  ASSERT(el >= pos);
  len = el - pos; /* only parse the first line */

  /* split request */
  if (!(el = vstr_srch_cstr_chrs_fwd(s1, pos, len, HTTP_LWS)))
    return;
  vstr_sects_add(req->sects, pos, el - pos);
  len -= (el - pos); pos += (el - pos);

  /* just skip whitespace on method call... */
  if ((skip_len = vstr_spn_cstr_chrs_fwd(s1, pos, len, HTTP_LWS)))
  { len -= skip_len; pos += skip_len; }

  if (!len)
    goto req_line_parse_err;
  
  if (!(el = vstr_srch_cstr_chrs_fwd(s1, pos, len, HTTP_LWS)))
  {
    vstr_sects_add(req->sects, pos, len);
    len = 0;
  }
  else
  {
    vstr_sects_add(req->sects, pos, el - pos);
    len -= (el - pos); pos += (el - pos);
    
    /* just skip whitespace on method call... */
    if ((skip_len = vstr_spn_cstr_chrs_fwd(s1, pos, len, HTTP_LWS)))
    { len -= skip_len; pos += skip_len; }
  }

  if (len)
    vstr_sects_add(req->sects, pos, len);
  else if (!req->policy->allow_http_0_9)
    return; /* we keep it, for logging */
  else
    req->ver_0_9 = TRUE;

  if (req->sects->malloc_bad)
    goto req_line_parse_err;
  
  return;
  
 req_line_parse_err:
  req->sects->num = orig_num;
}

void http_req_split_hdrs(struct Con *con, struct Httpd_req_data *req)
{
  Vstr_base *s1 = con->evnt->io_r;
  size_t pos = 1;
  size_t len = req->len;
  size_t el = 0;
  size_t hpos = 0;

  ASSERT(req->sects->num >= 3);  
    
  /* skip first line */
  el = (VSTR_SECTS_NUM(req->sects, req->sects->num)->pos +
        VSTR_SECTS_NUM(req->sects, req->sects->num)->len);
  
  assert(VEQ(s1, el, CLEN(HTTP_EOL), HTTP_EOL));
  len -= (el - pos) + CLEN(HTTP_EOL); pos += (el - pos) + CLEN(HTTP_EOL);
  
  if (VPREFIX(s1, pos, len, HTTP_EOL))
    return; /* end of headers */

  ASSERT(vstr_srch_cstr_buf_fwd(s1, pos, len, HTTP_END_OF_REQUEST));
  /* split headers */
  hpos = pos;
  while ((el = vstr_srch_cstr_buf_fwd(s1, pos, len, HTTP_EOL)) != pos)
  {
    char chr = 0;
    
    len -= (el - pos) + CLEN(HTTP_EOL); pos += (el - pos) + CLEN(HTTP_EOL);

    chr = vstr_export_chr(s1, pos);
    if (chr == ' ' || chr == '\t') /* header continues to next line */
      continue;

    vstr_sects_add(req->sects, hpos, el - hpos);
    
    hpos = pos;
  }
}

/* try to set the content-type,
 * . first if it's manually set leave it,
 * . next try looking it up in the xattr for the file.
 * . next do a real "lookup" based on the filename
 * NOTE: If this lookup "fails" it still returns
 * the default content-type. So we just have to determine if we want to use
 * it or not. Can also return "content-types" like /404/ which returns a 404
 * error for the request */
int http_req_content_type(Httpd_req_data *req)
{
  const Vstr_base *vs1 = NULL;
  size_t     pos = 0;
  size_t     len = 0;

  if (req->content_type_vs1) /* manually set */
    return (TRUE);

  if (req->policy->use_mime_xattr)
  { /* lookup mime/type in the xattr of the filename -- this is racey
     * but we want to parse the accept line before, open(), so we can't use
     * fgetxattr() anyway. */
    static const char key[] = "user.mime_type";
    char buf[1024]; /* guess */
    ssize_t ret = -1;
    const char *fname_cstr = NULL;
    
    if (!req->xtra_content && !(req->xtra_content = vstr_make_base(NULL)))
      return (FALSE);

    fname_cstr = vstr_export_cstr_ptr(req->fname, 1, req->fname->len);
    ASSERT(fname_cstr); /* must have been done before call */

    /* don't use lgetxattr() as it does nothing on Linux */
    if ((ret = getxattr(fname_cstr, key, buf, sizeof(buf))) != -1)
    {
      pos = req->xtra_content->len + 1;
      len = ret;
      if (!vstr_add_buf(req->xtra_content, req->xtra_content->len, buf, len))
        return (FALSE);

      req->content_type_vs1 = req->xtra_content;
      req->content_type_pos = pos;
      req->content_type_len = len;
      
      HTTP_REQ__X_CONTENT_HDR_CHK(content_type);
      
      return (TRUE);
    }
    else if (errno == ENOSYS)
      httpd_disable_getxattr();
    else if ((errno == EOPNOTSUPP) || (errno == EPERM))
    { /* time limit the warn messages... */
      static time_t last = -1;
      time_t now = evnt_sc_time();

      if ((last == -1) || (difftime(last, now) > (10 * 60)))
      {
        vlg_warn(vlg, "getxattr($<vstr.all:%p>, %s): %m\n", req->fname, key);
        last = now;
      }
    }
  }
  
  mime_types_match(req->policy->mime_types,
                   req->fname, 1, req->fname->len, &vs1, &pos, &len);
  if (!len)
  {
    req->parse_accept = FALSE;
    return (TRUE);
  }
  
  if ((vstr_export_chr(vs1, pos) == '/') && (len > 2) &&
      (vstr_export_chr(vs1, vstr_sc_poslast(pos, len)) == '/'))
  {
    size_t num_len = 1;
    static const char xmsg[] = "Mime/Type";
    
    len -= 2;
    ++pos;
    req->user_return_error_code = TRUE;
    req->direct_filename = FALSE;
    switch (vstr_parse_uint(vs1, pos, len, 0, &num_len, NULL))
    {
      case 400: if (num_len == len) HTTPD_ERR_MSG_RET(req, 400, xmsg, FALSE);
      case 403: if (num_len == len) HTTPD_ERR_MSG_RET(req, 403, xmsg, FALSE);
      case 404: if (num_len == len) HTTPD_ERR_MSG_RET(req, 404, xmsg, FALSE);
      case 410: if (num_len == len) HTTPD_ERR_MSG_RET(req, 410, xmsg, FALSE);
      case 500: if (num_len == len) HTTPD_ERR_MSG_RET(req, 500, xmsg, FALSE);
      case 503: if (num_len == len) HTTPD_ERR_MSG_RET(req, 503, xmsg, FALSE);
        
      default: /* just ignore any other content */
        req->user_return_error_code = FALSE;
        return (TRUE);
    }
  }

  req->content_type_vs1 = vs1;
  req->content_type_pos = pos;
  req->content_type_len = len;

  return (TRUE);
}

static void httpd__req_etag_hex_num(Vstr_base *vs1, uintmax_t val, int more)
{
  char buf[(sizeof(uintmax_t) * CHAR_BIT) + 1];
  size_t len = 0;

  len = vstr_sc_conv_num_uintmax(buf, sizeof(buf), val, "0123456789abcdef", 16);
  vstr_add_buf(vs1, vs1->len, buf, len);
  if (more)
    vstr_add_cstr_buf(vs1, vs1->len, "-");
}

static int httpd__req_etag_auto(struct Httpd_req_data *req)
{
  size_t xpos = 0;
  Vstr_base *vs1 = NULL;
  
  ASSERT(!req->etag_vs1 && req->policy->etag_auto_type);
  
  if (!(xpos = http_req_xtra_content(req, NULL, 0, &req->etag_len)))
    return (FALSE);
  vs1 = req->xtra_content;

  /* If it's too soon, make it weak */
  if (difftime(req->now, req->f_stat->st_mtime) <= 1)
    vstr_add_cstr_buf(vs1, vs1->len, "W/");
  
  vstr_add_cstr_buf(vs1, vs1->len, "\"");
  switch (req->policy->etag_auto_type)
  {
    case HTTPD_ETAG_TYPE_AUTO_DISM:
      httpd__req_etag_hex_num(vs1, req->f_stat->st_dev,   TRUE);
      /* FALL THROUGH */
    case HTTPD_ETAG_TYPE_AUTO_ISM:
      httpd__req_etag_hex_num(vs1, req->f_stat->st_ino,   TRUE);
      /* FALL THROUGH */      
    case HTTPD_ETAG_TYPE_AUTO_SM:
      httpd__req_etag_hex_num(vs1, req->f_stat->st_size,  TRUE);
      httpd__req_etag_hex_num(vs1, req->f_stat->st_mtime, FALSE);
      /* Use st_mtime.tv_nsec ? */
      
      ASSERT_NO_SWITCH_DEF();
  }
  vstr_add_cstr_buf(vs1, vs1->len, "\"");

  req->etag_vs1 = vs1;
  req->etag_pos = xpos;
  req->etag_len = (req->xtra_content->len - xpos) + 1;

  return (!vs1->conf->malloc_bad);
}

#define HTTPD__HD_EQ(x)                                 \
    VEQ(hdrs, h_ ## x ->pos,  h_ ## x ->len,  date)

/* gets here if the GET/HEAD response is ok, we test for caching etc. using the
 * if-* headers */
/* FALSE = 412 Precondition Failed */
static int http_response_ok(struct Con *con, struct Httpd_req_data *req,
                            unsigned int *http_ret_code,
                            const char ** http_ret_line)
{
  const Vstr_base *hdrs = con->evnt->io_r;
  time_t mtime = req->f_stat->st_mtime;
  Vstr_sect_node *h_ims  = req->http_hdrs->hdr_if_modified_since;
  Vstr_sect_node *h_ir   = req->http_hdrs->hdr_if_range;
  Vstr_sect_node *h_iums = req->http_hdrs->hdr_if_unmodified_since;
  Vstr_sect_node *h_r    = req->http_hdrs->hdr_range;
  Vstr_base *comb = req->http_hdrs->multi->comb;
  Vstr_sect_node *h_im   = req->http_hdrs->multi->hdr_if_match;
  Vstr_sect_node *h_inm  = req->http_hdrs->multi->hdr_if_none_match;
  int h_ir_tst      = FALSE;
  int h_iums_tst    = FALSE;
  int req_if_range  = FALSE;
  int cached_output = FALSE;
  const char *date = NULL;
  
  if (HTTPD_VER_GE_1_1(req) && h_iums->pos)
    h_iums_tst = TRUE;

  if (HTTPD_VER_GE_1_1(req) && h_ir->pos && h_r->pos)
    h_ir_tst = TRUE;
  
  /* assumes time doesn't go backwards ... From rfc2616:
   *
   * Note: When handling an If-Modified-Since header field, some
   * servers will use an exact date comparison function, rather than a
   * less-than function, for deciding whether to send a 304 (Not
   * Modified) response. To get best results when sending an If-
   * Modified-Since header field for cache validation, clients are
   * advised to use the exact date string received in a previous Last-
   * Modified header field whenever possible.
   */
  if (difftime(req->now, mtime) > 0)
  { /* if mtime in future, or now ... don't allow checking */
    Date_store *ds = httpd_opts->date;

    date = date_rfc1123(ds, mtime);
    if (h_ims->pos && !cached_output && HTTPD__HD_EQ(ims))
      cached_output = TRUE;
    if (h_iums_tst &&                   HTTPD__HD_EQ(iums))
      return (FALSE);
    if (h_ir_tst   && !req_if_range  && HTTPD__HD_EQ(ir))
      req_if_range = TRUE;
  
    date = date_rfc850(ds, mtime);
    if (h_ims->pos && !cached_output && HTTPD__HD_EQ(ims))
      cached_output = TRUE;
    if (h_iums_tst &&                   HTTPD__HD_EQ(iums))
      return (FALSE);
    if (h_ir_tst   && !req_if_range  && HTTPD__HD_EQ(ir))
      req_if_range = TRUE;
  
    date = date_asctime(ds, mtime);
    if (h_ims->pos && !cached_output && HTTPD__HD_EQ(ims))
      cached_output = TRUE;
    if (h_iums_tst &&                   HTTPD__HD_EQ(iums))
      return (FALSE);
    if (h_ir_tst   && !req_if_range  && HTTPD__HD_EQ(ir))
      req_if_range = TRUE;
  }

  if (HTTPD_VER_GE_1_1(req))
  {
    const Vstr_base *vs1 = NULL;
    size_t pos = 0;
    size_t len = 0;

    if (req->policy->etag_auto_type && !req->etag_vs1)
    {
      if (!httpd__req_etag_auto(req))
      {
        con->evnt->io_w->conf->malloc_bad = TRUE;
        return (TRUE); /* dealt with in http_req_op_get, can't continue */
      }

      req->etag_time = mtime;
    }
    if (req->etag_vs1 && (req->etag_time >= mtime))
    {
      vs1 = req->etag_vs1;
      pos = req->etag_pos;
      len = req->etag_len;
    }

    if (h_ir_tst   && !req_if_range &&
        httpd_match_etags(req,
                          hdrs, h_ir->pos, h_ir->len, vs1, pos, len, FALSE))
      req_if_range = TRUE;
  
    if (h_ir_tst && !req_if_range)
      h_r->pos = 0;

    /* #13.3.3 says: don't trust weak for "complex" queries, ie. byteranges */
    if (h_inm->pos && (VEQ(hdrs, h_inm->pos, h_inm->len, "*") ||
                       httpd_match_etags(req, comb, h_inm->pos, h_inm->len,
                                         vs1, pos, len, !h_r->pos)))
      cached_output = TRUE; /* Note: should return 412 for POST/PUT */

    /* #14.24 says: must use strong comparison, and also...
       If the request would, without the If-Match header field, result in
       anything other than a 2xx or 412 status, then the If-Match header
       MUST be ignored. */
    if (!cached_output &&
        h_im->pos  && !(VEQ(hdrs, h_im->pos, h_im->len, "*") ||
                        httpd_match_etags(req, comb, h_im->pos, h_im->len,
                                          vs1, pos, len, FALSE)))
      return (FALSE);
  }
  else if (h_ir_tst && !req_if_range)
    h_r->pos = 0;
  
  if (cached_output)
  {
    req->head_op = TRUE;
    *http_ret_code = 304;
    *http_ret_line = "Not Modified";
  }
  else if (h_r->pos)
  {
    *http_ret_code = 206;
    *http_ret_line = "Partial content";
  }

  return (TRUE);
}

int http_req_1_x(struct Con *con, Httpd_req_data *req,
                 unsigned int *http_ret_code,
                 const char **http_ret_line)
{
  Vstr_base *out = con->evnt->io_w;
  Vstr_sect_node *h_r = req->http_hdrs->hdr_range;
  time_t mtime = -1;
  
  if (HTTPD_VER_GE_1_1(req) && req->http_hdrs->hdr_expect->len)
    /* I'm pretty sure we can ignore 100-continue, as no request will
     * have a body */
    HTTPD_ERR_RET(req, 417, FALSE);
          
  httpd_parse_sc_try_fd_encoding(con, req, req->f_stat, &req->f_stat_st_size,
                                 req->fname);
  
  if (req->policy->use_err_406 &&
      !req->content_encoding_identity &&
      !req->content_encoding_bzip2 && !req->content_encoding_gzip)
    HTTPD_ERR_MSG_RET(req, 406, "Encoding", FALSE);

  if (h_r->pos)
  {
    int ret_code = 0;

    if (!(req->policy->use_range &&
	  (HTTPD_VER_GE_1_1(req) || req->policy->use_range_1_0)))
      h_r->pos = 0;
    else if (!(ret_code = http_parse_range(con, req)))
      h_r->pos = 0;
    ASSERT(!ret_code || (ret_code == 200) || (ret_code == 416));
    if (ret_code == 416)
    {
      if (!req->http_hdrs->hdr_if_range->pos)
        HTTPD_ERR_RET(req, 416, FALSE);
      h_r->pos = 0;
    }
  }
  
  if (!http_response_ok(con, req, http_ret_code, http_ret_line))
    HTTPD_ERR_RET(req, 412, FALSE);

  if (!h_r->pos)
    httpd_serv_file_sects_none(con, req, req->f_stat_st_size);
  
  httpd_serv_call_file_init(con, req, http_ret_code, http_ret_line);

  ASSERT(con->fs && (con->fs_off < con->fs_num) && (con->fs_num <= con->fs_sz));
  ASSERT(!con->fs_off);

  mtime = req->f_stat->st_mtime;
  http_app_def_hdrs(con, req, *http_ret_code, *http_ret_line,
                    mtime, NULL, TRUE, http_serv_file_len(con, req));
  if (h_r->pos && !con->use_mpbr)
    http_app_hdr_fmt(out, "Content-Range", "%s %ju-%ju/%ju", "bytes",
                     con->fs->off, con->fs->off + (con->fs->len - 1),
                     (uintmax_t)req->f_stat_st_size);
  if (req->content_location_vs1)
    http_app_hdr_vstr_def(out, "Content-Location",
                          HTTP__XTRA_HDR_PARAMS(req, content_location));
  http_app_hdrs_url(con, req);
  http_app_hdrs_file(con, req);  
  
  http_app_end_hdrs(out);

  if (!req->head_op && h_r->pos && con->use_mpbr)
  {
    con->mpbr_fs_len = req->f_stat_st_size;
    http_app_hdrs_mpbr(con, con->fs);
  }
  
  return (TRUE);
}

static int httpd_req_add_vhost(struct Con *con, struct Httpd_req_data *req)
{
  Vstr_base *data = con->evnt->io_r;
  Vstr_base *fname = req->fname;
  Vstr_sect_node *h_h = req->http_hdrs->hdr_host;
  size_t h_h_pos = h_h->pos;
  size_t h_h_len = h_h->len;
  size_t orig_len = 0;
  size_t dots = 0;  
  
  /* a lot of clients will pass example.com. for example.com ... fix them
   * this can happen more than one time Eg. "wget www.and.org.." */
  if (h_h_len)
  {
    dots = vstr_spn_cstr_chrs_rev(data, h_h_pos, h_h_len, ".");
    if (dots == h_h_len)
      h_h_len = 1; /* give 400s to hostname "." */
    else
    {
      ASSERT(dots < h_h_len);
      
      h_h_len -= dots;
  
      if (req->policy->use_canonize_host)
      {
        if (VIPREFIX(data, h_h_pos, h_h_len, "www."))
        { h_h_len -= CLEN("www."); h_h_pos += CLEN("www."); }
      }
    }
    
    h_h->pos = h_h_pos;
    h_h->len = h_h_len;
  }
  
  if (!req->policy->use_vhosts_name)
    return (TRUE);

  orig_len = fname->len;
  if (!http_serv_add_vhost(con, req, fname, 0, TRUE))
    return (FALSE);

  vstr_add_cstr_ptr(fname, 0, "/");

  req->vhost_prefix_len = (fname->len - orig_len);

  return (TRUE);
}

/* Decode url-path,
   check url-path for a bunch of problems,
   if vhosts is on add vhost prefix,
   Note we don't do dir_filename additions yet */
int http_req_make_path(struct Con *con, Httpd_req_data *req)
{
  Vstr_base *data = con->evnt->io_r;
  Vstr_base *fname = req->fname;
  
  ASSERT(!fname->len);

  assert(VPREFIX(data, req->path_pos, req->path_len, "/") ||
         VEQ(data, req->path_pos, req->path_len, "*"));

  if (req->chk_encoded_slash &&
      vstr_srch_case_cstr_buf_fwd(data, req->path_pos, req->path_len, "%2f"))
    HTTPD_ERR_MSG_RET(req, 403, "Path has encoded /", FALSE);
  if (req->chk_encoded_dot &&
      vstr_srch_case_cstr_buf_fwd(data, req->path_pos, req->path_len, "%2e"))
    HTTPD_ERR_MSG_RET(req, 403, "Path has encoded .", FALSE);
  req->chked_encoded_path = TRUE;

  vstr_add_vstr(fname, 0,
                data, req->path_pos, req->path_len, VSTR_TYPE_ADD_BUF_PTR);
  vstr_conv_decode_uri(fname, 1, fname->len);

  if (fname->conf->malloc_bad) /* dealt with as errmem_req() later */
    return (TRUE);

  /* NOTE: need to split function here so we can more efficently alter the
   * path. */
  if (!httpd_req_add_vhost(con, req))
    return (FALSE);
  
  /* check posix path ... including hostname, for NIL and path escapes */
  if (vstr_srch_chr_fwd(fname, 1, fname->len, 0))
    HTTPD_ERR_MSG_RET(req, 403, "Path has NIL", FALSE);

  /* web servers don't have relative paths, so /./ and /../ aren't "special" */
  if (vstr_srch_cstr_buf_fwd(fname, 1, fname->len, "/../") ||
      VSUFFIX(req->fname, 1, req->fname->len, "/.."))
    HTTPD_ERR_MSG_RET(req, 403, "Path has /../", FALSE);
  if (req->policy->chk_dot_dir &&
      (vstr_srch_cstr_buf_fwd(fname, 1, fname->len, "/./") ||
       VSUFFIX(req->fname, 1, req->fname->len, "/.")))
    HTTPD_ERR_MSG_RET(req, 403, "Path has /./", FALSE);

  ASSERT(fname->len);
  assert(VPREFIX(fname, 1, fname->len, "/") ||
         VEQ(fname, 1, fname->len, "*") ||
         fname->conf->malloc_bad);

  if (fname->conf->malloc_bad)
    return (TRUE);
  
  return (TRUE);
}

size_t http_req_xtra_content(Httpd_req_data *req, const Vstr_base *s1,
                             size_t pos, size_t *len)
{
  Vstr_base *xs1 = req->xtra_content;
  size_t ret = 0;
  
  ASSERT(len);
  ASSERT((s1 == xs1) || !s1);
  ASSERT(s1 || !*len);
  
  if (!req->xtra_content && !(req->xtra_content = vstr_make_base(NULL)))
    return (0);
  xs1 = req->xtra_content;

  if (!s1 || !*len)
    return (xs1->len + 1);
  
  if (vstr_sc_poslast(pos, *len) == xs1->len)
    return (pos); /* we are last, so just overwrite */

  /* we aren't, so copy to last place */
  ret = xs1->len + 1;
  if (!vstr_add_vstr(xs1, xs1->len, s1, pos, *len, VSTR_TYPE_ADD_BUF_REF))
    return (0);

  return (ret);
}

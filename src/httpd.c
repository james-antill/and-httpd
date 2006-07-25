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
/* main HTTPD APIs, only really implements server portions */

#define EX_UTILS_NO_USE_INIT  1
#define EX_UTILS_NO_USE_EXIT  1
#define EX_UTILS_NO_USE_LIMIT 1
#define EX_UTILS_NO_USE_BLOCK 1
#define EX_UTILS_NO_USE_GET   1
#define EX_UTILS_NO_USE_PUT   1
#define EX_UTILS_RET_FAIL     1
#include "ex_utils.h"

#include "mk.h"

#include "vlg.h"

#define HTTPD_HAVE_GLOBAL_OPTS 1
#include "httpd.h"
#include "httpd_policy.h"

#ifndef POSIX_FADV_SEQUENTIAL
# define posix_fadvise64(x1, x2, x3, x4) (errno = ENOSYS, -1)
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

#include <syslog.h>

HTTPD_CONF_MAIN_DECL_OPTS(httpd_opts);

static Vlg *vlg = NULL;


void httpd_init(Vlg *passed_vlg)
{
  ASSERT(passed_vlg && !vlg);
  vlg = passed_vlg;
  httpd_app_init(vlg);
  httpd_parse_init(vlg);
  httpd_req_init(vlg);
}

void httpd_exit(void)
{
  ASSERT(vlg);
  vlg = NULL;
  httpd_parse_exit();
  httpd_req_exit();
  httpd_app_exit();
}

/* prints out headers in human friedly way for log files */
#define PCUR (pos + (base->len - orig_len))
static int http_app_vstr_escape(Vstr_base *base, size_t pos,
                                Vstr_base *sf, size_t sf_pos, size_t sf_len)
{
  unsigned int sf_flags = VSTR_TYPE_ADD_BUF_PTR;
  Vstr_iter iter[1];
  size_t orig_len = base->len;
  int saved_malloc_bad = FALSE;
  size_t norm_chr = 0;

  if (!sf_len) /* hack around !sf_pos */
    return (TRUE);
  
  if (!vstr_iter_fwd_beg(sf, sf_pos, sf_len, iter))
    return (FALSE);

  saved_malloc_bad = base->conf->malloc_bad;
  base->conf->malloc_bad = FALSE;
  while (sf_len)
  { /* assumes ASCII */
    char scan = vstr_iter_fwd_chr(iter, NULL);

    if ((scan >= ' ') && (scan <= '~') && (scan != '"') && (scan != '\\'))
      ++norm_chr;
    else
    {
      vstr_add_vstr(base, PCUR, sf, sf_pos, norm_chr, sf_flags);
      sf_pos += norm_chr;
      norm_chr = 0;
      
      if (0) {}
      else if (scan == '"')  vstr_add_cstr_buf(base, PCUR, "\\\"");
      else if (scan == '\\') vstr_add_cstr_buf(base, PCUR, "\\\\");
      else if (scan == '\t') vstr_add_cstr_buf(base, PCUR, "\\t");
      else if (scan == '\v') vstr_add_cstr_buf(base, PCUR, "\\v");
      else if (scan == '\r') vstr_add_cstr_buf(base, PCUR, "\\r");
      else if (scan == '\n') vstr_add_cstr_buf(base, PCUR, "\\n");
      else if (scan == '\b') vstr_add_cstr_buf(base, PCUR, "\\b");
      else
        vstr_add_sysfmt(base, PCUR, "\\x%02hhx", scan);
      ++sf_pos;
    }
    
    --sf_len;
  }

  vstr_add_vstr(base, PCUR, sf, sf_pos, norm_chr, sf_flags);
  
  if (base->conf->malloc_bad)
    return (FALSE);
  
  base->conf->malloc_bad = saved_malloc_bad;
  return (TRUE);
}
#undef PCUR

static int http__fmt__add_vstr_add_vstr(Vstr_base *base, size_t pos,
                                        Vstr_fmt_spec *spec)
{
  Vstr_base *sf = VSTR_FMT_CB_ARG_PTR(spec, 0);
  size_t sf_pos = VSTR_FMT_CB_ARG_VAL(spec, size_t, 1);
  size_t sf_len = VSTR_FMT_CB_ARG_VAL(spec, size_t, 2);
  
  return (http_app_vstr_escape(base, pos, sf, sf_pos, sf_len));
}
int http_fmt_add_vstr_add_vstr(Vstr_conf *conf, const char *name)
{
  return (vstr_fmt_add(conf, name, http__fmt__add_vstr_add_vstr,
                       VSTR_TYPE_FMT_PTR_VOID,
                       VSTR_TYPE_FMT_SIZE_T,
                       VSTR_TYPE_FMT_SIZE_T,
                       VSTR_TYPE_FMT_END));
}
static int http__fmt__add_vstr_add_sect_vstr(Vstr_base *base, size_t pos,
                                             Vstr_fmt_spec *spec)
{
  Vstr_base *sf     = VSTR_FMT_CB_ARG_PTR(spec, 0);
  Vstr_sects *sects = VSTR_FMT_CB_ARG_PTR(spec, 1);
  unsigned int num  = VSTR_FMT_CB_ARG_VAL(spec, unsigned int, 2);
  size_t sf_pos     = VSTR_SECTS_NUM(sects, num)->pos;
  size_t sf_len     = VSTR_SECTS_NUM(sects, num)->len;
  
  return (http_app_vstr_escape(base, pos, sf, sf_pos, sf_len));
}
int http_fmt_add_vstr_add_sect_vstr(Vstr_conf *conf, const char *name)
{
  return (vstr_fmt_add(conf, name, http__fmt__add_vstr_add_sect_vstr,
                       VSTR_TYPE_FMT_PTR_VOID,
                       VSTR_TYPE_FMT_PTR_VOID,
                       VSTR_TYPE_FMT_UINT,
                       VSTR_TYPE_FMT_END));
}

static void http_vlg_def(struct Con *con, struct Httpd_req_data *req, int meth)
{
  Vstr_base *data = con->evnt->io_r;
  Vstr_sect_node *h_h  = req->http_hdrs->hdr_host;
  Vstr_sect_node *h_ua = req->http_hdrs->hdr_ua;
  Vstr_sect_node *h_r  = req->http_hdrs->hdr_referer;

  vlg_info(vlg, (" host[\"$<http-esc.vstr:%p%zu%zu>\"]"
                 " UA[\"$<http-esc.vstr:%p%zu%zu>\"]"
                 " ref[\"$<http-esc.vstr:%p%zu%zu>\"]"),
           data, h_h->pos, h_h->len,    
           data, h_ua->pos, h_ua->len,
           data, h_r->pos, h_r->len);

  if (meth && (req->sects->num >= 1))
    vlg_info(vlg, " meth[\"$<http-esc.vstr.sect:%p%p%u>\"]",
             data, req->sects, 1U);

  if (req->ver_0_9)
    vlg_info(vlg, " ver[\"HTTP/0.9\"]");
  else
  {
    ASSERT(req->sects->num >= 3);
    vlg_info(vlg, " ver[\"$<vstr.sect:%p%p%u>\"]", data, req->sects, 3);
  }

  vlg_info(vlg, ": $<http-esc.vstr:%p%zu%zu>\n",
           data, req->path_pos, req->path_len);
}

static struct File_sect *httpd__fd_next(struct Con *con)
{
  struct File_sect *fs = NULL;
  
  ASSERT(con->fs &&
         (con->fs_off <= con->fs_num) && (con->fs_num <= con->fs_sz));
  
  if (++con->fs_off >= con->fs_num)
  {
    fs = &con->fs[con->fs_off - 1];
    fs->len = 0;
    if (fs->fd != -1)
      close(fs->fd);
    fs->fd = -1;

    fs = con->fs;
    fs->fd = -1;
    fs->len = 0;
    
    con->fs_off = 0;
    con->fs_num = 0;

    con->use_mpbr = FALSE;
    ASSERT(!(con->mpbr_fs_len = 0));
  
    if (con->mpbr_ct)
      vstr_del(con->mpbr_ct, 1, con->mpbr_ct->len);

    return (NULL);
  }

  /* only allow multipart/byterange atm. where all fd's are the same */
  ASSERT(con->fs[con->fs_off - 1].fd == con->fs[con->fs_off].fd);
  
  fs = &con->fs[con->fs_off];
  if (con->use_posix_fadvise)
    posix_fadvise64(fs->fd, fs->off, fs->len, POSIX_FADV_SEQUENTIAL);
  
  return (fs);
}

void httpd_fin_fd_close(struct Con *con)
{
  con->use_posix_fadvise = FALSE;
  while (httpd__fd_next(con))
  { /* do nothing */ }
}

static int http_fin_req(struct Con *con, Httpd_req_data *req)
{
  Vstr_base *out = con->evnt->io_w;
  
  ASSERT(!out->conf->malloc_bad);
  http_parse_clear_hdrs(req);

  /* Note: Not resetting con->parsed_method_ver_1_0,
   * if it's non-0.9 now it should continue to be */
  
  if (!con->keep_alive) /* all input is here */
  {
    evnt_wait_cntl_del(con->evnt, POLLIN);
    req->len = con->evnt->io_r->len; /* delete it all */
  }
  
  vstr_del(con->evnt->io_r, 1, req->len);
  
  evnt_put_pkt(con->evnt);

  if (req->policy->use_tcp_cork)
    evnt_fd_set_cork(con->evnt, TRUE);

  http_req_free(req);

  return (httpd_serv_send(con));
}

static int http_fin_fd_req(struct Con *con, Httpd_req_data *req)
{
  ASSERT(con->fs && (con->fs_off < con->fs_num) && (con->fs_num <= con->fs_sz));
  ASSERT(!con->fs_off);
  
  if (req->head_op || con->use_mmap || !con->fs->len)
    httpd_fin_fd_close(con);
  else if ((con->use_posix_fadvise = req->policy->use_posix_fadvise))
  {
    struct File_sect *fs = con->fs;
    posix_fadvise64(fs->fd, fs->off, fs->len, POSIX_FADV_SEQUENTIAL);
  }
  
  return (http_fin_req(con, req));
}

static int http_con_cleanup(struct Con *con, Httpd_req_data *req)
{
  con->evnt->io_r->conf->malloc_bad = FALSE;
  con->evnt->io_w->conf->malloc_bad = FALSE;
  
  http_parse_clear_hdrs(req);
  http_req_free(req);
    
  return (FALSE);
}

static int http_con_close_cleanup(struct Con *con, Httpd_req_data *req)
{
  httpd_fin_fd_close(con);
  return (http_con_cleanup(con, req));
}

static void httpd__disable_sendfile(void)
{
  Opt_serv_policy_opts *scan = httpd_opts->s->def_policy;
  
  while (scan)
  {
    Httpd_policy_opts *tmp = (Httpd_policy_opts *)scan;
    tmp->use_sendfile = FALSE;
    scan = scan->next;
  }
}

static void httpd__disable_mmap(void)
{
  Opt_serv_policy_opts *scan = httpd_opts->s->def_policy;
  
  while (scan)
  {
    Httpd_policy_opts *tmp = (Httpd_policy_opts *)scan;
    tmp->use_mmap = FALSE;
    scan = scan->next;
  }
}

static void httpd_serv_call_mmap(struct Con *con, struct Httpd_req_data *req,
                                 struct File_sect *fs)
{
  static long pagesz = 0;
  Vstr_base *data = con->evnt->io_r;
  uintmax_t mmoff = fs->off;
  uintmax_t mmlen = fs->len;
  
  ASSERT(!req->f_mmap || !req->f_mmap->len);
  ASSERT(!con->use_mmap);
  ASSERT(!req->head_op);

  if (con->use_sendfile)
    return;

  if (con->fs_num > 1)
    return;
  
  if (!pagesz)
    pagesz = sysconf(_SC_PAGESIZE);
  if (pagesz == -1)
    httpd__disable_mmap();

  if (!req->policy->use_mmap ||
      (mmlen < HTTP_CONF_MMAP_LIMIT_MIN) || (mmlen > HTTP_CONF_MMAP_LIMIT_MAX))
    return;
  
  /* mmap offset needs to be aligned - so tweak offset before and after */
  mmoff /= pagesz;
  mmoff *= pagesz;
  ASSERT(mmoff <= fs->off);
  mmlen += fs->off - mmoff;

  if (!req->f_mmap && !(req->f_mmap = vstr_make_base(data->conf)))
    VLG_WARN_RET_VOID((vlg, /* fall back to read */
                       "failed to allocate mmap Vstr.\n"));
  ASSERT(!req->f_mmap->len);
  
  if (!vstr_sc_mmap_fd(req->f_mmap, 0, fs->fd, mmoff, mmlen, NULL))
  {
    if (errno == ENOSYS) /* also logs it */
      httpd__disable_mmap();

    VLG_WARN_RET_VOID((vlg, /* fall back to read */
                       "mmap($<http-esc.vstr:%p%zu%zu>,"
                       "(%ju,%ju)->(%ju,%ju)): %m\n",
                       req->fname, (size_t)1, req->fname->len,
                       fs->off, fs->len, mmoff, mmlen));
  }
  
  con->use_mmap = TRUE;  
  vstr_del(req->f_mmap, 1, fs->off - mmoff); /* remove alignment */
    
  ASSERT(req->f_mmap->len == fs->len);
}

static int httpd_serv_call_seek(struct Con *con, struct File_sect *fs)
{
  if (con->use_mmap || con->use_sendfile)
    return (TRUE);

  if (fs->off && fs->len && (lseek64(fs->fd, fs->off, SEEK_SET) == -1))
    return (FALSE);
  
  return (TRUE);
}

static void httpd__serv_call_seek(struct Con *con, struct Httpd_req_data *req,
                                  struct File_sect *fs,
                                  unsigned int *http_ret_code,
                                  const char ** http_ret_line)
{
  ASSERT(!req->head_op);

  if (!httpd_serv_call_seek(con, fs))
  { /* this should be impossible for normal files AFAIK */
    vlg_warn(vlg, "lseek($<http-esc.vstr:%p%zu%zu>,off=%ju): %m\n",
             req->fname, (size_t)1, req->fname->len, fs->off);
    /* opts->use_range - turn off? */
    req->http_hdrs->hdr_range->pos = 0;
    *http_ret_code = 200;
    *http_ret_line = "OK - Range Failed";
  }
}

static int http__conf_req(struct Con *con, Httpd_req_data *req, size_t del_len)
{
  Conf_parse *conf = NULL;
  
  if (!(conf = conf_parse_make(NULL)))
    return (FALSE);
  
  if (!httpd_conf_req_parse_file(conf, con, req, del_len))
  {
    Vstr_base *s1 = req->policy->s->policy_name;
    Vstr_base *s2 = conf->tmp;

    if (!req->user_return_error_code)
      vlg_info(vlg, "CONF-REQ-ERR from[$<sa:%p>]: policy $<vstr.all:%p>"
               " backtrace: $<vstr.all:%p>\n", CON_CEVNT_SA(con), s1, s2);
    conf_parse_free(conf);
    return (TRUE);
  }
  conf_parse_free(conf);
  
  if (req->direct_uri)
  {
    Vstr_base *s1 = req->policy->s->policy_name;
    vlg_info(vlg, "CONF-REQ-ERR from[$<sa:%p>]: policy $<vstr.all:%p>"
             " Has URI.\n", CON_CEVNT_SA(con), s1);
    HTTPD_ERR_MSG_RET(req, 503, "Has URI", TRUE);
  }
  
  return (TRUE);
}

static void http_prepend_doc_root(Vstr_base *fname, Httpd_req_data *req)
{
  Vstr_base *dir = req->policy->document_root;
  
  ASSERT((dir->len   >= 1) && vstr_cmp_cstr_eq(dir,   dir->len, 1, "/"));
  ASSERT((fname->len >= 1) && vstr_cmp_cstr_eq(fname,        1, 1, "/"));
  vstr_add_vstr(fname, 0, dir, 1, dir->len - 1, VSTR_TYPE_ADD_BUF_REF);
}

/* characters valid in a hostname -- these are also safe unencoded in a URL */
#define HTTPD__VALID_CSTR_CHRS_HOSTNAME     \
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"            \
    "abcdefghijklmnopqrstuvwxyz"            \
    "0123456789"                            \
    ".-_"
/* characters that are valid in a part of a URL _and_ in a file basename ...
 * without encoding */
#define HTTPD__VALID_CSTR_CHRS_URL_FILENAME \
    "!$,:=~" HTTPD__VALID_CSTR_CHRS_HOSTNAME

int httpd_valid_url_filename(Vstr_base *s1, size_t pos, size_t len)
{
  static const char cstr[] = HTTPD__VALID_CSTR_CHRS_URL_FILENAME;
  return (vstr_spn_cstr_chrs_fwd(s1, pos, len, cstr) == len);
}

static unsigned short
httpd__valid_hostname(Vstr_base *s1, size_t pos, size_t len, int allow_port)
{
  static const char cstr[] = HTTPD__VALID_CSTR_CHRS_HOSTNAME;
  size_t tmp = 0;
  
   /* this is also checked via /./ path checking */
  if (vstr_cmp_cstr_eq(s1, pos, len, "."))
    return (0);
  
  if (vstr_srch_cstr_buf_fwd(s1, pos, len, ".."))
    return (0); /* example..com */

  if (VPREFIX(s1, pos, len, ".")) return (0); /* .example.com  */

  /* this is always removed in httpd_req_add_vhost */
  assert(!VSUFFIX(s1, pos, len, "."));        /*  example.com. */
  
  tmp = vstr_spn_cstr_chrs_fwd(s1, pos, len, cstr);
  if (tmp == len)
    return (80);

  if (!allow_port)
    return (0);
  
  len -= tmp; pos += tmp;
  if (vstr_export_chr(s1, pos) == ':') /* here both before and after port rm */
    return (httpd_parse_host_port(s1, pos, len));
  
  return (0);
}

static int httpd__chk_vhost(const Httpd_policy_opts *popts,
                            Vstr_base *lfn, size_t pos, size_t len)
{
  const char *vhost = NULL;
  struct stat64 v_stat[1];
  const Vstr_base *def_hname = popts->default_hostname;
  int ret = -1;
  
  ASSERT(pos);

  if (popts->use_internal_host_chk)
  {
    if (!httpd__valid_hostname(lfn, pos, len, TRUE))
      return (FALSE);
  }
  
  if (!popts->use_host_chk)
    return (TRUE);
  
  if (vstr_cmp_eq(lfn, pos, len, def_hname, 1, def_hname->len))
    return (TRUE); /* don't do lots of work for nothing */

  vstr_add_vstr(lfn, pos - 1, 
		popts->document_root, 1, popts->document_root->len,
                VSTR_TYPE_ADD_BUF_PTR);
  len += popts->document_root->len;
  
  if (lfn->conf->malloc_bad || !(vhost = vstr_export_cstr_ptr(lfn, pos, len)))
    return (TRUE); /* dealt with as errmem_req() later */
  
  ret = stat64(vhost, v_stat);
  vstr_del(lfn, pos, popts->document_root->len);

  if (ret == -1)
    return (FALSE);

  if (!S_ISDIR(v_stat->st_mode))
    return (FALSE);
  
  return (TRUE);
}

int http_serv_add_vhost(struct Con *con, Httpd_req_data *req,
                        Vstr_base *s1, size_t pos, int chk)
{
  size_t tmp = s1->len;
  
  httpd_sc_add_hostname(con, req, s1, pos);
  
  if (!req->http_hdrs->hdr_host->len)
    return (TRUE); /* don't bother checking valid vhost for default */

  tmp = s1->len - tmp; /* length of added data */
  if (chk && !s1->conf->malloc_bad &&
      !httpd__chk_vhost(req->policy, s1, pos + 1, tmp))
  {
    if (req->policy->use_host_err_400) /* rfc2616 5.2 */
      HTTPD_ERR_MSG_RET(req, 400, "Hostname not local", FALSE);
    else
    { /* what everything else does ... *sigh* */
      if (s1->conf->malloc_bad)
        return (TRUE);
      
      req->http_hdrs->hdr_host->len = 0;
      vstr_del(s1, pos + 1, tmp);
      httpd_sc_add_default_hostname(con, req, s1, pos);
    }
  }

  return (TRUE);
}

static void http_app_err_file(struct Con *con, Httpd_req_data *req,
                              Vstr_base *fname, size_t *vhost_prefix_len)
{
  Vstr_base *dir = NULL;
  size_t orig_len = 0;

  ASSERT(con && req && fname);
  ASSERT(vhost_prefix_len && !*vhost_prefix_len);

  orig_len = fname->len;
  dir = req->policy->req_err_dir;
  ASSERT((dir->len   >= 1) && vstr_cmp_cstr_eq(dir,   dir->len, 1, "/"));
  HTTPD_APP_REF_ALLVSTR(fname, dir);
  
  if (req->policy->use_vhosts_name)
  {
    http_serv_add_vhost(con, req, fname, fname->len, FALSE);
    vstr_add_cstr_ptr(fname, fname->len, "/");
  }
  
  /* FIXME: This kind of looks like a hack, we tell the rest of the code that
   * the err req dir and any vhost info. is all part of the
   * "non-path prefix" basically so = does the right thing with limits.
   * Ie. path-eq 404 ... vhost_prefix_len should probably be called
   * something else. */
  *vhost_prefix_len = (fname->len - orig_len);
  
  vstr_add_fmt(fname, fname->len, "%u.html", req->error_code);
}

uintmax_t http_serv_file_len(struct Con *con, Httpd_req_data *req)
{
#ifndef NDEBUG
  uintmax_t len = 0;
  unsigned int num = con->fs_num;

  while (num > 0)
    len += con->fs[--num].len;

  ASSERT(len == req->fs_len);
#endif

  return (req->fs_len);
}

static void http__err_vlg_msg(struct Con *con, Httpd_req_data *req)
{
  uintmax_t tmp = 0;

  if (!req->head_op)
    tmp = req->error_len;
  
  vlg_info(vlg, "ERREQ from[$<sa:%p>] err[%03u %s%s%s] sz[${BKMG.ju:%ju}:%ju]",
           CON_CEVNT_SA(con), req->error_code, req->error_line,
           *req->error_xmsg ? " | " : "", req->error_xmsg, tmp, tmp);
  if ((req->sects->num >= 2) && (req->ver_0_9 || (req->sects->num >= 3)))
    http_vlg_def(con, req, TRUE);
  else
    vlg_info(vlg, "%s", "\n");
}

void httpd_serv_call_file_init(struct Con *con, Httpd_req_data *req,
                               unsigned int *http_ret_code,
                               const char ** http_ret_line)
{
  ASSERT(req);
  
  con->use_mmap = FALSE;
  if (!req->head_op)
  {
    httpd_serv_call_mmap(con, req, con->fs);
    httpd__serv_call_seek(con, req, con->fs, http_ret_code, http_ret_line);
  }
}

void httpd_serv_file_sects_none(struct Con *con, Httpd_req_data *req,
                                struct stat64 *f_stat)
{
  con->use_mpbr = FALSE;
  con->fs_num   = 1;
  con->fs->off  = 0;
  con->fs->len  = f_stat->st_size;
  req->fs_len   = f_stat->st_size;
}
                                      
/* if the attacker gives a user a URL like:
   http://example.com/">x</a><script>...</script>
 * and we're redirecting everything for example.com to www.example.com
 * that'll get output, with html redirects, as:
 <a href="http://example.com/">x</a><script>...</script>">here</a>
 * ...browsers probably can't be relied upon to not do the stupid thing so
 * we escape ' " < > ... ' is just because. None of them mean anything special
 * in URLs so we should be fine */
static unsigned int http__safe_html_url(Vstr_base *loc)
{
  static const char unsafe[] = "'\"<>"; /* include " " for configs? */
  size_t pos = 1;
  size_t len = loc->len;
  size_t chrs = 0;
  unsigned int ret = 0;
  
  ASSERT(loc->len);
  
  while ((chrs = vstr_cspn_cstr_chrs_fwd(loc, pos, len, unsafe)) != len)
  {
    const char *safe = "...";
    
    ++ret;
    
    pos += chrs;
    switch (vstr_export_chr(loc, pos))
    {
      case ' ':  safe = "%20"; break; /* NOTE: not included above */
      case '"':  safe = "%22"; break;
      case '\'': safe = "%27"; break;
      case '<':  safe = "%3c"; break;
      case '>':  safe = "%3e";
        ASSERT_NO_SWITCH_DEF();
    }

    ASSERT(strlen(safe) == 3);
    if (!vstr_sub_buf(loc, pos, 1, safe, 3))
      return (0);

    if (pos == len)
      break;

    pos += 3;
    len = vstr_sc_posdiff(pos, loc->len);
  }
  
  ASSERT(vstr_cspn_cstr_chrs_fwd(loc, 1, loc->len, unsafe) == loc->len);

  return (ret);
}

int http_fin_err_req(struct Con *con, Httpd_req_data *req)
{
  Vstr_base *out = con->evnt->io_w;
  int cust_err_msg = FALSE;
  int deleted_req_data = FALSE;

  ASSERT(req->error_code);

  ASSERT(!con->use_mpbr); /* done as part of close() */
  ASSERT(con->fs && !con->fs_num);

  req->content_encoding_gzip  = FALSE;
  req->content_encoding_bzip2 = FALSE;
  req->content_encoding_xgzip = FALSE;

  /* These are done before keep-alive parsing is done */
  ASSERT((req->error_code != 411) || (con->keep_alive == HTTP_NON_KEEP_ALIVE));
  ASSERT((req->error_code != 413) || (con->keep_alive == HTTP_NON_KEEP_ALIVE));
  
  if ((req->error_code == 400) || (req->error_code == 405) ||
      (req->error_code == 411) || (req->error_code == 413) ||
      (req->error_code == 500) || (req->error_code == 501))
    con->keep_alive = HTTP_NON_KEEP_ALIVE;
  
  if (req->malloc_bad)
  { /* delete all input to give more room */
    ASSERT(req->error_code == 500);
    http__err_vlg_msg(con, req);
    vstr_del(con->evnt->io_r, 1, con->evnt->io_r->len);
    deleted_req_data = TRUE;
  }
  else if (!HTTPD_ERR_REDIR(req->error_code) && /* don't do as href is passed */
           req->policy->req_err_dir->len)
  { /* custom err message */
    Vstr_base *fname = NULL;
    size_t vhost_prefix_len = 0;
    const char *fname_cstr = NULL;
    struct stat64 f_stat[1];
    int open_flags = O_NONBLOCK;

    if (HTTPD_ERR_MATCH_RESP(req->error_code))
    {
      req->req_user_return_error_code = req->user_return_error_code;
      req->user_return_error_code     = FALSE;    
      req->req_error_code             = req->error_code;
      req->error_code                 = 0;
      req->req_error_xmsg             = req->error_xmsg;
      req->error_xmsg                 = "";
    
      if (!httpd_policy_response(con, req,
                                 httpd_opts->conf, httpd_opts->match_response))
      {
        Vstr_base *s1 = httpd_opts->conf->tmp;
        if (!req->user_return_error_code)
          vlg_info(vlg, "CONF-MATCH-RESP-ERR from[$<sa:%p>]:"
                   " backtrace: $<vstr.all:%p>\n", CON_CEVNT_SA(con), s1);
        /* fall through */
      }
      else
      {
        ASSERT(!req->user_return_error_code);
        ASSERT(!req->error_code);
        ASSERT(!*req->error_xmsg);
        req->user_return_error_code = req->req_user_return_error_code;
        req->error_code             = req->req_error_code;
        req->error_xmsg             = req->req_error_xmsg;
        
        if (con->evnt->flag_q_closed)
        {
          Vstr_base *s1 = req->policy->s->policy_name;
          
          vlg_info(vlg, "BLOCKED from[$<sa:%p>]: policy $<vstr.all:%p>\n",
                   CON_CEVNT_SA(con), s1);
          return (http_con_cleanup(con, req));
        }
        
        if (req->direct_uri)
        {
          Vstr_base *s1 = req->policy->s->policy_name;
          vlg_info(vlg, "CONF-MATCH-RESP-ERR from[$<sa:%p>]: "
                   "policy $<vstr.all:%p> Has URI.\n", CON_CEVNT_SA(con), s1);
          HTTPD_ERR_MSG_RET(req, 503, "Has URI", TRUE);
        }
      }
    
      if (!HTTPD_ERR_MATCH_RESP(req->error_code))
        return (http_fin_err_req(con, req)); /* don't loop, just fall through */
    }
    
    if (!(fname = vstr_make_base(req->fname->conf)))
      goto fail_custom_err;

    /* NOTE that vary_* is the union of both the req and the resp. processing */
    
    if (!req->user_return_error_code)
    {
      req->cache_control_vs1 = NULL;
      req->expires_vs1       = NULL;
      req->p3p_vs1           = NULL;
    }

    if (req->user_return_error_code && req->direct_filename)
    {
      HTTPD_APP_REF_ALLVSTR(fname, req->fname);
      if (!req->skip_document_root)
        http_prepend_doc_root(fname, req);
    }
    else
    {
      int conf_ret = FALSE;
      unsigned int code = req->error_code;
      unsigned int ncode = 0;
      const char *xmsg = req->error_xmsg;
      
      http_app_err_file(con, req, fname, &vhost_prefix_len);

      req->content_type_vs1 = NULL;
      req->error_code = 0;
      req->skip_document_root = FALSE;
      req->direct_uri = FALSE;
      req->neg_content_type_done = FALSE;
      req->neg_content_lang_done = FALSE;
      
      SWAP_TYPE(fname, req->fname, Vstr_base *);
      SWAP_TYPE(vhost_prefix_len, req->vhost_prefix_len, size_t);
      
      req->conf_flags = HTTPD_CONF_REQ_FLAGS_PARSE_FILE_UERR;
      conf_ret = http__conf_req(con, req, CLEN(".html"));
      
      SWAP_TYPE(fname, req->fname, Vstr_base *);
      SWAP_TYPE(vhost_prefix_len, req->vhost_prefix_len, size_t);

      ncode = req->error_code;
      switch (code)
      { /* restore default error info. in case of failure */
        case 400: HTTPD_ERR(req, 400); break;
        case 401: HTTPD_ERR(req, 401); break;
        case 403: HTTPD_ERR(req, 403); break;
        case 404: HTTPD_ERR(req, 404); break;
        case 405: HTTPD_ERR(req, 405); break;
        case 406: HTTPD_ERR(req, 406); break;
        case 410: HTTPD_ERR(req, 410); break;
        case 411: HTTPD_ERR(req, 411); break;
        case 412: HTTPD_ERR(req, 412); break;
        case 413: HTTPD_ERR(req, 413); break;
        case 414: HTTPD_ERR(req, 414); break;
        case 415: HTTPD_ERR(req, 415); break;
        case 416: HTTPD_ERR(req, 416); break;
        case 417: HTTPD_ERR(req, 417); break;
        case 500: HTTPD_ERR(req, 500); break;
        case 501: HTTPD_ERR(req, 501); break;
        case 503: HTTPD_ERR(req, 503); break;
        case 505: HTTPD_ERR(req, 505);
          ASSERT_NO_SWITCH_DEF();
      }
      req->error_xmsg = xmsg; /* restore xmsg too */

      if (!conf_ret)
        goto fail_custom_err;
      if (ncode)
        goto fail_custom_err; /* don't allow remapping errors -- loops */
    }
    fname_cstr = vstr_export_cstr_ptr(fname, 1, fname->len);
    
    if (fname->conf->malloc_bad)
      goto fail_custom_err;

    if (req->policy->use_noatime)
      open_flags |= O_NOATIME;
    
    ASSERT(con->fs && (con->fs->fd == -1));
    if ((con->fs->fd = io__open(fname_cstr, open_flags)) == -1)
      goto fail_custom_err;

    if (fstat64(con->fs->fd, f_stat) == -1)
      goto fail_custom_err;
    if (req->policy->use_public_only && !(f_stat->st_mode & S_IROTH))
      goto fail_custom_err;
    if (!S_ISREG(f_stat->st_mode))
      goto fail_custom_err;

    con->fs_off  = 0;
    con->fs_num  = 0;
    con->fs->len = f_stat->st_size;
    req->fs_len  = 0;
    
    if (!req->ver_0_9)
      httpd_parse_sc_try_fd_encoding(con, req, f_stat, fname);

    /* FIXME: gzipped error documents weren't tested for */
    httpd_serv_file_sects_none(con, req, f_stat);
    
    con->use_mmap = FALSE;
    
    if (!req->head_op)
      httpd_serv_call_mmap(con, req, con->fs);

    req->error_len = http_serv_file_len(con, req);
    cust_err_msg = TRUE;
    
   fail_custom_err:
    if (!cust_err_msg)
      httpd_fin_fd_close(con);
    fname->conf->malloc_bad = FALSE;
    vstr_free_base(fname);
  }

  if (!cust_err_msg)
    req->content_type_vs1 = NULL;

  /* HEAD op might seem normal, but again HTTP asks that GET and HEAD
     produce identical headers */
  if (!req->policy->use_text_plain_redirect)
    switch (req->error_code)
    { /* make sure browsers don't allow XSS */
      case 301:
      {
        unsigned int repl = http__safe_html_url(req->fname);
        
        ASSERT((req->error_len + (repl * 2)) == CONF_MSG_LEN_301(req->fname));
          
        req->error_len = CONF_MSG_LEN_301(req->fname);
      }
      break;
      
      case 302:
      {
        unsigned int repl = http__safe_html_url(req->fname);
        
        ASSERT((req->error_len + (repl * 2)) == CONF_MSG_LEN_302(req->fname));
          
        req->error_len = CONF_MSG_LEN_302(req->fname);
      }
      break;
      
      case 303:
      {
        unsigned int repl = http__safe_html_url(req->fname);
        
        ASSERT((req->error_len + (repl * 2)) == CONF_MSG_LEN_303(req->fname));
          
        req->error_len = CONF_MSG_LEN_303(req->fname);
      }
      break;
      
      case 307:
      {
        unsigned int repl = http__safe_html_url(req->fname);
        
        ASSERT((req->error_len + (repl * 2)) == CONF_MSG_LEN_307(req->fname));
          
        req->error_len = CONF_MSG_LEN_307(req->fname);
      }
      break;      
    }

  if (!req->ver_0_9)
  { /* use_range is dealt with inside */
    const char *content_type = "text/html";
    
    switch (req->error_code)
    {
      case 301: case 302: case 303: case 307:
        if (req->policy->use_text_plain_redirect)
          content_type = "text/plain";
        else /* make sure browsers don't allow XSS */
          http__safe_html_url(req->fname);
    }

    http_app_def_hdrs(con, req, req->error_code, req->error_line,
                      httpd_opts->beg_time, content_type, TRUE, req->error_len);
    
    if (req->error_code == 416)
      http_app_hdr_fmt(out, "Content-Range", "%s */%ju", "bytes",
                          (uintmax_t)req->f_stat->st_size);

    if (req->error_code == 401)
      http_app_hdr_fmt(out, "WWW-Authenticate",
                       "Basic realm=\"$<vstr.all:%p>\"",
                       req->policy->auth_realm);
    
    if ((req->error_code == 405) || (req->error_code == 501))
      HTTP_APP_HDR_CONST_CSTR(out, "Allow", "GET, HEAD, OPTIONS, TRACE");
    
    switch (req->error_code)
    {
      case 301: case 302: case 303: case 307:
      { /* make sure we haven't screwed up and allowed response splitting */
        Vstr_base *loc = req->fname;
        
        http_app_hdr_vstr(out, "Location",
                          loc, 1, loc->len, VSTR_TYPE_ADD_ALL_BUF);
      }
    }
    
    if (req->user_return_error_code || cust_err_msg)
      http_app_hdrs_url(con, req);
    if (cust_err_msg)
      http_app_hdrs_file(con, req);
    
    http_app_end_hdrs(out);
  }

  if (!deleted_req_data)
    http__err_vlg_msg(con, req);
  
  if (cust_err_msg)
  {
    if (con->use_mmap && !vstr_mov(con->evnt->io_w, con->evnt->io_w->len,
                                   req->f_mmap, 1, req->f_mmap->len))
      return (http_con_close_cleanup(con, req));
    
    vlg_dbg3(vlg, "ERROR CUSTOM-ERR REPLY:\n$<vstr.all:%p>\n", out);
    
    if (out->conf->malloc_bad)
      return (http_con_close_cleanup(con, req));
    
    return (http_fin_fd_req(con, req));
  }
  
  if (!req->head_op)
  { /* default internal error message */
    Vstr_base *loc = req->fname;

    switch (req->error_code)
    {
      case 301:
        if (!req->policy->use_text_plain_redirect)
        {
          ASSERT(req->error_len == CONF_MSG_LEN_301(loc));
          vstr_add_fmt(out, out->len, CONF_MSG_FMT_301,
                       CONF_MSG__FMT_301_BEG,
                       loc, (size_t)1, loc->len, VSTR_TYPE_ADD_ALL_BUF,
                       CONF_MSG__FMT_30x_END);
          break;
        }
      case 302:
        if (!req->policy->use_text_plain_redirect)
        {
          ASSERT(req->error_len == CONF_MSG_LEN_302(loc));
          vstr_add_fmt(out, out->len, CONF_MSG_FMT_302,
                       CONF_MSG__FMT_302_BEG,
                       loc, (size_t)1, loc->len, VSTR_TYPE_ADD_ALL_BUF,
                       CONF_MSG__FMT_30x_END);
          break;
        }
      case 303:
        if (!req->policy->use_text_plain_redirect)
        {
          ASSERT(req->error_len == CONF_MSG_LEN_303(loc));
          vstr_add_fmt(out, out->len, CONF_MSG_FMT_303,
                       CONF_MSG__FMT_303_BEG,
                       loc, (size_t)1, loc->len, VSTR_TYPE_ADD_ALL_BUF,
                       CONF_MSG__FMT_30x_END);
          break;
        }
      case 307:
        if (!req->policy->use_text_plain_redirect)
        {
          ASSERT(req->error_len == CONF_MSG_LEN_307(loc));
          vstr_add_fmt(out, out->len, CONF_MSG_FMT_307,
                       CONF_MSG__FMT_307_BEG,
                       loc, (size_t)1, loc->len, VSTR_TYPE_ADD_ALL_BUF,
                       CONF_MSG__FMT_30x_END);
          break;
        }

        /* if using text/plain just output the URL */
        ASSERT((req->error_len - 1) == loc->len);
        vstr_add_vstr(out, out->len,
                      loc, (size_t)1, loc->len, VSTR_TYPE_ADD_ALL_BUF);
        vstr_add_cstr_ptr(out, out->len, "\n");
        break;
        
      default:
        assert(req->error_len < SIZE_MAX);
        vstr_add_ptr(out, out->len, req->error_msg, req->error_len);
    }
  }
  
  vlg_dbg3(vlg, "ERROR REPLY:\n$<vstr.all:%p>\n", out);

  if (out->conf->malloc_bad)
    return (http_con_cleanup(con, req));
  
  return (http_fin_req(con, req));
}

int http_fin_errmem_req(struct Con *con, struct Httpd_req_data *req)
{ /* try sending a 500 as the last msg */
  Vstr_base *out = con->evnt->io_w;
  
  /* remove anything we can to free space */
  vstr_sc_reduce(out, 1, out->len, out->len - req->orig_io_w_len);
  
  con->evnt->io_r->conf->malloc_bad = FALSE;
  con->evnt->io_w->conf->malloc_bad = FALSE;
  req->malloc_bad = TRUE;
  
  HTTPD_ERR_MSG_RET(req, 500, "Memory failure", http_fin_err_req(con, req));
}

static int http_fin_err_close_req(struct Con *con, Httpd_req_data *req)
{
  httpd_fin_fd_close(con);
  return (http_fin_err_req(con, req));
}

int httpd_sc_add_default_hostname(struct Con *con,
                                  Httpd_req_data *req,
                                  Vstr_base *lfn, size_t pos)
{
  const Httpd_policy_opts *opts = req->policy;
  const Vstr_base *d_h = opts->default_hostname;
  int ret = FALSE;
  
  ret = vstr_add_vstr(lfn, pos, d_h, 1, d_h->len, VSTR_TYPE_ADD_DEF);

  if (ret && req->policy->add_def_port)
  { /* FIXME: ipv6 */
    struct sockaddr_in *sinv4 = EVNT_ACPT_SA_IN4(con->evnt);

    ASSERT(sinv4->sin_family == AF_INET);

    if (ntohs(sinv4->sin_port) != 80)
      ret = vstr_add_fmt(lfn, pos + d_h->len, ":%hu", ntohs(sinv4->sin_port));
  }

  return (ret);
}

int httpd_sc_add_req_hostname(struct Con *con, Httpd_req_data *req,
                              Vstr_base *s1, size_t pos)
{
  Vstr_base *http_data = con->evnt->io_r;
  Vstr_sect_node *h_h = req->http_hdrs->hdr_host;
  
  ASSERT(h_h->len);

  if (vstr_add_vstr(s1, pos, http_data, h_h->pos, h_h->len, VSTR_TYPE_ADD_DEF))
  {
    if (req->http_host_port != 80) /* if port 80, ignore it */
      vstr_add_sysfmt(s1, pos + h_h->len, ":%hu", req->http_host_port);
    vstr_conv_lowercase(s1, pos + 1, h_h->len);
  }

  return (!!s1->conf->malloc_bad);
}

int httpd_sc_add_hostname(struct Con *con, Httpd_req_data *req,
                          Vstr_base *s1, size_t pos)
{
  if (req->http_hdrs->hdr_host->len)
    return (httpd_sc_add_req_hostname(con, req, s1, pos));

  return (httpd_sc_add_default_hostname(con, req, s1, pos));
}


static void httpd_sc_add_default_filename(Httpd_req_data *req, Vstr_base *fname)
{
  if (vstr_export_chr(fname, fname->len) == '/')
    HTTPD_APP_REF_ALLVSTR(fname, req->policy->dir_filename);
}                                  

/* turn //foo//bar// into /foo/bar/ */
int httpd_canon_path(Vstr_base *s1)
{
  size_t tmp = 0;
  
  while ((tmp = vstr_srch_cstr_buf_fwd(s1, 1, s1->len, "//")))
  {
    if (!vstr_del(s1, tmp, 1))
      return (FALSE);
  }

  return (TRUE);
}

int httpd_canon_dir_path(Vstr_base *s1)
{
  if (!httpd_canon_path(s1))
    return (FALSE);

  if (s1->len && (vstr_export_chr(s1, s1->len) != '/'))
    return (vstr_add_cstr_ptr(s1, s1->len, "/"));

  return (TRUE);
}

int httpd_canon_abs_dir_path(Vstr_base *s1)
{
  if (!httpd_canon_dir_path(s1))
    return (FALSE);

  if (s1->len && (vstr_export_chr(s1, 1) != '/'))
    return (vstr_add_cstr_ptr(s1, 0, "/"));
  
  return (TRUE);
}
  

static int http__policy_req(struct Con *con, Httpd_req_data *req)
{
  if (!httpd_policy_request(con, req,
                            httpd_opts->conf, httpd_opts->match_request))
  {
    Vstr_base *s1 = httpd_opts->conf->tmp;
    if (!req->user_return_error_code)
      vlg_info(vlg, "CONF-MATCH-REQ-ERR from[$<sa:%p>]:"
               " backtrace: $<vstr.all:%p>\n", CON_CEVNT_SA(con), s1);
    return (TRUE);
  }
  
  if (con->evnt->flag_q_closed)
  {
    Vstr_base *s1 = req->policy->s->policy_name;
    
    vlg_info(vlg, "BLOCKED from[$<sa:%p>]: policy $<vstr.all:%p>\n",
             CON_CEVNT_SA(con), s1);
    return (http_con_cleanup(con, req));
  }

  if (req->direct_uri)
  {
    Vstr_base *s1 = req->policy->s->policy_name;
    vlg_info(vlg, "CONF-MATCH-REQ-ERR from[$<sa:%p>]: policy $<vstr.all:%p>"
             " Has URI.\n", CON_CEVNT_SA(con), s1);
    HTTPD_ERR_MSG_RET(req, 503, "Has URI", TRUE);
  }
  
  if (req->policy->auth_token->len) /* they need rfc2617 auth */
  {
    Vstr_base *data = con->evnt->io_r;
    size_t pos = req->http_hdrs->hdr_authorization->pos;
    size_t len = req->http_hdrs->hdr_authorization->len;
    Vstr_base *auth_token = req->policy->auth_token;
    int auth_ok = TRUE;
    
    if (!VIPREFIX(data, pos, len, "Basic"))
      auth_ok = FALSE;
    else
    {
      len -= CLEN("Basic"); pos += CLEN("Basic");
      HTTP_SKIP_LWS(data, pos, len);
      if (!vstr_cmp_eq(data, pos, len, auth_token, 1, auth_token->len))
        auth_ok = FALSE;
    }
    
    if (!auth_ok)
    {
      req->user_return_error_code = FALSE;
      HTTPD_ERR(req, 401);
    }
  }
  
  return (TRUE);
}

int http_req_op_get(struct Con *con, Httpd_req_data *req)
{ /* GET or HEAD ops */
  Vstr_base *data = con->evnt->io_r;
  Vstr_base *out  = con->evnt->io_w;
  Vstr_base *fname = req->fname;
  const char *fname_cstr = NULL;
  unsigned int http_ret_code = 200;
  const char * http_ret_line = "OK";
  int open_flags = O_NONBLOCK;
  uintmax_t resp_len = 0;
  
  if (fname->conf->malloc_bad)
    goto malloc_err;

  assert(VPREFIX(fname, 1, fname->len, "/"));

  /* final act of vengance, before policy */
  if (vstr_srch_cstr_buf_fwd(data, req->path_pos, req->path_len, "//"))
  { /* in theory we can skip this if there is no policy */
    vstr_sub_vstr(fname, 1, fname->len, data, req->path_pos, req->path_len, 0);
    if (!httpd_canon_path(fname))
      goto malloc_err;
    httpd_req_absolute_uri(con, req, fname, 1, fname->len);
    HTTPD_REDIR_MSG(req, 301, "Path contains //");
  
    return (http_fin_err_req(con, req));
  }
  
  if (!http__policy_req(con, req))
    return (FALSE);
  if (req->error_code)
    return (http_fin_err_req(con, req));

  httpd_sc_add_default_filename(req, fname);
  
  req->conf_flags = HTTPD_CONF_REQ_FLAGS_PARSE_FILE_DEFAULT;
  if (!http__conf_req(con, req, 0))
    return (FALSE);
  if (req->error_code)
    return (http_fin_err_req(con, req));
    
  if (!http_req_content_type(req))
    return (http_fin_err_req(con, req));

  /* don't change vary_a/vary_al just because of 406 */
  if (req->parse_accept)
  {
    if (!http_parse_accept(req, HTTP__XTRA_HDR_PARAMS(req, content_type)))
      HTTPD_ERR_MSG_RET(req, 406, "Type", http_fin_err_req(con, req));
  }
  if (!req->content_language_vs1 || !req->content_language_len)
    req->parse_accept_language = FALSE;
  if (req->parse_accept_language)
  {
    if (!http_parse_accept_language(req,
                                    HTTP__XTRA_HDR_PARAMS(req,
                                                          content_language)))
      HTTPD_ERR_MSG_RET(req, 406, "Language", http_fin_err_req(con, req));
  }
  
  /* Add the document root now, this must be at least . so
   * "///foo" becomes ".///foo" ... this is done now
   * so nothing has to deal with document_root values */
  if (!req->skip_document_root)
    http_prepend_doc_root(fname, req);
  
  fname_cstr = vstr_export_cstr_ptr(fname, 1, fname->len);
  
  if (fname->conf->malloc_bad)
    goto malloc_err;

  if (req->policy->use_noatime)
    open_flags |= O_NOATIME;
  
  ASSERT(con->fs && !con->fs_num && !con->fs_off && (con->fs->fd == -1));
  if ((con->fs->fd = io__open(fname_cstr, open_flags)) == -1)
  {
    if (0) { }
    else if (req->direct_filename && (errno == EISDIR)) /* don't allow */
      HTTPD_ERR_MSG(req, 404, "Direct filename is DIR");
    else if (errno == EISDIR)
      return (http_req_chk_dir(con, req, "open(EISDIR)"));
    else if (req->conf_friendly_file && (errno == ENOENT))
      return (http_req_chk_dir(con, req, "open(ENOENT)"));
    else if (req->conf_friendly_file &&
             (errno == ENOTDIR)) /* part of path was not a dir */
      return (http_req_chk_dir(con, req, "open(ENOTDIR)"));
    else if (req->conf_friendly_file && (errno == ENAMETOOLONG)) /* 414 ? */
      return (http_req_chk_dir(con, req, "open(ENAMETOOLONG)"));
    else if ((errno == ENOENT) && req->conf_friendly_dirs)
      return (http_req_chk_file(con, req, "open(ENOENT)"));
    else if (errno == ENOTDIR) /* part of path was not a dir */
      return (http_req_chk_file(con, req, "open(ENOTDIR)"));
    else if (errno == ENAMETOOLONG) /* 414 ? */
      return (http_req_chk_file(con, req, "open(ENAMETOOLONG)"));
    else if (errno == EACCES)
      HTTPD_ERR_MSG(req, 403, "open(EACCES)");
    else if (errno == ENOENT)
      HTTPD_ERR_MSG(req, 404, "open(ENOENT)");
    else if (errno == ENODEV) /* device file, with no driver */
      HTTPD_ERR_MSG(req, 404, "open(ENODEV)");
    else if (errno == ENXIO) /* device file, with no driver */
      HTTPD_ERR_MSG(req, 404, "open(ENXIO)");
    else if (errno == ELOOP) /* symlinks */
      HTTPD_ERR_MSG(req, 404, "open(ELOOP)");
    else if (errno == EMFILE) /* can't create fd ... just close */
      return (http_con_cleanup(con, req));
    else
    {
      vlg_warn(vlg, "open(%s): %m\n", fname_cstr);
      HTTPD_ERR_MSG(req, 500, "open()");
    }
    
    return (http_fin_err_req(con, req));
  }
  if (fstat64(con->fs->fd, req->f_stat) == -1)
    HTTPD_ERR_MSG_RET(req, 500, "fstat()", http_fin_err_close_req(con, req));
  if (req->policy->use_public_only && !(req->f_stat->st_mode & S_IROTH))
    HTTPD_ERR_MSG_RET(req, 403, "Filename is not PUBLIC",
                      http_fin_err_close_req(con, req));
  
  if (S_ISDIR(req->f_stat->st_mode))
  {
    if (req->direct_filename) /* don't allow */
      HTTPD_ERR_MSG_RET(req, 404, "Direct filename is DIR",
                        http_fin_err_close_req(con, req));
    httpd_fin_fd_close(con);
    return (http_req_chk_dir(con, req, "ISDIR"));
  }
  if (!S_ISREG(req->f_stat->st_mode))
    HTTPD_ERR_MSG_RET(req, 403, "File not ISREG",
                      http_fin_err_close_req(con, req));
  
  con->fs->len = req->f_stat->st_size;
  
  if (req->ver_0_9)
  {
    httpd_serv_file_sects_none(con, req, req->f_stat);
    httpd_serv_call_file_init(con, req, &http_ret_code, &http_ret_line);
    http_ret_line = "OK - HTTP/0.9";
  }
  else if (!http_req_1_x(con, req, &http_ret_code, &http_ret_line))
    return (http_fin_err_close_req(con, req));
  
  if (out->conf->malloc_bad)
    goto malloc_close_err;
  
  vlg_dbg3(vlg, "REPLY:\n$<vstr.all:%p>\n", out);
  
  if (con->use_mmap && !vstr_mov(con->evnt->io_w, con->evnt->io_w->len,
                                 req->f_mmap, 1, req->f_mmap->len))
    goto malloc_close_err;

  /* req->head_op is set for 304 returns */
  resp_len = http_serv_file_len(con, req);
  vlg_info(vlg, "REQ $<vstr.sect:%p%p%u> from[$<sa:%p>] ret[%03u %s]"
           " sz[${BKMG.ju:%ju}:%ju]", data, req->sects, 1U, CON_CEVNT_SA(con),
           http_ret_code, http_ret_line, resp_len, resp_len);
  http_vlg_def(con, req, FALSE);
  
  return (http_fin_fd_req(con, req));
  
 malloc_close_err:
  httpd_fin_fd_close(con);
 malloc_err:
  VLG_WARNNOMEM_RET(http_fin_errmem_req(con, req), (vlg, "op_get(): %m\n"));
}

int http_req_op_opts(struct Con *con, Httpd_req_data *req)
{
  Vstr_base *out = con->evnt->io_w;
  Vstr_base *fname = req->fname;
  uintmax_t tmp = 0;

  if (fname->conf->malloc_bad)
    goto malloc_err;
  
  assert(VPREFIX(fname, 1, fname->len, "/") ||
         !req->policy->use_vhosts_name ||
         !req->policy->use_host_chk ||
	 !req->policy->use_host_err_400 ||
         VEQ(con->evnt->io_r, req->path_pos, req->path_len, "*"));
  
  /* apache doesn't test for 404's here ... which seems weird */
  
  http_app_def_hdrs(con, req, 200, "OK", 0, NULL, TRUE, 0);
  HTTP_APP_HDR_CONST_CSTR(out, "Allow", "GET, HEAD, OPTIONS, TRACE");
  http_app_end_hdrs(out);
  if (out->conf->malloc_bad)
    goto malloc_err;
  
  vlg_info(vlg, "REQ %s from[$<sa:%p>] ret[%03u %s] sz[${BKMG.ju:%ju}:%ju]",
           "OPTIONS", CON_CEVNT_SA(con), 200, "OK", tmp, tmp);
  http_vlg_def(con, req, FALSE);
  
  return (http_fin_req(con, req));
  
 malloc_err:
  VLG_WARNNOMEM_RET(http_fin_errmem_req(con, req), (vlg, "op_opts(): %m\n"));
}

int http_req_op_trace(struct Con *con, Httpd_req_data *req)
{
  Vstr_base *data = con->evnt->io_r;
  Vstr_base *out  = con->evnt->io_w;
  uintmax_t tmp = req->len;
  
  http_app_def_hdrs(con, req, 200, "OK", req->now,
                    "message/http", FALSE, tmp);
  http_app_end_hdrs(out);
  vstr_add_vstr(out, out->len, data, 1, req->len, VSTR_TYPE_ADD_DEF);
  if (out->conf->malloc_bad)
    VLG_WARNNOMEM_RET(http_fin_errmem_req(con, req), (vlg, "op_trace(): %m\n"));

  vlg_info(vlg, "REQ %s from[$<sa:%p>] ret[%03u %s] sz[${BKMG.ju:%ju}:%ju]",
           "TRACE", CON_CEVNT_SA(con), 200, "OK", tmp, tmp);
  http_vlg_def(con, req, FALSE);
      
  return (http_fin_req(con, req));
}

int httpd_init_default_hostname(Opt_serv_policy_opts *sopts)
{
  Httpd_policy_opts *popts = (Httpd_policy_opts *)sopts;
  Vstr_base *nhn = popts->default_hostname;
  Vstr_base *chn = NULL;
  
  if (!httpd__valid_hostname(nhn, 1, nhn->len, FALSE))
    vstr_del(nhn, 1, nhn->len);

  if (nhn->len)
    return (TRUE);
  
  if (sopts != sopts->beg->def_policy)
    chn = ((Httpd_policy_opts *)sopts->beg->def_policy)->default_hostname;
  
  if (chn)
    HTTPD_APP_REF_ALLVSTR(nhn, chn);
  else
  {
    opt_serv_sc_append_hostname(nhn, 0);
    vstr_conv_lowercase(nhn, 1, nhn->len);
  }

  return (!nhn->conf->malloc_bad);
}

static int httpd__serv_send_err(struct Con *con, const char *msg)
{
  if (errno != EPIPE)
    vlg_warn(vlg, "send(%s): %m\n", msg);
  else
    vlg_dbg2(vlg, "send(%s): SIGPIPE $<sa:%p>\n", msg, CON_CEVNT_SA(con));

  return (FALSE);
}

static int httpd_serv_q_send(struct Con *con)
{
  vlg_dbg2(vlg, "http Q send $<sa:%p>\n", CON_CEVNT_SA(con));
  if (!evnt_send_add(con->evnt, TRUE, HTTPD_CONF_MAX_WAIT_SEND))
    return (httpd__serv_send_err(con, "Q"));
      
  /* queued */
  return (TRUE);
}

static int httpd__serv_fin_send(struct Con *con)
{
  if (con->keep_alive)
    /* need to try immediately, as we might have already got the next req */
    return (http_parse_req(con));

  return (evnt_shutdown_w(con->evnt));
}

/* NOTE: lim is just a hint ... we can send more */
static int httpd__serv_send_lim(struct Con *con, const char *emsg,
                                unsigned int lim, int *cont)
{
  Vstr_base *out = con->evnt->io_w;
  
  *cont = FALSE;
  
  while (out->len >= lim)
  {
    if (!con->io_limit_num--) return (httpd_serv_q_send(con));
    
    if (!evnt_send(con->evnt))
      return (httpd__serv_send_err(con, emsg));
  }

  *cont = TRUE;
  return (TRUE);
}

int httpd_serv_send(struct Con *con)
{
  Vstr_base *out = con->evnt->io_w;
  int cont = FALSE;
  int ret = FALSE;
  struct File_sect *fs = NULL;
  
  ASSERT(!out->conf->malloc_bad);
    
  if (!con->fs_num)
  {
    ASSERT(!con->fs_off);
    
    ret = httpd__serv_send_lim(con, "end", 1, &cont);
    if (!cont)
      return (ret);
    
    return (httpd__serv_fin_send(con));
  }

  ASSERT(con->fs && (con->fs_off < con->fs_num) && (con->fs_num <= con->fs_sz));
  fs = &con->fs[con->fs_off];
  ASSERT((fs->fd != -1) && fs->len);
  
  if (con->use_sendfile)
  {
    unsigned int ern = 0;

    ret = httpd__serv_send_lim(con, "sendfile", 1, &cont);
    if (!cont)
      return (ret);
    
    while (fs->len)
    {
      if (!con->io_limit_num--) return (httpd_serv_q_send(con));
      
      if (!evnt_sendfile(con->evnt, fs->fd, &fs->off, &fs->len, &ern))
      {
        if (ern == VSTR_TYPE_SC_READ_FD_ERR_EOF)
          goto file_eof_end;
        
        if (errno == EPIPE)
        {
          vlg_dbg2(vlg, "sendfile: SIGPIPE $<sa:%p>\n", CON_CEVNT_SA(con));
          return (FALSE);
        }

        if (errno == ENOSYS)
          httpd__disable_sendfile();
        vlg_warn(vlg, "sendfile: %m\n");
        
        if (lseek64(fs->fd, fs->off, SEEK_SET) == -1)
          VLG_WARN_RET(FALSE,
                       (vlg, "lseek(<sendfile>,off=%ju): %m\n", fs->off));

        con->use_sendfile = FALSE;
        return (httpd_serv_send(con)); /* recurse */
      }
    }
    
    goto file_end;
  }

  while (fs->len)
  {
    ret = httpd__serv_send_lim(con, "max", EX_MAX_W_DATA_INCORE, &cont);
    if (!cont)
      return (ret);
    
    switch (evnt_sc_read_send(con->evnt, fs->fd, &fs->len))
    {
      case EVNT_IO_OK:
        ASSERT_NO_SWITCH_DEF();
        
      case EVNT_IO_READ_ERR:
        vlg_warn(vlg, "read: %m\n");
        out->conf->malloc_bad = FALSE;
        
      case EVNT_IO_READ_FIN: goto file_end;
      case EVNT_IO_READ_EOF: goto file_eof_end;
        
      case EVNT_IO_SEND_ERR:
        return (httpd__serv_send_err(con, "io_get"));
    }
  }

  ASSERT_NOT_REACHED();

 file_end:
  ASSERT(!fs->len);
  if (con->use_mpbr) /* multipart/byterange */
  {
    ASSERT(con->mpbr_ct);
    ASSERT(con->mpbr_fs_len);

    if (!(fs = httpd__fd_next(con)))
    {
      vstr_add_cstr_ptr(out, out->len, "--SEP--" HTTP_EOL);
      return (httpd_serv_send(con)); /* restart with a read, or finish */
    }
    con->use_mmap = FALSE;
    if (!httpd_serv_call_seek(con, fs))
      VLG_WARN_RET(FALSE, (vlg, "lseek(<mpbr>,off=%ju): %m\n", fs->off));

    http_app_hdrs_mpbr(con, fs);
    return (httpd_serv_send(con)); /* start outputting next file section */
  }
  
 file_eof_end:
  if (fs->len) /* something bad happened, just kill the connection */
    con->keep_alive = HTTP_NON_KEEP_ALIVE;
  
  httpd_fin_fd_close(con);
  return (httpd_serv_send(con)); /* restart with a read, or finish */
}

int httpd_serv_recv(struct Con *con)
{
  unsigned int ern = 0;
  int ret = 0;
  Vstr_base *data = con->evnt->io_r;

  ASSERT(!con->evnt->io_r_shutdown);
  
  if (!con->io_limit_num--)
    return (TRUE);
  
  if (!(ret = evnt_recv(con->evnt, &ern)))
  {
    if (ern != VSTR_TYPE_SC_READ_FD_ERR_EOF)
    {
      vlg_dbg2(vlg, "RECV ERR from[$<sa:%p>]: %u\n", CON_CEVNT_SA(con), ern);
      goto con_cleanup;
    }
    if (!evnt_shutdown_r(con->evnt, TRUE))
      goto con_cleanup;
  }

  if (con->fs_num) /* may need to stop input, until we can deal with next req */
  {
    ASSERT(con->keep_alive || con->parsed_method_ver_1_0);
    
    if (con->policy->max_header_sz && (data->len > con->policy->max_header_sz))
      evnt_wait_cntl_del(con->evnt, POLLIN);

    return (TRUE);
  }
  
  if (http_parse_req(con))
    return (TRUE);
  
 con_cleanup:
  con->evnt->io_r->conf->malloc_bad = FALSE;
  con->evnt->io_w->conf->malloc_bad = FALSE;
    
  return (FALSE);
}

int httpd_con_init(struct Con *con, struct Acpt_listener *acpt_listener)
{
  int ret = TRUE;
  Httpd_policy_opts *po = (Httpd_policy_opts *)httpd_opts->s->def_policy;
  
  con->mpbr_ct = NULL;
  
  con->fs      = con->fs_store;
  con->fs->len = 0;
  con->fs->fd  = -1;
  con->fs_off  = 0;
  con->fs_num  = 0;
  con->fs_sz   = 1;

  con->vary_star   = FALSE;
  con->keep_alive  = HTTP_NON_KEEP_ALIVE;
  con->evnt->acpt_sa_ref = vstr_ref_add(acpt_listener->ref);
  con->use_mpbr    = FALSE;
  con->use_mmap    = FALSE;

  con->parsed_method_ver_1_0 = FALSE;

  if (acpt_listener->def_policy)
    po = acpt_listener->def_policy->ptr;
  
  httpd_policy_change_con(con, po);

  if (!httpd_policy_connection(con,
                               httpd_opts->conf, httpd_opts->match_connection))
  {
    Vstr_base *s1 = con->policy->s->policy_name;
    Vstr_base *s2 = httpd_opts->conf->tmp;

    vlg_info(vlg, "CONF-MAIN-ERR from[$<sa:%p>]: policy $<vstr.all:%p>"
             " backtrace: $<vstr.all:%p>\n", CON_CEVNT_SA(con), s1, s2);
    ret = FALSE;
  }
  else if (con->evnt->flag_q_closed)
  {
    Vstr_base *s1 = con->policy->s->policy_name;
    vlg_info(vlg, "BLOCKED from[$<sa:%p>]: policy $<vstr.all:%p>\n",
             CON_CEVNT_SA(con), s1);
    ret = FALSE;
  }
  
  return (ret);
}

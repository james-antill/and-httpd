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
/* main HTTPD appending APIs, output responses */

#define EX_UTILS_NO_FUNCS 1
#include "ex_utils.h"

#include "mk.h"

#include "vlg.h"

#define HTTPD_HAVE_GLOBAL_OPTS 1
#include "httpd.h"
#include "httpd_policy.h"

#include "base64.h"

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

static Vlg *vlg = NULL;


void httpd_app_init(Vlg *passed_vlg)
{
  ASSERT(passed_vlg && !vlg);
  vlg = passed_vlg;
}

void httpd_app_exit(void)
{
  ASSERT(vlg);
  vlg = NULL;
}


static void http__app_hdr_hdr(Vstr_base *out, const char *hdr)
{
  vstr_add_cstr_buf(out, out->len, hdr);
  vstr_add_cstr_buf(out, out->len, ": ");  
}
static void http__app_hdr_eol(Vstr_base *out)
{
  vstr_add_cstr_buf(out, out->len, HTTP_EOL);
}

void http_app_hdr_cstr(Vstr_base *out, const char *hdr, const char *data)
{
  http__app_hdr_hdr(out, hdr);
  vstr_add_cstr_buf(out, out->len, data);
  http__app_hdr_eol(out);
}

void http_app_hdr_vstr(Vstr_base *out, const char *hdr,
                       const Vstr_base *s1, size_t vpos, size_t vlen,
                       unsigned int type)
{
  if (!vlen) return; /* don't allow "empty" headers, use a single space */
  
  http__app_hdr_hdr(out, hdr);
  vstr_add_vstr(out, out->len, s1, vpos, vlen, type);
  http__app_hdr_eol(out);
}

void http_app_hdr_vstr_def(Vstr_base *out, const char *hdr,
                           const Vstr_base *s1, size_t vpos, size_t vlen)
{
  if (!vlen) return; /* don't allow "empty" headers, use a single space */
  
  http__app_hdr_hdr(out, hdr);
  vstr_add_vstr(out, out->len, s1, vpos, vlen, VSTR_TYPE_ADD_DEF);
  http__app_hdr_eol(out);
}

void http_app_hdr_conf_vstr(Vstr_base *out, const char *hdr,
                            const Vstr_base *s1)
{
  if (!s1->len) return; /* don't allow "empty" headers, a single space */
  
  http__app_hdr_hdr(out, hdr);
  vstr_add_vstr(out, out->len, s1, 1, s1->len, VSTR_TYPE_ADD_DEF);
  http__app_hdr_eol(out);
}

/* convert a 4byte number into 4 bytes... */
#define APP_BUF4(x) do {                                       \
      buf[(x * 4) + 0] = (num[x] >>  0) & 0xFF;                \
      buf[(x * 4) + 1] = (num[x] >>  8) & 0xFF;                \
      buf[(x * 4) + 2] = (num[x] >> 16) & 0xFF;                \
      buf[(x * 4) + 3] = (num[x] >> 14) & 0xFF;                \
    } while (FALSE)
static void http_app_hdr_vstr_md5(struct Con *con, Httpd_req_data *req,
                                  const Vstr_base *s1, size_t vpos, size_t vlen)
{
  Vstr_base *out = con->evnt->io_w;
  
  if (!vlen) return; /* don't allow "empty" headers, use a single space */
  
  http__app_hdr_hdr(out, "Content-MD5");

  if (vlen == (128 / 8)) /* raw bytes ... */
    vstr_x_conv_base64_encode(out, out->len, s1, vpos, vlen, 0);
  else if (vlen != (128 / 4)) /* just output... */
    vstr_add_vstr(out, out->len, s1, vpos, vlen, VSTR_TYPE_ADD_DEF);
  else /* hex encoded bytes... */
  { /* NOTE: lots of work, should be compiled to raw bytes in the conf */
    Vstr_base *xc = req->xtra_content;
    size_t pos = 0;
    unsigned int nflags = VSTR_FLAG02(PARSE_NUM_NO, BEG_PM, NEGATIVE);
    unsigned int num[4];
    unsigned char buf[128 / 8];
    
    ASSERT(xc); /* must be true, if the MD5 headers are used */

    num[0] = vstr_parse_uint(s1, vpos, 8, 16 | nflags, NULL, NULL);
    num[1] = vstr_parse_uint(s1, vpos, 8, 16 | nflags, NULL, NULL);
    num[2] = vstr_parse_uint(s1, vpos, 8, 16 | nflags, NULL, NULL);
    num[3] = vstr_parse_uint(s1, vpos, 8, 16 | nflags, NULL, NULL);
    
    APP_BUF4(0);
    APP_BUF4(1);
    APP_BUF4(2);
    APP_BUF4(3);
    
    pos = xc->len + 1;
    if (!vstr_add_buf(xc, xc->len, buf, sizeof(buf)))
      return;

    /* raw bytes now... */
    ASSERT(vstr_sc_posdiff(pos, xc->len) == sizeof(buf));
                           
    vstr_x_conv_base64_encode(out, out->len, xc, pos, sizeof(buf), 0);
  }
}
#undef APP_BUF4

void http_app_hdr_fmt(Vstr_base *out, const char *hdr, const char *fmt, ...)
{
  va_list ap;

  http__app_hdr_hdr(out, hdr);
  
  va_start(ap, fmt);
  vstr_add_vfmt(out, out->len, fmt, ap);
  va_end(ap);

  http__app_hdr_eol(out);
}

void http_app_hdr_uintmax(Vstr_base *out, const char *hdr, uintmax_t data)
{
  http__app_hdr_hdr(out, hdr);
  vstr_add_fmt(out, out->len, "%ju", data);
  http__app_hdr_eol(out);
}

#define HTTP__VARY_ADD(x, y) do {                                       \
      ASSERT((x) < (sizeof(varies_ptr) / sizeof(varies_ptr[0])));       \
                                                                        \
      varies_ptr[(x)] = (y);                                            \
      varies_len[(x)] = CLEN(y);                                        \
      ++(x);                                                            \
    } while (FALSE)

void http_app_def_hdrs(struct Con *con, struct Httpd_req_data *req,
                       unsigned int http_ret_code,
                       const char *http_ret_line, time_t mtime,
                       const char *custom_content_type,
                       int use_range,
                       uintmax_t content_length)
{
  Vstr_base *out = con->evnt->io_w;
  Date_store *ds = httpd_opts->date;
  
  if (use_range)
    use_range = req->policy->use_range;
  
  vstr_add_fmt(out, out->len, "%s %03u %s" HTTP_EOL,
               "HTTP/1.1", http_ret_code, http_ret_line);
  http_app_hdr_cstr(out, "Date", date_rfc1123(ds, req->now));
  http_app_hdr_conf_vstr(out, "Server", req->policy->server_name);

  if (mtime)
  { /* if mtime in future, chop it #14.29 
     * for cache validation we don't cmp last-modified == now either */
    if (difftime(req->now, mtime) <= 0)
      mtime = req->now;
    http_app_hdr_cstr(out, "Last-Modified", date_rfc1123(ds, mtime));
  }
  
  switch (con->keep_alive)
  {
    case HTTP_NON_KEEP_ALIVE:
      HTTP_APP_HDR_CONST_CSTR(out, "Connection", "close");
      break;
      
    case HTTP_1_0_KEEP_ALIVE:
      HTTP_APP_HDR_CONST_CSTR(out, "Connection", "Keep-Alive");
      /* FALLTHROUGH */
    case HTTP_1_1_KEEP_ALIVE:
      if (req->policy->output_keep_alive_hdr)
      {
        if (!req->policy->max_requests)
          http_app_hdr_fmt(out, "Keep-Alive",
                           "%s=%u", "timeout", req->policy->s->idle_timeout);
        else
        {
          unsigned int left = (req->policy->max_requests -
                               con->evnt->acct.req_got);
          
          http_app_hdr_fmt(out, "Keep-Alive",
                           "%s=%u, %s=%u",
                           "timeout", req->policy->s->idle_timeout,
                           "max", left);
        }
      }
      
      ASSERT_NO_SWITCH_DEF();
  }

  switch (http_ret_code)
  {
    case 200: /* OK */
      /* case 206: */ /* OK - partial -- needed? */
    case 302: case 307: /* Tmp Redirects */
    case 304: /* Not modified */
    case 406: /* Not accept - a */
    case 412: /* Not accept - precondition */
    case 413: /* Too large */
    case 416: /* Bad range */
    case 417: /* Not accept - expect contained something */
      if (use_range && req->policy->use_adv_range)
        HTTP_APP_HDR_CONST_CSTR(out, "Accept-Ranges", "bytes");
  }
  
  if (req->vary_star)
    HTTP_APP_HDR_CONST_CSTR(out, "Vary", "*");
  else if (req->vary_a || req->vary_ac || req->vary_ae || req->vary_al ||
           req->vary_rf || req->vary_ua ||
           req->vary_ims || req->vary_ius || req->vary_ir  ||
           req->vary_im  || req->vary_inm || req->vary_xm)
  {
    const char *varies_ptr[11];
    size_t      varies_len[12];
    unsigned int num = 0;
    
    if (req->vary_xm)  HTTP__VARY_ADD(num, "X-Moz");
    if (req->vary_ua)  HTTP__VARY_ADD(num, "User-Agent");
    if (req->vary_rf)  HTTP__VARY_ADD(num, "Referer");
    if (req->vary_ius) HTTP__VARY_ADD(num, "If-Unmodified-Since");
    if (req->vary_ir)  HTTP__VARY_ADD(num, "If-Range");
    if (req->vary_inm) HTTP__VARY_ADD(num, "If-None-Match");
    if (req->vary_ims) HTTP__VARY_ADD(num, "If-Modified-Since");
    if (req->vary_im)  HTTP__VARY_ADD(num, "If-Match");
    if (req->vary_al)  HTTP__VARY_ADD(num, "Accept-Language");
    if (req->vary_ae)  HTTP__VARY_ADD(num, "Accept-Encoding");
    if (req->vary_ac)  HTTP__VARY_ADD(num, "Accept-Charset");
    if (req->vary_a)   HTTP__VARY_ADD(num, "Accept");

    ASSERT(num && (num <= 12));
    
    http__app_hdr_hdr(out, "Vary");
    while (num-- > 1)
    {
      vstr_add_buf(out, out->len, varies_ptr[num], varies_len[num]);
      vstr_add_cstr_buf(out, out->len, ",");
    }
    ASSERT(num == 0);
    
    vstr_add_buf(out, out->len, varies_ptr[0], varies_len[0]);
    http__app_hdr_eol(out);
  }

  if (con->use_mpbr)
  {
    ASSERT(con->mpbr_ct && !con->mpbr_ct->len);
    if (req->content_type_vs1 && req->content_type_len)
      http_app_hdr_vstr_def(con->mpbr_ct, "Content-Type",
                            HTTP__XTRA_HDR_PARAMS(req, content_type));
    HTTP_APP_HDR_CONST_CSTR(out, "Content-Type",
                            "multipart/byteranges; boundary=SEP");
  }
  else if (req->content_type_vs1 && req->content_type_len)
    http_app_hdr_vstr_def(out, "Content-Type",
                          HTTP__XTRA_HDR_PARAMS(req, content_type));
  else if (custom_content_type) /* possible we don't send one */
    http_app_hdr_cstr(out, "Content-Type", custom_content_type);
  
  if (req->content_encoding_bzip2)
      HTTP_APP_HDR_CONST_CSTR(out, "Content-Encoding", "bzip2");
  else if (req->content_encoding_gzip)
  {
    if (req->content_encoding_xgzip)
      HTTP_APP_HDR_CONST_CSTR(out, "Content-Encoding", "x-gzip");
    else
      HTTP_APP_HDR_CONST_CSTR(out, "Content-Encoding", "gzip");
  }
  
  if (!con->use_mpbr)
    http_app_hdr_uintmax(out, "Content-Length", content_length);
}
#undef HTTP__VARY_ADD

void http_app_end_hdrs(Vstr_base *out)
{ /* apache contains a workaround for buggy Netscape 2.x, 3.x and 4.0beta */
  http__app_hdr_eol(out);
}

void http_app_hdrs_url(struct Con *con, Httpd_req_data *req)
{
  Vstr_base *out = con->evnt->io_w;
  
  if (req->cache_control_vs1)
    http_app_hdr_vstr_def(out, "Cache-Control",
                          HTTP__XTRA_HDR_PARAMS(req, cache_control));
  if (req->expires_vs1 && (req->expires_time > req->f_stat->st_mtime))
    http_app_hdr_vstr_def(out, "Expires",
                          HTTP__XTRA_HDR_PARAMS(req, expires));
  if (req->p3p_vs1)
    http_app_hdr_vstr_def(out, "P3P",
                          HTTP__XTRA_HDR_PARAMS(req, p3p));
}

void http_app_hdrs_file(struct Con *con, Httpd_req_data *req)
{
  Vstr_base *out = con->evnt->io_w;
  time_t mtime     = req->f_stat->st_mtime;
  time_t enc_mtime = req->encoded_mtime;
  
  if (req->content_disposition_vs1)
    http_app_hdr_vstr_def(out, "Content-Disposition",
                          HTTP__XTRA_HDR_PARAMS(req, content_disposition));
  if (req->content_language_vs1)
    http_app_hdr_vstr_def(out, "Content-Language",
                          HTTP__XTRA_HDR_PARAMS(req, content_language));
  if (req->content_encoding_bzip2)
  {
    if (req->bzip2_content_md5_vs1 && (req->content_md5_time > enc_mtime))
      http_app_hdr_vstr_md5(con, req,
                            HTTP__XTRA_HDR_PARAMS(req, bzip2_content_md5));
  }
  else if (req->content_encoding_gzip)
  {
    if (req->gzip_content_md5_vs1 && (req->content_md5_time > enc_mtime))
      http_app_hdr_vstr_md5(con, req,
                            HTTP__XTRA_HDR_PARAMS(req, gzip_content_md5));
  }
  else if (req->content_md5_vs1 && (req->content_md5_time > mtime))
    http_app_hdr_vstr_md5(con, req,
                          HTTP__XTRA_HDR_PARAMS(req, content_md5));
  
  if (req->content_encoding_bzip2)
  {
    if (req->bzip2_etag_vs1 && (req->etag_time > enc_mtime))
      http_app_hdr_vstr_def(out, "ETag",
                            HTTP__XTRA_HDR_PARAMS(req, bzip2_etag));
  }
  else if (req->content_encoding_gzip)
  {
    if (req->gzip_etag_vs1 && (req->etag_time > enc_mtime))
      http_app_hdr_vstr_def(out, "ETag",
                            HTTP__XTRA_HDR_PARAMS(req, gzip_etag));
  }
  else if (req->etag_vs1 && (req->etag_time > mtime))
    http_app_hdr_vstr_def(out, "ETag", HTTP__XTRA_HDR_PARAMS(req, etag));
  
  if (req->link_vs1)
    http_app_hdr_vstr_def(out, "Link", HTTP__XTRA_HDR_PARAMS(req, link));
}

void http_app_hdrs_mpbr(struct Con *con, struct File_sect *fs)
{
  Vstr_base *out = con->evnt->io_w;
  uintmax_t range_beg;
  uintmax_t range_end;    

  ASSERT(fs && (fs->fd != -1));
  
  range_beg = fs->off;
  range_end = range_beg + fs->len - 1;

  vstr_add_cstr_ptr(out, out->len, "--SEP" HTTP_EOL);
  HTTPD_APP_REF_ALLVSTR(out, con->mpbr_ct);
  http_app_hdr_fmt(out, "Content-Range",
                   "%s %ju-%ju/%ju", "bytes", range_beg, range_end,
                   con->mpbr_fs_len);
  http_app_end_hdrs(out);
}


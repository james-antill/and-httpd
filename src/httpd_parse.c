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
/* main HTTP parsing routines, currently mainly implements server portions */

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

void httpd_parse_init(Vlg *passed_vlg)
{
  ASSERT(passed_vlg && !vlg);
  vlg = passed_vlg;
}

void httpd_parse_exit(void)
{
  ASSERT(vlg);
  vlg = NULL;
}

/* HTTP crack -- Implied linear whitespace between tokens, note that it
 * is *LWS == *([CRLF] 1*(SP | HT)) */
void http_parse_skip_lws(const Vstr_base *s1, size_t *pos, size_t *len)
{
  size_t lws__len = 0;
  
  ASSERT(s1 && pos && len);
  
  while (TRUE)
  {
    if (VPREFIX(s1, *pos, *len, HTTP_EOL))
    {
      *len -= CLEN(HTTP_EOL); *pos += CLEN(HTTP_EOL);
    }
    else if (lws__len)
      break;
    
    if (!(lws__len = vstr_spn_cstr_chrs_fwd(s1, *pos, *len, HTTP_LWS)))
      break;
    *len -= lws__len;
    *pos += lws__len;
  }
}

/* might have been able to do it with string matches, but getting...
 * "HTTP/1.1" = OK
 * "HTTP/1.10" = OK
 * "HTTP/1.10000000000000" = BAD
 * ...seemed not as easy. It also seems like you have to accept...
 * "HTTP / 01 . 01" as "HTTP/1.1"
 */
int http_parse_version(struct Con *con, struct Httpd_req_data *req)
{
  Vstr_base *data = con->evnt->io_r;
  size_t op_pos = VSTR_SECTS_NUM(req->sects, 3)->pos;
  size_t op_len = VSTR_SECTS_NUM(req->sects, 3)->len;
  unsigned int major = 0;
  unsigned int minor = 0;
  size_t num_len = 0;
  unsigned int num_flags = 10 | (VSTR_FLAG_PARSE_NUM_NO_BEG_PM |
                                 VSTR_FLAG_PARSE_NUM_OVERFLOW);
  
  if (!VPREFIX(data, op_pos, op_len, "HTTP"))
    HTTPD_ERR_MSG_RET(req, 400, "<PROTO>/Version", FALSE);

  op_len -= CLEN("HTTP"); op_pos += CLEN("HTTP");
  HTTP_SKIP_LWS(data, op_pos, op_len);
  
  if (!VPREFIX(data, op_pos, op_len, "/"))
    HTTPD_ERR_MSG_RET(req, 400, "HTTP/Version", FALSE);
  op_len -= CLEN("/"); op_pos += CLEN("/");
  HTTP_SKIP_LWS(data, op_pos, op_len);
  
  major = vstr_parse_uint(data, op_pos, op_len, num_flags, &num_len, NULL);
  op_len -= num_len; op_pos += num_len;
  HTTP_SKIP_LWS(data, op_pos, op_len);
  
  if (!num_len || !VPREFIX(data, op_pos, op_len, "."))
    HTTPD_ERR_MSG_RET(req, 400, "HTTP/Version", FALSE);

  op_len -= CLEN("."); op_pos += CLEN(".");
  HTTP_SKIP_LWS(data, op_pos, op_len);
  
  minor = vstr_parse_uint(data, op_pos, op_len, num_flags, &num_len, NULL);
  op_len -= num_len; op_pos += num_len;
  HTTP_SKIP_LWS(data, op_pos, op_len);
  
  if (!num_len || op_len)
    HTTPD_ERR_MSG_RET(req, 400, "HTTP/Version", FALSE);
  
  if (0) { } /* not allowing HTTP/0.9 here */
  else if ((major == 1) && (minor >  1))
    req->ver_1_x = TRUE;
  else if ((major == 1) && (minor == 1))
    req->ver_1_1 = TRUE;
  else if ((major == 1) && (minor == 0))
  { /* do nothing */ }
  else
    HTTPD_ERR_MSG_RET(req, 505, "HTTP/Version", FALSE);
        
  return (TRUE);
}

void http_parse_clear_hdrs(struct Httpd_req_data *req)
{
  Vstr_base *tmp = req->http_hdrs->multi->combiner_store;

  ASSERT(tmp);
  
  HTTP__HDR_SET(req, ua,                  0, 0);
  HTTP__HDR_SET(req, referer,             0, 0);

  HTTP__HDR_SET(req, authorization,       0, 0);
  HTTP__HDR_SET(req, expect,              0, 0);
  HTTP__HDR_SET(req, host,                0, 0);
  req->http_host_port = 80;
  HTTP__HDR_SET(req, if_modified_since,   0, 0);
  HTTP__HDR_SET(req, if_range,            0, 0);
  HTTP__HDR_SET(req, if_unmodified_since, 0, 0);
  HTTP__HDR_SET(req, range,               0, 0);
  HTTP__HDR_SET(req, x_moz,               0, 0);

  vstr_del(tmp, 1, tmp->len);
  HTTP__HDR_MULTI_SET(req, accept,          0, 0);
  HTTP__HDR_MULTI_SET(req, accept_charset,  0, 0);
  HTTP__HDR_MULTI_SET(req, accept_encoding, 0, 0);
  HTTP__HDR_MULTI_SET(req, accept_language, 0, 0);
  HTTP__HDR_MULTI_SET(req, connection,      0, 0);
  HTTP__HDR_MULTI_SET(req, if_match,        0, 0);
  HTTP__HDR_MULTI_SET(req, if_none_match,   0, 0);

  if (req->xtra_content)
    vstr_del(req->xtra_content, 1, req->xtra_content->len);

  HTTP__XTRA_HDR_INIT(content_type);
  HTTP__XTRA_HDR_INIT(content_disposition);
  HTTP__XTRA_HDR_INIT(content_language);
  HTTP__XTRA_HDR_INIT(content_location);
  HTTP__XTRA_HDR_INIT(content_md5);
  HTTP__XTRA_HDR_INIT(gzip_content_md5);
  HTTP__XTRA_HDR_INIT(bzip2_content_md5);
  HTTP__XTRA_HDR_INIT(cache_control);
  HTTP__XTRA_HDR_INIT(etag);
  HTTP__XTRA_HDR_INIT(expires);
  HTTP__XTRA_HDR_INIT(link);
  HTTP__XTRA_HDR_INIT(p3p);
  HTTP__XTRA_HDR_INIT(ext_vary_a);
  HTTP__XTRA_HDR_INIT(ext_vary_ac);
  HTTP__XTRA_HDR_INIT(ext_vary_al);
}

static void http__multi_hdr_fixup(Vstr_sect_node *hdr_ignore,
                                  Vstr_sect_node *hdr, size_t pos, size_t len)
{
  if (hdr == hdr_ignore)
    return;
  
  if (hdr->pos <= pos)
    return;

  hdr->pos += len;
}

static int http__multi_hdr_cp(Vstr_base *comb,
                              Vstr_base *data, Vstr_sect_node *hdr)
{
  size_t pos = comb->len + 1;

  if (!hdr->pos)
    return (TRUE);
  
  if (hdr->len &&
      !vstr_add_vstr(comb, comb->len,
                     data, hdr->pos, hdr->len, VSTR_TYPE_ADD_BUF_PTR))
    return (FALSE);

  hdr->pos = pos;
  
  return (TRUE);
}

static int http__app_multi_hdr(Vstr_base *data, struct Http_hdrs *hdrs,
                               Vstr_sect_node *hdr, size_t pos, size_t len)
{
  Vstr_base *comb = hdrs->multi->comb;
  
  ASSERT(comb);
  
  ASSERT((hdr == hdrs->multi->hdr_accept) ||
         (hdr == hdrs->multi->hdr_accept_charset) ||
         (hdr == hdrs->multi->hdr_accept_encoding) ||
         (hdr == hdrs->multi->hdr_accept_language) ||
         (hdr == hdrs->multi->hdr_connection) ||
         (hdr == hdrs->multi->hdr_if_match) ||
         (hdr == hdrs->multi->hdr_if_none_match));

  ASSERT((comb == data) || (comb == hdrs->multi->combiner_store));
  
  if (hdr->pos && !len) /* just ignore the new addition */
    return (TRUE);
  if ((data == comb) && (!hdr->pos || !hdr->len))
  { /* Do the fast thing... */
    hdr->pos = pos;
    hdr->len = len;
    return (TRUE);
  }

  if (data == comb)
  { /* OK, so we have a crap request and need to JOIN multiple headers... */
    comb = hdrs->multi->comb = hdrs->multi->combiner_store;
  
    if (!http__multi_hdr_cp(comb, data, hdrs->multi->hdr_accept) ||
        !http__multi_hdr_cp(comb, data, hdrs->multi->hdr_accept_charset) ||
        !http__multi_hdr_cp(comb, data, hdrs->multi->hdr_accept_encoding) ||
        !http__multi_hdr_cp(comb, data, hdrs->multi->hdr_accept_language) ||
        !http__multi_hdr_cp(comb, data, hdrs->multi->hdr_connection) ||
        !http__multi_hdr_cp(comb, data, hdrs->multi->hdr_if_match) ||
        !http__multi_hdr_cp(comb, data, hdrs->multi->hdr_if_none_match) ||
        FALSE)
      return (FALSE);
  }
  
  if (!hdr->pos)
  {
    hdr->pos = comb->len + 1;
    hdr->len = len;
    
    return (!hdr->len || vstr_add_vstr(comb, comb->len,
                                       data, pos, len, VSTR_TYPE_ADD_BUF_PTR));
  }

  /* reverses the order, but that doesn't matter */
  if (!vstr_add_cstr_ptr(comb, hdr->pos - 1, ","))
    return (FALSE);
  if (!vstr_add_vstr(comb, hdr->pos - 1,
                     data, pos, len, VSTR_TYPE_ADD_BUF_PTR))
    return (FALSE);
  hdr->len += ++len;

  /* now need to "move" any hdrs after this one */
  pos = hdr->pos - 1;
  http__multi_hdr_fixup(hdr, hdrs->multi->hdr_accept,          pos, len);
  http__multi_hdr_fixup(hdr, hdrs->multi->hdr_accept_charset,  pos, len);
  http__multi_hdr_fixup(hdr, hdrs->multi->hdr_accept_encoding, pos, len);
  http__multi_hdr_fixup(hdr, hdrs->multi->hdr_accept_language, pos, len);
  http__multi_hdr_fixup(hdr, hdrs->multi->hdr_connection,      pos, len);
  http__multi_hdr_fixup(hdr, hdrs->multi->hdr_if_match,        pos, len);
  http__multi_hdr_fixup(hdr, hdrs->multi->hdr_if_none_match,   pos, len);
    
  return (TRUE);
}

/* viprefix, with local knowledge */
static int http__hdr_eq(struct Con *con, size_t pos, size_t len,
                        const char *hdr, size_t hdr_len, size_t *hdr_val_pos)
{
  Vstr_base *data = con->evnt->io_r;

  ASSERT(CLEN(hdr) == hdr_len);
  ASSERT(hdr[hdr_len - 1] == ':');
  
  if (!con->policy->use_hdrs_non_spc)
    --hdr_len;
  
  if ((len < hdr_len) ||
      !vstr_cmp_case_buf_eq(data, pos, hdr_len, hdr, hdr_len))
    return (FALSE);
  len -= hdr_len; pos += hdr_len;

  if (!con->policy->use_hdrs_non_spc)
  {
    HTTP_SKIP_LWS(data, pos, len);
    if (!len)
      return (FALSE);
  
    if (vstr_export_chr(data, pos) != ':')
      return (FALSE);
    --len; ++pos;
  }
  
  *hdr_val_pos = pos;
  
  return (TRUE);
}

/* remove LWS from front and end... what a craptastic std. */
static void http__hdr_fixup(Vstr_base *data, size_t *pos, size_t *len,
                            size_t hdr_val_pos)
{
  size_t tmp = 0;
  
  *len -= hdr_val_pos - *pos; *pos += hdr_val_pos - *pos;
  HTTP_SKIP_LWS(data, *pos, *len);

  /* hand coding for a HTTP_SKIP_LWS() going backwards... */
  while ((tmp = vstr_spn_cstr_chrs_rev(data, *pos, *len, HTTP_LWS)))
  {
    *len -= tmp;
  
    if (VSUFFIX(data, *pos, *len, HTTP_EOL))
      *len -= CLEN(HTTP_EOL);
  }  
}

/* for single headers, multiple ones aren't allowed ...
 * we can do last one wins, or just error (erroring is more secure, see
 * HTTP Request smuggling) */
#define HDR__EQ(x) http__hdr_eq(con, pos, len, x ":", CLEN(x ":"), &hdr_val_pos)

#define HDR__EQ_SET(x, h)                                               \
    else if (HDR__EQ(x)) do                                             \
    {                                                                   \
      if (req->policy->use_hdrs_no_x2 && http_hdrs-> hdr_ ## h ->pos)   \
        HTTPD_ERR_MSG_RET(req, 400, "Double header " x, FALSE);         \
      http__hdr_fixup(data, &pos, &len, hdr_val_pos);                   \
      http_hdrs-> hdr_ ## h ->pos = pos;                                \
      http_hdrs-> hdr_ ## h ->len = len;                                \
    } while (FALSE)
#define HDR__EQ_MULTI_SET(x, h)                                         \
    else if (HDR__EQ(x)) do                                             \
    {                                                                   \
      http__hdr_fixup(data, &pos, &len, hdr_val_pos);                   \
      if (!http__app_multi_hdr(data, http_hdrs,                         \
                               http_hdrs->multi-> hdr_ ## h, pos, len)) \
      {                                                                 \
        req->malloc_bad = TRUE;                                         \
        HTTPD_ERR_MSG_RET(req, 500, "Memory failure", FALSE);           \
      }                                                                 \
    } while (FALSE)
#define HDR__EQ_IGNORE(x, h)                                            \
    else if (HDR__EQ(x)) do                                             \
    {                                                                   \
      if (req->policy->use_hdrs_no_x2 && got_ ## h)                     \
        HTTPD_ERR_MSG_RET(req, 400, "Double header " x, FALSE);         \
      got_ ## h = TRUE;                                                 \
    } while (FALSE)

int http_parse_hdrs(struct Con *con, Httpd_req_data *req)
{
  Vstr_base *data = con->evnt->io_r;
  struct Http_hdrs *http_hdrs = req->http_hdrs;
  unsigned int num = 3; /* skip "method URI version" */
  int got_content_length = FALSE;
  int got_content_lang = FALSE;
  int got_content_type = FALSE;
  int got_transfer_encoding = FALSE;
  
  while (++num <= req->sects->num)
  {
    size_t pos = VSTR_SECTS_NUM(req->sects, num)->pos;
    size_t len = VSTR_SECTS_NUM(req->sects, num)->len;
    size_t hdr_val_pos = 0;

    if (0) { /* nothing */ }
    HDR__EQ_SET("User-Agent",                ua);
    HDR__EQ_SET("Referer",                   referer);
    HDR__EQ_SET("Authorization",             authorization);
    HDR__EQ_SET("Expect",                    expect);
    HDR__EQ_SET("Host",                      host);
    HDR__EQ_SET("If-Modified-Since",         if_modified_since);
    HDR__EQ_SET("If-Range",                  if_range);
    HDR__EQ_SET("If-Unmodified-Since",       if_unmodified_since);
    HDR__EQ_SET("Range",                     range);
    HDR__EQ_SET("X-Moz",                     x_moz);

    /* allow continuations over multiple headers... *sigh* */
    HDR__EQ_MULTI_SET("Accept",              accept);
    HDR__EQ_MULTI_SET("Accept-Charset",      accept_charset);
    HDR__EQ_MULTI_SET("Accept-Encoding",     accept_encoding);
    HDR__EQ_MULTI_SET("Accept-Language",     accept_language);
    HDR__EQ_MULTI_SET("Connection",          connection);
    HDR__EQ_MULTI_SET("If-Match",            if_match);
    HDR__EQ_MULTI_SET("If-None-Match",       if_none_match);

    /* allow a 0 (zero) length content-length, some clients do send these */
    else if (HDR__EQ("Content-Length"))
    {
      unsigned int num_flags = 10 | (VSTR_FLAG_PARSE_NUM_NO_BEG_PM |
                                     VSTR_FLAG_PARSE_NUM_OVERFLOW);
      unsigned int num_val = 0;
      size_t num_len = 0;
      
      if (req->policy->use_hdrs_no_x2 && got_content_length)
        HTTPD_ERR_MSG_RET(req, 400, "Double header Content-Length", FALSE);

      got_content_length = TRUE;
      http__hdr_fixup(data, &pos, &len, hdr_val_pos);

      num_val = vstr_parse_uint(data, pos, len, num_flags, &num_len, NULL);

      if (num_len != len)
        HTTPD_ERR_MSG_RET(req, 400, "Content-Length is not a number", FALSE);
      if (num_val)
        HTTPD_ERR_MSG_RET(req, 413, "Content-Length is not zero", FALSE);
    }
    HDR__EQ_IGNORE("Content-Type",     content_type);
    HDR__EQ_IGNORE("Content-Language", content_lang);
    
    /* in theory ,,identity;foo=bar;baz="zoom",, is ok ... who cares */
    else if (HDR__EQ("Transfer-Encoding"))
    {
      if (req->policy->use_hdrs_no_x2 && got_transfer_encoding)
        HTTPD_ERR_MSG_RET(req, 400, "Double header Transfer-Encoding", FALSE);
      got_transfer_encoding = TRUE;
      http__hdr_fixup(data, &pos, &len, hdr_val_pos);

      if (!VEQ(data, pos, len, "identity")) /* 3.6 says 501 */
        HTTPD_ERR_MSG_RET(req, 501, "Transfer-Encoding is not identity", FALSE);
    }
    else
    { /* we can't x2 check ... as some might be multi headers */
      size_t tmp = 0;

      /* all headers _must_ contain a ':' */
      tmp = vstr_srch_chr_fwd(data, pos, len, ':');
      if (!tmp)
        HTTPD_ERR_MSG_RET(req, 400, "Header does not end with : marker", FALSE);

      /* make sure unknown header is whitespace "valid" */
      tmp = vstr_sc_posdiff(pos, tmp);
      if (req->policy->use_hdrs_non_spc &&
          (vstr_cspn_cstr_chrs_fwd(data, pos, tmp, HTTP_LWS) != tmp))
        HTTPD_ERR_MSG_RET(req, 400, "Header has spaces before : marker", FALSE);
    }
  }

  if (!req->policy->use_hdrs_err_411)
    return (TRUE);
  
  if (got_content_type      && !got_content_length)
    HTTPD_ERR_MSG_RET(req, 411, "Type but no Length", FALSE);
  if (got_content_lang      && !got_content_length)
    HTTPD_ERR_MSG_RET(req, 411, "Language but no Length", FALSE);
  if (got_transfer_encoding && !got_content_length)
    HTTPD_ERR_MSG_RET(req, 411, "Transfer-Encoding but no Length", FALSE);

  return (TRUE);
}
#undef HDR__EQ
#undef HDR__SET
#undef HDR__MUTLI_SET

#define HDR__CON_1_0_FIXUP(name, h)                                     \
    else if (VIEQ(data, pos, tmp, name))                                \
      do {                                                              \
        req -> http_hdrs -> hdr_ ## h ->pos = 0;                        \
        req -> http_hdrs -> hdr_ ## h ->len = 0;                        \
      } while (FALSE)
#define HDR__CON_1_0_MULTI_FIXUP(name, h)                               \
    else if (VIEQ(data, pos, tmp, name))                                \
      do {                                                              \
        req -> http_hdrs -> multi -> hdr_ ## h ->pos = 0;               \
        req -> http_hdrs -> multi -> hdr_ ## h ->len = 0;               \
      } while (FALSE)
void http_parse_connection(struct Con *con, struct Httpd_req_data *req)
{
  Vstr_base *data = req->http_hdrs->multi->comb;
  size_t pos = 0;
  size_t len = 0;
  unsigned int num = 0;
  
  pos = req->http_hdrs->multi->hdr_connection->pos;
  len = req->http_hdrs->multi->hdr_connection->len;

  if (HTTPD_VER_GE_1_1(req))
    con->keep_alive = HTTP_1_1_KEEP_ALIVE;

  if (!len)
    return;

  while (len)
  {
    size_t tmp = vstr_cspn_cstr_chrs_fwd(data, pos, len,
                                         HTTP_EOL HTTP_LWS ",");

    ++num;
    if (HTTPD_VER_GE_1_1(req))
    { /* this is all we have to do for HTTP/1.1 ... proxies understand it */
      if (VIEQ(data, pos, tmp, "close"))
        con->keep_alive = HTTP_NON_KEEP_ALIVE;
    }
    else if (VIEQ(data, pos, tmp, "keep-alive"))
    {
      if (req->policy->use_keep_alive_1_0)
        con->keep_alive = HTTP_1_0_KEEP_ALIVE;
    }
    /* now fixup connection headers for HTTP/1.0 proxies */
    HDR__CON_1_0_FIXUP("User-Agent",          ua);
    HDR__CON_1_0_FIXUP("Referer",             referer);
    HDR__CON_1_0_FIXUP("Authorization",       authorization);
    HDR__CON_1_0_FIXUP("Expect",              expect);
    HDR__CON_1_0_FIXUP("Host",                host);
    HDR__CON_1_0_FIXUP("If-Modified-Since",   if_modified_since);
    HDR__CON_1_0_FIXUP("If-Range",            if_range);
    HDR__CON_1_0_FIXUP("If-Unmodified-Since", if_unmodified_since);
    HDR__CON_1_0_FIXUP("Range",               range);
    HDR__CON_1_0_FIXUP("X-Moz",               x_moz);
    
    HDR__CON_1_0_MULTI_FIXUP("Accept",          accept);
    HDR__CON_1_0_MULTI_FIXUP("Accept-Charset",  accept_charset);
    HDR__CON_1_0_MULTI_FIXUP("Accept-Encoding", accept_encoding);
    HDR__CON_1_0_MULTI_FIXUP("Accept-Language", accept_language);
    HDR__CON_1_0_MULTI_FIXUP("If-Match",        if_match);
    HDR__CON_1_0_MULTI_FIXUP("If-None-Match",   if_none_match);

    /* skip to end, or after next ',' */
    tmp = vstr_cspn_cstr_chrs_fwd(data, pos, len, ",");    
    len -= tmp; pos += tmp;
    if (!len)
      break;
    
    assert(VPREFIX(data, pos, len, ","));
    len -= 1; pos += 1;
    HTTP_SKIP_LWS(data, pos, len);

    if (req->policy->max_connection_nodes &&
        (num >= req->policy->max_connection_nodes))
      return;
  }
}
#undef HDR__CON_1_0_FIXUP
#undef HDR__CON_1_0_MULTI_FIXUP
                                  
/* parse >= 1.0 things like, version and headers */
int http_parse_1_x(struct Con *con, struct Httpd_req_data *req)
{
  ASSERT(!req->ver_0_9);
  
  if (!http_parse_version(con, req))
    return (FALSE);
  
  if (!http_parse_hdrs(con, req))
    return (FALSE);

  if (req->policy->max_requests &&
      (req->policy->max_requests <= con->evnt->acct.req_got) &&
      HTTPD_VER_GE_1_1(req))
    return (TRUE);

  if (!req->policy->use_keep_alive && HTTPD_VER_GE_1_1(req))
    return (TRUE);

  http_parse_connection(con, req);
  
  if (req->policy->max_requests &&
      (req->policy->max_requests <= con->evnt->acct.req_got))
    con->keep_alive = HTTP_NON_KEEP_ALIVE;

  return (TRUE);
}

/* NOTE: allow "1  .  000" or just allow "1.000" ... LWS is craptastic, why
 * not go all the way ? */
#define HTTP__PARSE_CHK_RET_OK() do {                   \
      HTTP_SKIP_LWS(data, pos, len);                    \
                                                        \
      if (!len ||                                       \
          VPREFIX(data, pos, len, ",") ||               \
          (allow_more && VPREFIX(data, pos, len, ";"))) \
      {                                                 \
        *passed_pos = pos;                              \
        *passed_len = len;                              \
                                                        \
        ASSERT(*val <= 1000);                           \
                                                        \
        return (TRUE);                                  \
      }                                                 \
    } while (FALSE)

/* What is the quality parameter, value between 0 and 1000 inclusive.
 * returns TRUE on success, FALSE on failure. */
static int http_parse_quality(Vstr_base *data,
                              size_t *passed_pos, size_t *passed_len,
                              int allow_more, unsigned int *val)
{
  size_t pos = *passed_pos;
  size_t len = *passed_len;
  int lead_zero = FALSE;
  size_t num_len = 0;
  unsigned int parse_flags = VSTR_FLAG02(PARSE_NUM, NO_BEG_PM, NO_NEGATIVE);  
  
  ASSERT(val);
  
  *val = 1000;
  
  HTTP_SKIP_LWS(data, pos, len);

  *passed_pos = pos;
  *passed_len = len;
  
  if (!len || VPREFIX(data, pos, len, ","))
    return (TRUE);

  if (VPREFIX(data, pos, len, ";q=0.")) /* opt */
  {
    len -= strlen(";q=0."); pos += strlen(";q=0.");
    lead_zero = TRUE;
    *val = 0;
  }
  else if (VPREFIX(data, pos, len, ";"))
  {
    len -= 1; pos += 1;
    HTTP_SKIP_LWS(data, pos, len);
    
    if (!VPREFIX(data, pos, len, "q"))
      return (!!allow_more);
    
    len -= 1; pos += 1;
    HTTP_SKIP_LWS(data, pos, len);
    
    if (!VPREFIX(data, pos, len, "="))
      return (!!allow_more);
    
    len -= 1; pos += 1;
    HTTP_SKIP_LWS(data, pos, len);

    /* if it's 0[.00?0?] TRUE, 0[.\d\d?\d?] or 1[.00?0?] is FALSE */
    if (!(lead_zero = VPREFIX(data, pos, len, "0")) &&
        !VPREFIX(data, pos, len, "1"))
      return (FALSE);
    *val = (!lead_zero) * 1000;
    
    len -= 1; pos += 1;
    
    HTTP__PARSE_CHK_RET_OK();

    if (!VPREFIX(data, pos, len, "."))
      return (FALSE);
    
    len -= 1; pos += 1;
  }

  
  HTTP_SKIP_LWS(data, pos, len);
  
  *val += vstr_parse_uint(data, pos, len, 10 | parse_flags, &num_len, NULL);
  if (!num_len || (num_len > 3) || (*val > 1000))
    return (FALSE);
  if (!lead_zero)
    ASSERT(*val == 1000);
  else
  {
    if (num_len < 3) *val *= 10;
    if (num_len < 2) *val *= 10;
  }
  len -= num_len; pos += num_len;
  
  HTTP__PARSE_CHK_RET_OK();
  
  return (FALSE);
}
#undef HTTP__PARSE_CHK_RET_OK

/* return the length of a quoted string (must be >= 2), or 0 on syntax error */
static size_t http__len_quoted_string(const Vstr_base *data,
                                      size_t pos, size_t len)
{
  size_t orig_pos = pos;
  
  if (!VPREFIX(data, pos, len, "\""))
    return (0);
  
  len -= 1; pos += 1;

  while (TRUE)
  {
    size_t tmp = vstr_cspn_cstr_chrs_fwd(data, pos, len, "\"\\");
    
    len -= tmp; pos += tmp;
    if (!len)
      return (0);
    
    if (vstr_export_chr(data, pos) == '"')
      return (vstr_sc_posdiff(orig_pos, pos));
    
    ASSERT(vstr_export_chr(data, pos) == '\\');
    if (len < 3) /* must be at least <\X"> */
      return (0);
    len -= 2; pos += 2;
  }

  assert_ret(FALSE, 0);
}

/* skip a quoted string, or fail on syntax error */
static int http__skip_quoted_string(const Vstr_base *data,
                                    size_t *pos, size_t *len)
{
  size_t qlen = http__len_quoted_string(data, *pos, *len);

  assert(VPREFIX(data, *pos, *len, "\""));
  
  if (!qlen)
    return (FALSE);
  
  *len -= qlen; *pos += qlen;

  HTTP_SKIP_LWS(data, *pos, *len);
  return (TRUE);
}

/* match non-week entity tags in both strings, return true if any match
 * only allow non-weak entity tags if allow_weak = FALSE */
int httpd_match_etags(struct Httpd_req_data *req,
                      const Vstr_base *hdr, size_t hpos, size_t hlen,
                      const Vstr_base *vs1, size_t epos, size_t elen,
                      int allow_weak)
{
  int need_comma = FALSE;

  ASSERT(hdr);
  
  if (!vs1)
    return (FALSE);
  
  while (hlen)
  {
    int weak = FALSE;
    size_t htlen = 0;

    if (vstr_export_chr(hdr, hpos) == ',')
    {
      hlen -= 1; hpos += 1;
      HTTP_SKIP_LWS(hdr, hpos, hlen);
      need_comma = FALSE;
      continue;
    }
    else if (need_comma)
      return (FALSE);
    
    if (VPREFIX(hdr, hpos, hlen, "W/"))
    {
      weak = TRUE;
      hlen -= CLEN("W/"); hpos += CLEN("W/");
    }
    if (!(htlen = http__len_quoted_string(hdr, hpos, hlen)))
      return (FALSE);

    if (allow_weak || !weak)
    {
      size_t orig_epos = epos;
      size_t orig_elen = elen;
      unsigned int num = 0;
      
      while (elen)
      {
        size_t etlen = 0;

        if (vstr_export_chr(vs1, epos) == ',')
        {
          elen -= 1; epos += 1;
          HTTP_SKIP_LWS(vs1, epos, elen);
          need_comma = FALSE;
          continue;
        }
        else if (need_comma)
          return (FALSE);

        ++num;
        
        if (!VPREFIX(vs1, epos, elen, "W/"))
          weak = FALSE;
        else
        {
          weak = TRUE;
          elen -= CLEN("W/"); epos += CLEN("W/");
        }
        if (!(etlen = http__len_quoted_string(vs1, epos, elen)))
          return (FALSE);
        
        if ((allow_weak || !weak) &&
            vstr_cmp_eq(hdr, hpos, htlen, vs1, epos, etlen))
          return (TRUE);
        
        elen -= etlen; epos += etlen;
        HTTP_SKIP_LWS(vs1, epos, elen);
        need_comma = TRUE;
        
        if (req->policy->max_etag_nodes && (num >= req->policy->max_etag_nodes))
          return (FALSE);
      }

      epos = orig_epos;
      elen = orig_elen;
    }

    hlen -= htlen; hpos += htlen;
    HTTP_SKIP_LWS(hdr, hpos, hlen);
    need_comma = TRUE;
  }

  return (FALSE);
}

/* skip, or fail on syntax error */
static int http__skip_parameters(Vstr_base *data, size_t *pos, size_t *len)
{
  while (*len && (vstr_export_chr(data, *pos) != ','))
  { /* skip parameters */
    size_t tmp = 0;
    
    if (vstr_export_chr(data, *pos) != ';')
      return (FALSE); /* syntax error */
    
    *len -= 1; *pos += 1;
    HTTP_SKIP_LWS(data, *pos, *len);
    tmp = vstr_cspn_cstr_chrs_fwd(data, *pos, *len, ";,=");
    *len -= tmp; *pos += tmp;
    if (!*len)
      break;
    
    switch (vstr_export_chr(data, *pos))
    {
      case ';': break;
      case ',': break;
        
      case '=': /* skip parameter value */
        *len -= 1; *pos += 1;
        HTTP_SKIP_LWS(data, *pos, *len);
        if (!*len)
          return (FALSE); /* syntax error */
        if (vstr_export_chr(data, *pos) == '"')
        {
          if (!http__skip_quoted_string(data, pos, len))
            return (FALSE); /* syntax error */
        }
        else
        {
          tmp = vstr_cspn_cstr_chrs_fwd(data, *pos, *len, ";,");
          *len -= tmp; *pos += tmp;
        }
        break;
    }
  }

  return (TRUE);
}

/* returns quality of the passed content-type in the "Accept:" header,
 * if it isn't there or we get a syntax error we return 1001 for not avilable */
unsigned int http_parse_accept(Httpd_req_data *req,
                               const Vstr_base *ct_vs1,
                               size_t ct_pos, size_t ct_len)
{
  Vstr_base *data = req->http_hdrs->multi->comb;
  size_t pos = 0;
  size_t len = 0;
  unsigned int num = 0;
  unsigned int quality = 1001;
  unsigned int dummy   = 1001;
  int done_sub_type = FALSE;
  size_t ct_sub_len = 0;
  
  pos = req->http_hdrs->multi->hdr_accept->pos;
  len = req->http_hdrs->multi->hdr_accept->len;
  
  if (!len) /* no accept == accept all */
    return (1000);

  ASSERT(ct_vs1);
    
  if (!(ct_sub_len = vstr_srch_chr_fwd(ct_vs1, ct_pos, ct_len, '/')))
  { /* it's too weird, blank it */
    if (ct_vs1 == req->content_type_vs1)
      req->content_type_vs1 = NULL;
    return (1);
  }
  ct_sub_len = vstr_sc_posdiff(ct_pos, ct_sub_len);
  
  while (len)
  {
    size_t tmp = vstr_cspn_cstr_chrs_fwd(data, pos, len,
                                         HTTP_EOL HTTP_LWS ";,");

    ++num;
    
    if (0) { }
    else if (vstr_cmp_eq(data, pos, tmp, ct_vs1, ct_pos, ct_len))
    { /* full match */
      len -= tmp; pos += tmp;
      if (!http_parse_quality(data, &pos, &len, TRUE, &quality))
        return (1);
      return (quality);
    }
    else if ((tmp == (ct_sub_len + 1)) &&
             vstr_cmp_eq(data, pos, ct_sub_len, ct_vs1, ct_pos, ct_sub_len) &&
             (vstr_export_chr(data, vstr_sc_poslast(pos, tmp)) == '*'))
    { /* sub match */
      len -= tmp; pos += tmp;
      if (!http_parse_quality(data, &pos, &len, TRUE, &quality))
        return (1);
      done_sub_type = TRUE;
    }
    else if (!done_sub_type && VEQ(data, pos, tmp, "*/*"))
    {
      len -= tmp; pos += tmp;
      if (!http_parse_quality(data, &pos, &len, TRUE, &quality))
        return (1);
    }
    else
    {
      len -= tmp; pos += tmp;
      if (!http_parse_quality(data, &pos, &len, TRUE, &dummy))
        return (1);
    }

    if (!http__skip_parameters(data, &pos, &len))
      return (1);
    if (!len)
      break;
    
    assert(VPREFIX(data, pos, len, ","));
    len -= 1; pos += 1;
    HTTP_SKIP_LWS(data, pos, len);
    
    if (req->policy->max_A_nodes && (num >= req->policy->max_A_nodes))
      return (1);
  }

  ASSERT(quality <= 1001);
  if (quality == 1001)
    return (0);
  
  return (quality);
}

static int http__cmp_lang_eq(const Vstr_base *s1, size_t p1, size_t l1,
                             const Vstr_base *s2, size_t p2, size_t l2)
{
  if (l1 == l2)
    return (FALSE);
  
  if (l1 > l2)
    return ((vstr_export_chr(s1, p1 + l2) == '-') &&
            vstr_cmp_case_eq(s1, p1, l2, s2, p2, l2));

  return ((vstr_export_chr(s2, p2 + l1) == '-') &&
          vstr_cmp_case_eq(s1, p1, l1, s2, p2, l1));
}

unsigned int http_parse_accept_language(Httpd_req_data *req,
                                        const Vstr_base *ct_vs1,
                                        size_t ct_pos, size_t ct_len)
{
  Vstr_base *data = req->http_hdrs->multi->comb;
  size_t pos = 0;
  size_t len = 0;
  unsigned int num = 0;
  unsigned int quality = 1001;
  unsigned int dummy   = 1001;
  size_t done_sub_type = 0;
  
  pos = req->http_hdrs->multi->hdr_accept_language->pos;
  len = req->http_hdrs->multi->hdr_accept_language->len;
  
  if (!len) /* no accept-language == accept all */
    return (1000);

  ASSERT(ct_vs1);
  while (len)
  {
    size_t tmp = vstr_cspn_cstr_chrs_fwd(data, pos, len,
                                         HTTP_EOL HTTP_LWS ";,");

    ++num;
    
    if (0) { }
    else if (vstr_cmp_case_eq(data, pos, tmp, ct_vs1, ct_pos, ct_len))
    { /* full match */
      len -= tmp; pos += tmp;
      if (!http_parse_quality(data, &pos, &len, FALSE, &quality))
        return (1);
      return (quality);
    }
    else if ((tmp >= done_sub_type) &&
             http__cmp_lang_eq(data, pos, tmp, ct_vs1, ct_pos, ct_len))
    { /* sub match - can be x-y-A;q=0, x-y-B, x-y
         rfc2616#14.4
         The language quality factor assigned to a language-tag by the
         Accept-Language field is the quality value of the longest
         language-range in the field that matches the language-tag.
      */
      unsigned int sub_type_qual = 0;
      
      len -= tmp; pos += tmp;
      if (!http_parse_quality(data, &pos, &len, FALSE, &sub_type_qual))
        return (1);
      
      ASSERT(sub_type_qual <= 1000);
      if ((tmp > done_sub_type) || (sub_type_qual > quality))
        quality = sub_type_qual;
      
      done_sub_type = tmp;
    }
    else if (!done_sub_type && VEQ(data, pos, tmp, "*"))
    {
      len -= tmp; pos += tmp;
      if (!http_parse_quality(data, &pos, &len, FALSE, &quality))
        return (1);
    }
    else
    {
      len -= tmp; pos += tmp;
      if (!http_parse_quality(data, &pos, &len, FALSE, &dummy))
        return (1);
    }
    
    if (!len)
      break;
    
    assert(VPREFIX(data, pos, len, ","));
    len -= 1; pos += 1;
    HTTP_SKIP_LWS(data, pos, len);
    
    if (req->policy->max_AL_nodes && (num >= req->policy->max_AL_nodes))
      return (1);
  }

  ASSERT(quality <= 1001);
  if (quality == 1001)
    return (0);
  
  return (quality);
}

int http_parse_accept_encoding(struct Httpd_req_data *req, int force)
{
  Vstr_base *data = req->http_hdrs->multi->comb;
  size_t pos = 0;
  size_t len = 0;
  unsigned int num = 0;
  unsigned int star_val     = 1001;
  unsigned int dummy_val    = 1001;

  pos = req->http_hdrs->multi->hdr_accept_encoding->pos;
  len = req->http_hdrs->multi->hdr_accept_encoding->len;

  if (!force && !req->policy->use_err_406 && !req->allow_accept_encoding)
    return (FALSE);

  if (!force)
    req->vary_ae = TRUE;
  
  if (req->parsed_content_encoding)
  {
    if (!req->allow_accept_encoding)
      return (FALSE);

    return (!!req->content_enc_gzip || !!req->content_enc_bzip2);
  }
  
  req->parsed_content_encoding = TRUE;
  
  if (!len)
    goto parse_err;
  
  req->content_encoding_xgzip = FALSE;
  req->content_enc_identity   = 1001;
  req->content_enc_gzip       = 1001;
  req->content_enc_bzip2      = 1001;
  
  while (len)
  {
    size_t tmp = vstr_cspn_cstr_chrs_fwd(data, pos, len,
                                         HTTP_EOL HTTP_LWS ";,");

    ++num;
    
    if (0) { }
    else if (VEQ(data, pos, tmp, "identity"))
    {
      len -= tmp; pos += tmp;
      if (!http_parse_quality(data, &pos, &len, FALSE,
                              &req->content_enc_identity))
        goto parse_err;
    }
    else if (VEQ(data, pos, tmp, "gzip"))
    {
      len -= tmp; pos += tmp;
      req->content_encoding_xgzip = FALSE;
      if (!http_parse_quality(data, &pos, &len, FALSE, &req->content_enc_gzip))
        goto parse_err;
    }
    else if (VEQ(data, pos, tmp, "bzip2"))
    {
      len -= tmp; pos += tmp;
      if (!http_parse_quality(data, &pos, &len, FALSE, &req->content_enc_bzip2))
        goto parse_err;
    }
    else if (VEQ(data, pos, tmp, "x-gzip"))
    {
      len -= tmp; pos += tmp;
      req->content_encoding_xgzip = TRUE;
      if (!http_parse_quality(data, &pos, &len, FALSE, &req->content_enc_gzip))
        goto parse_err; /* ignore quality on x-gzip - just parse for errors */
      req->content_enc_gzip = 1000;
    }
    else if (VEQ(data, pos, tmp, "*"))
    { /* "*;q=0,gzip" means TRUE ... and "*;q=1.0,gzip;q=0" means FALSE */
      len -= tmp; pos += tmp;
      if (!http_parse_quality(data, &pos, &len, FALSE, &star_val))
        goto parse_err;
    }
    else
    {
      len -= tmp; pos += tmp;
      if (!http_parse_quality(data, &pos, &len, FALSE, &dummy_val))
        goto parse_err;
    }
    
    if (!len)
      break;
    assert(VPREFIX(data, pos, len, ","));
    len -= 1; pos += 1;
    HTTP_SKIP_LWS(data, pos, len);

    if (req->policy->max_AE_nodes && (num >= req->policy->max_AE_nodes))
      goto parse_err;
  }
  
  if (req->content_enc_gzip     == 1001) req->content_enc_gzip     = star_val;
  if (req->content_enc_bzip2    == 1001) req->content_enc_bzip2    = star_val;
  if (req->content_enc_identity == 1001) req->content_enc_identity = star_val;

  if (req->content_enc_gzip     == 1001) req->content_enc_gzip     = 0;
  if (req->content_enc_bzip2    == 1001) req->content_enc_bzip2    = 0;
  if (req->content_enc_identity == 1001) req->content_enc_identity = 1;
  
  if (!req->allow_accept_encoding)
    return (FALSE);

  if ((req->content_enc_identity > req->content_enc_gzip) &&
      (req->content_enc_identity > req->content_enc_bzip2))
    goto parse_err; /* this is insane, but legal */

  req->content_encoding_identity = !!req->content_enc_identity;
  req->content_encoding_gzip     = !!req->content_enc_gzip;
  req->content_encoding_bzip2    = !!req->content_enc_bzip2;
    
  return (!!req->content_enc_gzip || !!req->content_enc_bzip2);
  
 parse_err:
  req->content_enc_identity = 1;
  req->content_enc_gzip     = 0;
  req->content_enc_bzip2    = 0;

  req->content_encoding_identity = !!req->content_enc_identity;
  req->content_encoding_gzip     = !!req->content_enc_gzip;
  req->content_encoding_bzip2    = !!req->content_enc_bzip2;
  req->content_encoding_xgzip    = FALSE;
    
  return (FALSE);
}

/* try to use gzip content-encoding on entity */
static int http__try_encoded_content(struct Con *con, Httpd_req_data *req,
                                     const struct stat64 *req_f_stat,
                                     off64_t *req_f_stat_st_size,
                                     Vstr_base *fname,
                                     const char *zip_ext, size_t zip_len)
{
  const char *fname_cstr = NULL;
  int fd = -1;
  int ret = FALSE;
  int open_flags = O_NONBLOCK;

  ASSERT(con->fs && !con->fs_num && !con->fs_off);
  ASSERT(con->fs->len == (uintmax_t)req_f_stat->st_size);

  if (req_f_stat->st_size < HTTPD_CONF_ZIP_LIMIT_MIN) /* minor opt. */
    return (ret);
  
  if (req->policy->use_noatime)
    open_flags |= O_NOATIME;
    
  vstr_add_cstr_ptr(fname, fname->len, zip_ext);
  fname_cstr = vstr_export_cstr_ptr(fname, 1, fname->len);
  
  if (fname->conf->malloc_bad)
    vlg_warn(vlg, "Failed to export cstr for '%s'\n", zip_ext);
  else if ((fd = io__open(fname_cstr, open_flags)) == -1)
  { /* no encoded version */ }
  else
  {
    struct stat64 f_stat[1];
    
    if (fstat64(fd, f_stat) == -1)
      vlg_warn(vlg, "fstat: %m\n");
    else if ((req->policy->use_public_only && !(f_stat->st_mode & S_IROTH)) ||
             (S_ISDIR(f_stat->st_mode)) || (!S_ISREG(f_stat->st_mode)) ||
             (req_f_stat->st_mtime >  f_stat->st_mtime) ||
             !f_stat->st_size || /* zero sized compressed files aren't valid */
             (*req_f_stat_st_size  <= f_stat->st_size))
    { /* ignore the encoded version */ }
    else
    {
      /* swap, close the old fd (later) and use the new */
      SWAP_TYPE(con->fs->fd, fd, int);
      
      /* _only_ copy the new size over, mtime etc. is from the original file */
      con->fs->len = *req_f_stat_st_size = f_stat->st_size;
      req->encoded_mtime = f_stat->st_mtime;
      ret = TRUE;
    }
    close(fd);
  }

  if (!ret)
    vstr_sc_reduce(fname, 1, fname->len, zip_len);

  return (ret);
}  

void httpd_parse_sc_try_fd_encoding(struct Con *con, Httpd_req_data *req,
                                    const struct stat64 *fs,
                                    off64_t *req_f_stat_st_size,
                                    Vstr_base *fname)
{ /* Might normally add "!req->head_op && ..." but
   * http://www.w3.org/TR/chips/#gl6 says that's bad */
  if (http_parse_accept_encoding(req, FALSE))
  {
    if (req->content_enc_bzip2 >= req->content_enc_gzip)
    { /* try bzip2, then gzip */
      if (req->content_encoding_bzip2 &&
          !http__try_encoded_content(con, req, fs, req_f_stat_st_size,
                                     fname, ".bz2", CLEN(".bz2")))
        req->content_encoding_bzip2 = FALSE;

      if (req->content_encoding_bzip2) req->content_encoding_gzip = FALSE;

      if (req->content_encoding_gzip &&
          !http__try_encoded_content(con, req, fs, req_f_stat_st_size,
                                     fname, ".gz", CLEN(".gz")))
        req->content_encoding_gzip = FALSE;
    }
    else
    { /* try gzip, then bzip2 */
      if (req->content_encoding_gzip &&
          !http__try_encoded_content(con, req, fs, req_f_stat_st_size,
                                     fname, ".gz", CLEN(".gz")))
        req->content_encoding_gzip = FALSE;

      if (req->content_encoding_gzip) req->content_encoding_bzip2 = FALSE;

      if (req->content_encoding_bzip2 &&
          !http__try_encoded_content(con, req, fs, req_f_stat_st_size,
                                     fname, ".bz2", CLEN(".bz2")))
        req->content_encoding_bzip2 = FALSE;
    }

    /* both can't be on ... one, the other or neither */
    ASSERT(!req->content_encoding_bzip2 || !req->content_encoding_gzip);
  }
}

static int httpd__file_sect_add(struct Con *con, Httpd_req_data *req,
                                uintmax_t range_beg, uintmax_t range_end)
{
  struct File_sect *fs = NULL;
    
  ASSERT(con->fs && (con->fs_sz >= 1));
  
  if (req->policy->max_range_nodes <= con->fs_num)
    return (FALSE); /* done at start so we don't allocate anything needlessly */
  
  if (!con->fs_num)
  {
    ASSERT((con->fs == con->fs_store) || (con->fs_sz > 1));
    ASSERT(!con->use_mpbr);

    goto file_sect_add;
  }

  con->use_mpbr = TRUE;
  
  if (con->fs == con->fs_store)
  {
    ASSERT(con->fs_num == 1);

    if (!(con->mpbr_ct = vstr_make_base(con->evnt->io_w->conf)))
      return (FALSE);
    
    if (!(fs = MK(sizeof(struct File_sect) * 16)))
      return (FALSE);
    con->fs    = fs;
    con->fs_sz = 16;
    
    con->fs->fd  = con->fs_store->fd;
    con->fs->off = con->fs_store->off;
    con->fs->len = con->fs_store->len;
    ++fs;
  }
  else if (con->fs_num >= con->fs_sz)
  {
    unsigned int num = (con->fs_sz << 1) + 1;
    
    ASSERT(con->fs_num == con->fs_sz);
  
    if (!MV(con->fs, fs, sizeof(struct File_sect) * num))
      return (FALSE);
    con->fs_sz = num;
  }

 file_sect_add:
  fs = con->fs + con->fs_num++;

  fs->fd  = con->fs->fd; /* copy to each one */
  fs->off = range_beg;
  fs->len = (range_end - range_beg) + 1;

  if ((req->fs_len + fs->len) < req->fs_len)
    return (FALSE);

  req->fs_len += fs->len;
  
  return (TRUE);
}

/* Allow...
   bytes=NUM-NUM
   bytes=-NUM
   bytes=NUM-
   ...and due to LWS, http crapola parsing, even...
   bytes = , , NUM - NUM , ,
   ...allowing ability to disable multiple ranges at once, due to
   multipart/byteranges being too much crack, I think this is stds. compliant.
 */
int http_parse_range(struct Con *con, Httpd_req_data *req)
{
  Vstr_base *data     = con->evnt->io_r;
  Vstr_sect_node *h_r = req->http_hdrs->hdr_range;
  size_t pos = h_r->pos;
  size_t len = h_r->len;
  uintmax_t fsize = req->f_stat_st_size;
  unsigned int num_flags = 10 | (VSTR_FLAG_PARSE_NUM_NO_BEG_PM |
                                 VSTR_FLAG_PARSE_NUM_OVERFLOW);
  size_t num_len = 0;
  
  if (!VPREFIX(data, pos, len, "bytes"))
    return (0);
  len -= CLEN("bytes"); pos += CLEN("bytes");

  HTTP_SKIP_LWS(data, pos, len);
  
  if (!VPREFIX(data, pos, len, "="))
    return (0);
  len -= CLEN("="); pos += CLEN("=");

  http_parse_skip_blanks(data, &pos, &len);
  
  while (len)
  {
    uintmax_t range_beg = 0;
    uintmax_t range_end = 0;
    
    if (VPREFIX(data, pos, len, "-"))
    { /* num bytes at end */
      uintmax_t tmp = 0;

      len -= CLEN("-"); pos += CLEN("-");
      HTTP_SKIP_LWS(data, pos, len);

      tmp = vstr_parse_uintmax(data, pos, len, num_flags, &num_len, NULL);
      len -= num_len; pos += num_len;
      if (!num_len)
        return (0);

      if (!tmp)
        return (416);
    
      if (tmp >= fsize)
        return (0);
    
      range_beg = fsize - tmp;
      range_end = fsize - 1;
    }
    else
    { /* offset - [end] */
      range_beg = vstr_parse_uintmax(data, pos, len, num_flags, &num_len, NULL);
      len -= num_len; pos += num_len;
      HTTP_SKIP_LWS(data, pos, len);
    
      if (!VPREFIX(data, pos, len, "-"))
        return (0);
      len -= CLEN("-"); pos += CLEN("-");
      HTTP_SKIP_LWS(data, pos, len);

      if (!len || VPREFIX(data, pos, len, ","))
        range_end = fsize - 1;
      else
      {
        range_end = vstr_parse_uintmax(data, pos, len, num_flags, &num_len, 0);
        len -= num_len; pos += num_len;
        if (!num_len)
          return (0);
      
        if (range_end >= fsize)
          range_end = fsize - 1;
      }
    
      if ((range_beg >= fsize) || (range_beg > range_end))
        return (416);
    
      if ((range_beg == 0) && 
          (range_end == (fsize - 1)))
        return (0);
    }
  
    http_parse_skip_blanks(data, &pos, &len);

    if (!httpd__file_sect_add(con, req, range_beg, range_end))
      return (0); /* after all that, ignore if there is more than one range */
  }

  return (200);
}

/* because we only parse for a combined CRLF, and some proxies/clients parse for
 * either ... make sure we don't have embedded singles which could cause
 * response splitting */
static int http__chk_single_crlf(Vstr_base *data, size_t pos, size_t len)
{
  if (vstr_srch_chr_fwd(data, pos, len, '\r'))
    return ('\r');
  
  if (vstr_srch_chr_fwd(data, pos, len, '\n'))
    return ('\n');

  return (0);
}

unsigned short httpd_parse_host_port(Vstr_base *s1, size_t pos, size_t len)
{
  unsigned int num_flags = 10 | (VSTR_FLAG_PARSE_NUM_NO_BEG_PM |
                                 VSTR_FLAG_PARSE_NUM_OVERFLOW);
  size_t num_len = 0;
  unsigned short port = 0;
  
  ASSERT(vstr_export_chr(s1, pos) == ':');
  
  len -= 1; pos += 1; /* skip the ':' */
  port = vstr_parse_ushort(s1, pos, len, num_flags, &num_len, NULL);
  
  if (!port || (num_len != len))
    return (0);

  return (port);
}

/* convert a http://abcd/foo into /foo with host=abcd ...
 * also do sanity checking on the URI and host for valid characters */
int http_parse_host(struct Con *con, struct Httpd_req_data *req)
{
  Vstr_base *data = con->evnt->io_r;
  size_t op_pos = req->path_pos;
  size_t op_len = req->path_len;
  
  /* HTTP/1.1 requires a host -- allow blank hostnames */
  if (req->ver_1_1 && !req->http_hdrs->hdr_host->pos)
    HTTPD_ERR_MSG_RET(req, 400, "Hostname is required in 1.1", FALSE);
  
  /* check for absolute URIs */
  if (VIPREFIX(data, op_pos, op_len, "http://"))
  { /* ok, be forward compatible */
    size_t tmp = CLEN("http://");
    
    op_len -= tmp; op_pos += tmp;
    tmp = vstr_srch_chr_fwd(data, op_pos, op_len, '/');
    if (!tmp)
    {
      HTTP__HDR_SET(req, host, op_pos, op_len);
      op_len = 1;
      --op_pos;
    }
    else
    { /* found end of host ... */
      size_t host_len = tmp - op_pos;
      
      HTTP__HDR_SET(req, host, op_pos, host_len);
      op_len -= host_len; op_pos += host_len;
    }
    assert(VPREFIX(data, op_pos, op_len, "/"));
  }

  if (req->ver_1_x && !req->http_hdrs->hdr_host->pos)
    HTTPD_ERR_MSG_RET(req, 400,
                      "Hostname or Absolute URL is required in 1.x", FALSE);
  
  if (req->http_hdrs->hdr_host->len)
  { /* check host looks valid ... header must exist, but can be empty */
    size_t pos = req->http_hdrs->hdr_host->pos;
    size_t len = req->http_hdrs->hdr_host->len;
    size_t tmp = 0;

    /* leaving out most checks for ".." or invalid chars in hostnames etc.
       as the default filename checks should catch them.
       Note: "Host: ." is also caught by default due to the check for /./
       Note: There are also optional checks in http__valid_hostname()
     */

    /*  Check for Host header with extra / ...
     * Ie. only allow a single directory name.
     *  We could just leave this (it's not a security check, /../ is checked
     * for at filepath time), but I feel like being anal and this way there
     * aren't multiple urls to a single path. */
    if (vstr_srch_chr_fwd(data, pos, len, '/'))
      HTTPD_ERR_MSG_RET(req, 400, "Hostname contains /", FALSE);

    switch (http__chk_single_crlf(data, pos, len))
    {
      case '\r':
        HTTPD_ERR_MSG_RET(req, 400, "Hostname contains \\r", FALSE);
      case '\n':
        HTTPD_ERR_MSG_RET(req, 400, "Hostname contains \\n", FALSE);
      case 0:
        ASSERT_NO_SWITCH_DEF();
    }

    if ((tmp = vstr_srch_chr_fwd(data, pos, len, ':')))
    { /* NOTE: not sure if we have to 400 if the port doesn't match
       * or if it's an "invalid" port number (Ie. == 0 || > 65535) */
      len -= tmp - pos; pos = tmp;

      if (!VEQ(data, pos, len, ":"))
        if (!(req->http_host_port = httpd_parse_host_port(data, pos, len)))
          HTTPD_ERR_MSG_RET(req, 400, "Port is not a valid number", FALSE);
        
      req->http_hdrs->hdr_host->len -= len;
    }
  }

  switch (http__chk_single_crlf(data, op_pos, op_len))
  {
    case '\r':
      HTTPD_ERR_MSG_RET(req, 400, "Path contains \\r", FALSE);
    case '\n':
      HTTPD_ERR_MSG_RET(req, 400, "Path contains \\n", FALSE);
    case 0:
      ASSERT_NO_SWITCH_DEF();
  }
  
  /* uri#fragment ... craptastic clients pass this and assume it is ignored */
  if (req->policy->remove_url_frag)
    op_len = vstr_cspn_cstr_chrs_fwd(data, op_pos, op_len, "#");
  /* uri?foo ... This is "ok" to pass, however if you move dynamic
   * resources to static ones you need to do this */
  if (req->policy->remove_url_query)
    op_len = vstr_cspn_cstr_chrs_fwd(data, op_pos, op_len, "?");
  
  req->path_pos = op_pos;
  req->path_len = op_len;
  
  return (TRUE);
}

void http_parse_skip_blanks(Vstr_base *data,
                            size_t *passed_pos, size_t *passed_len)
{
  size_t pos = *passed_pos;
  size_t len = *passed_len;
  
  HTTP_SKIP_LWS(data, pos, len);
  while (VPREFIX(data, pos, len, ",")) /* http crack */
  {
    len -= CLEN(","); pos += CLEN(",");
    HTTP_SKIP_LWS(data, pos, len);
  }

  *passed_pos = pos;
  *passed_len = len;
}

static int http_parse_wait_io_r(struct Con *con)
{
  if (con->evnt->io_r_shutdown)
    return (!!con->evnt->io_w->len);

  /* so we aren't acting under the req policy anymore */
  httpd_policy_change_con(con, con->policy);
  
  evnt_poll->wait_cntl_add(con->evnt, POLLIN);
  evnt_fd_set_cork(con->evnt, FALSE);
  
  return (TRUE);
}

static int httpd_serv__parse_no_req(struct Con *con, struct Httpd_req_data *req)
{
  if (req->policy->max_header_sz &&
      (con->evnt->io_r->len > req->policy->max_header_sz))
  {
    evnt_got_pkt(con->evnt);
    HTTPD_ERR_MSG_RET(req, 400, "Too big", http_fin_err_req(con, req));
  }
  
  http_req_free(req);
  
  return (http_parse_wait_io_r(con));
}

/* http spec says ignore leading LWS ... *sigh* */
static int http__parse_req_all(struct Con *con, struct Httpd_req_data *req,
                               const char *eol, int *ern)
{
  Vstr_base *data = con->evnt->io_r;
  size_t pos = 0;
  
  ASSERT(eol && ern);
  
  *ern = FALSE;

  /* should use vstr_del(data, 1, vstr_spn_cstr_buf_fwd(..., HTTP_EOL)); */
  /* NOTE: eol might be HTTP_END_OF_REQUEST, so need to do this first *sigh* */
  while (VPREFIX(data, 1, data->len, HTTP_EOL))
    vstr_del(data, 1, CLEN(HTTP_EOL));

  ASSERT(!req->len);
  if (!(pos = vstr_srch_cstr_buf_fwd(data, 1, data->len, eol)))
      goto no_req;

  req->len = pos + CLEN(eol) - 1; /* add rest of EOL */

  return (TRUE);

 no_req:
  *ern = httpd_serv__parse_no_req(con, req);
  return (FALSE);
}

int http_parse_req(struct Con *con)
{
  Vstr_base *data = con->evnt->io_r;
  struct Httpd_req_data *req = NULL;
  int ern_req_all = FALSE;

  ASSERT(con->fs && !con->fs_num);

  if (!data->len)
    return (http_parse_wait_io_r(con));
  
  if (!(req = http_req_make(con)))
    return (FALSE);

  if (!req->policy->allow_http_0_9)
    con->parsed_method_ver_1_0 = TRUE;

  if (con->parsed_method_ver_1_0)
  { /* wait for all the headers */
    if (!http__parse_req_all(con, req, HTTP_END_OF_REQUEST, &ern_req_all))
      return (ern_req_all);
  }
  else
  {
    if (!http__parse_req_all(con, req, HTTP_EOL,            &ern_req_all))
      return (ern_req_all);
  }

  con->keep_alive = HTTP_NON_KEEP_ALIVE;
  http_req_split_method(con, req);
  if (req->sects->malloc_bad)
  {
    evnt_got_pkt(con->evnt);
    VLG_WARNNOMEM_RET(http_fin_errmem_req(con, req), (vlg, "split: %m\n"));
  }
  else if ((req->sects->num < 2) ||
           (!req->policy->allow_http_0_9 && (req->sects->num < 3)))
  {
    evnt_got_pkt(con->evnt);
    HTTPD_ERR_MSG_RET(req, 400, "Bad request line", http_fin_err_req(con, req));
  }
  else
  {
    size_t op_pos = 0;
    size_t op_len = 0;

    if (req->ver_0_9)
      vlg_dbg1(vlg, "Method(0.9):"
               " $<http-esc.vstr.sect:%p%p%u> $<http-esc.vstr.sect:%p%p%u>\n",
               con->evnt->io_r, req->sects, 1U,
               con->evnt->io_r, req->sects, 2U);
    else
    { /* need to get all headers */
      if (!con->parsed_method_ver_1_0)
      { /* req line isn't 0.9 ... so must continue to be */
        con->parsed_method_ver_1_0 = TRUE;
        req->len = 0;
        if (!http__parse_req_all(con, req, HTTP_END_OF_REQUEST, &ern_req_all))
          return (ern_req_all);
      }
      
      vlg_dbg1(vlg, "Method(1.x):"
               " $<http-esc.vstr.sect:%p%p%u> $<http-esc.vstr.sect:%p%p%u>"
               " $<http-esc.vstr.sect:%p%p%u>\n", data, req->sects, 1U,
               data, req->sects, 2U, data, req->sects, 3U);

      /* put this up here so errors don't get DATA */
      op_pos        = VSTR_SECTS_NUM(req->sects, 1)->pos;
      op_len        = VSTR_SECTS_NUM(req->sects, 1)->len;
      if (VEQ(data, op_pos, op_len, "HEAD"))
        req->head_op = TRUE;
    
      http_req_split_hdrs(con, req);
    }
    evnt_got_pkt(con->evnt);

    if (HTTP_CONF_SAFE_PRINT_REQ)
      vlg_dbg3(vlg, "REQ:\n$<vstr.hexdump:%p%zu%zu>",
               data, (size_t)1, req->len);
    else
      vlg_dbg3(vlg, "REQ:\n$<vstr:%p%zu%zu>", data, (size_t)1, req->len);
    
    assert(((req->sects->num >= 3) && !req->ver_0_9) || (req->sects->num == 2));
    
    op_pos        = VSTR_SECTS_NUM(req->sects, 1)->pos;
    op_len        = VSTR_SECTS_NUM(req->sects, 1)->len;
    req->path_pos = VSTR_SECTS_NUM(req->sects, 2)->pos;
    req->path_len = VSTR_SECTS_NUM(req->sects, 2)->len;

    if (!req->ver_0_9 && !http_parse_1_x(con, req))
    {
      if (req->error_code == 500)
        return (http_fin_errmem_req(con, req));
      return (http_fin_err_req(con, req));
    }
    
    if (!http_parse_host(con, req))
      return (http_fin_err_req(con, req));

    if (0) { }
    else if (VEQ(data, op_pos, op_len, "GET"))
    {
      if (!VPREFIX(data, req->path_pos, req->path_len, "/"))
        HTTPD_ERR_MSG_RET(req, 400, "Bad path", http_fin_err_req(con, req));
      
      if (!http_req_make_path(con, req))
        return (http_fin_err_req(con, req));

      return (http_req_op_get(con, req));
    }
    else if (req->ver_0_9) /* 400 or 501? - apache does 400 */
      HTTPD_ERR_RET(req, 501, http_fin_err_req(con, req));      
    else if (VEQ(data, op_pos, op_len, "HEAD"))
    {
      ASSERT(req->head_op == TRUE); /* above, so errors are chopped */
      req->head_op = TRUE;
      
      if (!VPREFIX(data, req->path_pos, req->path_len, "/"))
        HTTPD_ERR_MSG_RET(req, 400, "Bad path", http_fin_err_req(con, req));
      
      if (!http_req_make_path(con, req))
        return (http_fin_err_req(con, req));

      return (http_req_op_get(con, req));
    }
    else if (VEQ(data, op_pos, op_len, "OPTIONS"))
    {
      if (!VPREFIX(data, req->path_pos, req->path_len, "/") &&
          !VEQ(data, req->path_pos, req->path_len, "*"))
        HTTPD_ERR_MSG_RET(req, 400, "Bad path", http_fin_err_req(con, req));

      /* Speed hack: Don't even call make_path if it's "OPTIONS * ..."
       * and we don't need to check the Host header */
      if (req->policy->use_vhosts_name &&
          req->policy->use_host_chk && req->policy->use_host_err_400 &&
          !VEQ(data, req->path_pos, req->path_len, "*") &&
          !http_req_make_path(con, req))
        return (http_fin_err_req(con, req));

      return (http_req_op_opts(con, req));
    }
    else if (req->policy->allow_trace_op && VEQ(data, op_pos, op_len, "TRACE"))
      return (http_req_op_trace(con, req));
    else if (VEQ(data, op_pos, op_len, "TRACE") ||
             VEQ(data, op_pos, op_len, "POST") ||
             VEQ(data, op_pos, op_len, "PUT") ||
             VEQ(data, op_pos, op_len, "DELETE") ||
             VEQ(data, op_pos, op_len, "CONNECT") ||
             FALSE) /* we know about these ... but don't allow them */
      HTTPD_ERR_RET(req, 405, http_fin_err_req(con, req));
    else
      HTTPD_ERR_RET(req, 501, http_fin_err_req(con, req));
  }
  ASSERT_NOT_REACHED();
}


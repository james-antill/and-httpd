#ifndef HTTPD_H
#define HTTPD_H

#include <vstr.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/unistd.h>

#include "evnt.h"

#define HTTPD_CONF_SERV_DEF_PORT 80

/* if the data is less than this, queue instead of hitting write */
#define HTTPD_CONF_MAX_WAIT_SEND 16

#define HTTPD_CONF_RECV_CALL_LIMIT 3 /* read+send+sendfile */
#define HTTPD_CONF_SEND_CALL_LIMIT 1 /* already blocking in send */

struct Con;
struct Httpd_req_data;

#include "httpd_conf_main.h"
#include "httpd_conf_req.h"
#include "httpd_err_codes.h"

struct Http_hdrs
{
 Vstr_sect_node hdr_ua[1];
 Vstr_sect_node hdr_referer[1]; /* NOTE: referrer */

 Vstr_sect_node hdr_authorization[1];
 Vstr_sect_node hdr_expect[1];
 Vstr_sect_node hdr_host[1];
 Vstr_sect_node hdr_if_modified_since[1];
 Vstr_sect_node hdr_if_range[1];
 Vstr_sect_node hdr_if_unmodified_since[1];
 Vstr_sect_node hdr_range[1];
 Vstr_sect_node hdr_x_moz[1];

 /* can have multiple headers... */
 struct Http_hdrs__multi {
  Vstr_base *combiner_store;
  Vstr_base *comb;
  Vstr_sect_node hdr_accept[1];
  Vstr_sect_node hdr_accept_charset[1];
  Vstr_sect_node hdr_accept_encoding[1];
  Vstr_sect_node hdr_accept_language[1];
  Vstr_sect_node hdr_connection[1];
  Vstr_sect_node hdr_if_match[1];
  Vstr_sect_node hdr_if_none_match[1];
 } multi[1];
};

#define HTTPD__DECL_XTRA_HDR(x)                 \
    const Vstr_base * x ## _vs1;                \
    size_t            x ## _pos;                \
    size_t            x ## _len

#define HTTP__XTRA_HDR_PARAMS(req, x)                            \
    (req)-> x ## _vs1, (req)-> x ## _pos, (req)-> x ## _len


typedef struct Httpd_req_data
{
 const Httpd_policy_opts *policy;
 Vstr_base *tag;
 
 struct Http_hdrs http_hdrs[1];
 Vstr_base *fname;
 size_t len;
 size_t path_pos;
 size_t path_len;

 VSTR_AUTOCONF_uintmax_t fs_len; /* total length of all range's */
 
 unsigned int             error_code;
 const char              *error_line;
 const char              *error_msg;
 const char              *error_xmsg;
 VSTR_AUTOCONF_uintmax_t  error_len; /* due to custom files */
 unsigned int             req_error_code;
 const char              *req_error_xmsg;
 
 Vstr_sects *sects;
 struct stat64 f_stat[1];
 off64_t f_stat_st_size; /* output file size */
 
 size_t orig_io_w_len;
 Vstr_base *f_mmap;
 Vstr_base *xtra_content;
 HTTPD__DECL_XTRA_HDR(cache_control);
 HTTPD__DECL_XTRA_HDR(content_disposition);
 HTTPD__DECL_XTRA_HDR(content_language);
 HTTPD__DECL_XTRA_HDR(content_location);
 HTTPD__DECL_XTRA_HDR(content_md5); /* Note this is valid for range */
 time_t               content_md5_time;
 HTTPD__DECL_XTRA_HDR(gzip_content_md5);
 time_t               gzip_content_md5_time;
 HTTPD__DECL_XTRA_HDR(bzip2_content_md5);
 time_t               bzip2_content_md5_time;
 HTTPD__DECL_XTRA_HDR(content_type);
 HTTPD__DECL_XTRA_HDR(etag); /* in theory ETag is like Content-MD5, and
                                needs gzip/bzip2 versions however it doesn't
                                matter if we reuse them ... so we do */
 time_t               etag_time;
 HTTPD__DECL_XTRA_HDR(expires);
 time_t               expires_time;
 HTTPD__DECL_XTRA_HDR(ext_vary_a);
 HTTPD__DECL_XTRA_HDR(ext_vary_ac);
 HTTPD__DECL_XTRA_HDR(ext_vary_al);
 HTTPD__DECL_XTRA_HDR(link);
 HTTPD__DECL_XTRA_HDR(p3p);

 time_t encoded_mtime;
 
 time_t now;

 size_t vhost_prefix_len;
 
 unsigned int content_enc_identity;
 unsigned int content_enc_gzip;
 unsigned int content_enc_bzip2;

 unsigned short http_host_port;
 
 unsigned int ver_0_9 : 1;
 unsigned int ver_1_1 : 1;
 unsigned int ver_1_x : 1;
 unsigned int head_op : 1;

 unsigned int parsed_content_encoding   : 1;
 unsigned int content_encoding_identity : 1;
 unsigned int content_encoding_gzip     : 1;
 unsigned int content_encoding_bzip2    : 1;
 unsigned int content_encoding_xgzip    : 1; /* only valid if gzip is == 1000 */

 unsigned int direct_uri         : 1;
 unsigned int direct_filename    : 1;
 unsigned int skip_document_root : 1;
 
 unsigned int parse_accept          : 1;
 unsigned int parse_accept_language : 1;
 unsigned int allow_accept_encoding : 1;

 unsigned int user_return_error_code : 1;
 unsigned int req_user_return_error_code : 1;
 
 unsigned int vary_star : 1;
 unsigned int vary_a    : 1;
 unsigned int vary_ac   : 1;
 unsigned int vary_ae   : 1;
 unsigned int vary_al   : 1;
 unsigned int vary_rf   : 1;
 unsigned int vary_ua   : 1;
 unsigned int vary_ims  : 1;
 unsigned int vary_ius  : 1;
 unsigned int vary_ir   : 1;
 unsigned int vary_im   : 1;
 unsigned int vary_inm  : 1;
 unsigned int vary_xm   : 1;
 
 unsigned int chked_encoded_path : 1;
 unsigned int chk_encoded_slash  : 1;
 unsigned int chk_encoded_dot    : 1;
 
 unsigned int neg_content_type_done : 1;
 unsigned int neg_content_lang_done : 1;
 
 unsigned int conf_secure_dirs : 1;
 unsigned int conf_friendly_file : 1;
 unsigned int conf_friendly_dirs : 1;

 unsigned int conf_flags : 3;

 unsigned int using_req : 1;
 unsigned int done_once : 1;
 
 unsigned int malloc_bad : 1;
} Httpd_req_data;

struct File_sect
{
  int fd;
  VSTR_AUTOCONF_uintmax_t off;
  VSTR_AUTOCONF_uintmax_t len;
};

struct Con
{
 struct Evnt evnt[1];

 Vstr_base *tag;
 
 const Httpd_policy_opts *policy;

 Vstr_base *mpbr_ct; /* multipart/byterange */
 VSTR_AUTOCONF_uintmax_t mpbr_fs_len;
 unsigned int fs_off;
 unsigned int fs_num;
 unsigned int fs_sz;
 struct File_sect *fs;
 struct File_sect fs_store[1];

 unsigned int io_limit_num : 8;
 
 unsigned int vary_star : 1;
 unsigned int parsed_method_ver_1_0 : 1;
 unsigned int keep_alive : 3;
 
 unsigned int use_mmap : 1;
 unsigned int use_sendfile : 1; 
 unsigned int use_posix_fadvise : 1; 
 unsigned int use_mpbr : 1; 
};
#define CON_CEVNT_SA(x)     EVNT_SA((x)->evnt)
#define CON_CEVNT_SA_IN4(x) EVNT_SA_IN4((x)->evnt)
#define CON_CEVNT_SA_IN6(x) EVNT_SA_IN6((x)->evnt)
#define CON_CEVNT_SA_UN(x)  EVNT_SA_UN((x)->evnt)

#define CON_SEVNT_SA(x)     EVNT_ACPT_SA((x)->evnt)
#define CON_SEVNT_SA_IN4(x) EVNT_ACPT_SA_IN4((x)->evnt)
#define CON_SEVNT_SA_IN6(x) EVNT_ACPT_SA_IN6((x)->evnt)
#define CON_SEVNT_SA_UN(x)  EVNT_ACPT_SA_UN((x)->evnt)


#define HTTP_NON_KEEP_ALIVE 0
#define HTTP_1_0_KEEP_ALIVE 1
#define HTTP_1_1_KEEP_ALIVE 2

#define HTTPD_ETAG_TYPE_AUTO_NONE 0
#define HTTPD_ETAG_TYPE_AUTO_SM   1
#define HTTPD_ETAG_TYPE_AUTO_ISM  2
#define HTTPD_ETAG_TYPE_AUTO_DISM 3

/* Linear Whitespace, a full stds. check for " " and "\t" */
#define HTTP_LWS " \t"

/* End of Line */
#define HTTP_EOL "\r\n"

/* End of Request - blank line following previous line in request */
#define HTTP_END_OF_REQUEST HTTP_EOL HTTP_EOL

#define HTTPD_APP_REF_VSTR(x, s2, p2, l2)                               \
    vstr_add_vstr(x, (x)->len, s2, p2, l2, VSTR_TYPE_ADD_BUF_REF)
#define HTTPD_APP_REF_ALLVSTR(x, s2)                                    \
    vstr_add_vstr(x, (x)->len, s2, 1, (s2)->len, VSTR_TYPE_ADD_BUF_REF)

#ifdef HTTPD_HAVE_GLOBAL_OPTS
extern Httpd_opts httpd_opts[1]; /* hacky ... */
#endif

#include "httpd_app.h"
#include "httpd_parse.h"
#include "httpd_req.h"

extern void httpd_init(Vlg *);
extern void httpd_exit(void);

extern void httpd_fin_fd_close(struct Con *);

extern int httpd_valid_url_filename(Vstr_base *, size_t, size_t);
extern int httpd_init_default_hostname(Opt_serv_policy_opts *);
extern int httpd_sc_add_default_hostname(struct Con *, Httpd_req_data *,
                                         Vstr_base *, size_t);
extern int httpd_sc_add_req_hostname(struct Con *, Httpd_req_data *,
                                     Vstr_base *, size_t);
extern int httpd_sc_add_hostname(struct Con *, Httpd_req_data *,
                                 Vstr_base *, size_t);

extern int httpd_canon_path(Vstr_base *);
extern int httpd_canon_dir_path(Vstr_base *);
extern int httpd_canon_abs_dir_path(Vstr_base *);


extern int http_fmt_add_vstr_add_vstr(Vstr_conf *, const char *);
extern int http_fmt_add_vstr_add_sect_vstr(Vstr_conf *, const char *);


extern void httpd_disable_getxattr(void);

    
extern int httpd_serv_send(struct Con *);
extern int httpd_serv_recv(struct Con *);

extern int httpd_con_init(struct Con *, struct Acpt_listener *);

extern int http_fin_err_req(struct Con *, Httpd_req_data *);
extern int http_fin_errmem_req(struct Con *, struct Httpd_req_data *);

extern int http_serv_add_vhost(struct Con *, Httpd_req_data *,
                               Vstr_base *, size_t, int);

extern void httpd_serv_call_file_init(struct Con *, Httpd_req_data *,
                                      unsigned int *,
                                      const char ** );
extern void httpd_serv_file_sects_none(struct Con *, Httpd_req_data *, off64_t);
extern uintmax_t http_serv_file_len(struct Con *, Httpd_req_data *);

#endif

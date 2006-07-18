#ifndef HTTPD_CONF_MAIN_H
#define HTTPD_CONF_MAIN_H

#ifndef HTTPD_H
# error "include just httpd.h"
#endif

#include "opt_serv.h"
#include "mime_types.h"
#include "date.h"

/* **** defaults for runtime conf **** */
#ifndef HTTPD_CONF_VERSION
# error "Set the version (via. configure.in)"
#endif

/* note that the strings are assigned in httpd_main_conf.c */

#define HTTPD_CONF_PROG_NAME "and-httpd"
#if COMPILE_DEBUG
# define HTTPD_CONF_SERVER_COMMENT " (Debug)"
#else
# define HTTPD_CONF_SERVER_COMMENT ""
#endif
#define HTTPD_CONF_DEF_SERVER_NAME \
    HTTPD_CONF_PROG_NAME "/"       \
    HTTPD_CONF_VERSION HTTPD_CONF_SERVER_COMMENT
#define HTTPD_CONF_USE_MMAP FALSE
#define HTTPD_CONF_USE_SENDFILE TRUE
#define HTTPD_CONF_USE_KEEPA TRUE
#define HTTPD_CONF_USE_KEEPA_1_0 TRUE
#define HTTPD_CONF_USE_VHOSTS_NAME FALSE
#define HTTPD_CONF_USE_RANGE TRUE
#define HTTPD_CONF_USE_RANGE_1_0 TRUE
#define HTTPD_CONF_USE_ADV_RANGE TRUE
#define HTTPD_CONF_USE_PUBLIC_ONLY FALSE
#define HTTPD_CONF_USE_ENC_CONTENT_REPLACEMENT TRUE
#define HTTPD_CONF_DEF_DIR_FILENAME "index.html"
/* default charset ? -- default lanugage ? */
#define HTTPD_CONF_MIME_TYPE_DEF_CT "" /* "application/octet-stream" */
#define HTTPD_CONF_MIME_TYPE_MAIN "/etc/mime.types"
#define HTTPD_CONF_MIME_TYPE_XTRA ""
#define HTTPD_CONF_USE_ERR_406 TRUE
#define HTTPD_CONF_USE_CANONIZE_HOST FALSE
#define HTTPD_CONF_USE_HOST_ERR_400 TRUE
#define HTTPD_CONF_USE_INTERNAL_HOST_CHK TRUE
#define HTTPD_CONF_USE_HOST_CHK TRUE
#define HTTPD_CONF_USE_HDRS_NO_x2 TRUE
#define HTTPD_CONF_USE_HDRS_NON_SPC TRUE
#define HTTPD_CONF_USE_HDRS_ERR_411 TRUE
#define HTTPD_CONF_ALLOW_TRACE_OP TRUE
#define HTTPD_CONF_ALLOW_HTTP_0_9 TRUE
#define HTTPD_CONF_USE_REMOVE_FRAG TRUE
#define HTTPD_CONF_USE_REMOVE_QUERY FALSE
#define HTTPD_CONF_USE_SECURE_DIRS TRUE
#define HTTPD_CONF_USE_FRIENDLY_DIRS TRUE
#define HTTPD_CONF_USE_POSIX_FADVISE TRUE /* NOTE that this SEGV's on FC1 */
#define HTTPD_CONF_USE_TCP_CORK TRUE
#define HTTPD_CONF_USE_REQ_CONF TRUE
#define HTTPD_CONF_USE_ALLOW_HDR_SPLIT TRUE
#define HTTPD_CONF_USE_ALLOW_HDR_NIL TRUE
#define HTTPD_CONF_USE_CHK_DOT_DIR TRUE
#define HTTPD_CONF_USE_CHK_ENCODED_SLASH TRUE
#define HTTPD_CONF_USE_CHK_ENCODED_DOT TRUE
#define HTTPD_CONF_USE_NOATIME FALSE /* can't easily enable due to "security" */
#define HTTPD_CONF_USE_TEXT_PLAIN_REDIRECT FALSE
#define HTTPD_CONF_ADD_DEF_PORT TRUE
#define HTTPD_CONF_MAX_REQUESTS           0
#define HTTPD_CONF_MAX_NEG_A_NODES        8
#define HTTPD_CONF_MAX_NEG_AL_NODES       0
#define HTTPD_CONF_MAX_A_NODES          128 /* lynx uses 53 */
#define HTTPD_CONF_MAX_AC_NODES           8
#define HTTPD_CONF_MAX_AE_NODES          32
#define HTTPD_CONF_MAX_AL_NODES          16
#define HTTPD_CONF_MAX_CONNECTION_NODES  64 /* not sure */
#define HTTPD_CONF_MAX_ETAG_NODES        16
#define HTTPD_CONF_MAX_RANGE_NODES        1 /* zsync needs more */
#define HTTPD_CONF_REQ_CONF_MAXSZ (16 * 1024)

/* this is configurable, but is much higher than EX_MAX_R_DATA_INCORE due to
 * allowing largish requests with HTTP */
# define HTTPD_CONF_INPUT_MAXSZ (128 * 1024)

typedef struct Httpd_policy_opts
{
 Opt_serv_policy_opts s[1];

 Vstr_base   *document_root;
 Vstr_base   *server_name;
 Vstr_base   *dir_filename;
 Mime_types   mime_types[1];
 Vstr_base   *mime_types_def_ct;
 Vstr_base   *mime_types_main;
 Vstr_base   *mime_types_xtra;
 Vstr_base   *default_hostname;
 Vstr_base   *req_conf_dir;
 Vstr_base   *req_err_dir;
 Vstr_base   *auth_realm;
 Vstr_base   *auth_token;
 
 unsigned int use_mmap : 1;
 unsigned int use_sendfile : 1;
 unsigned int use_keep_alive : 1;
 unsigned int use_keep_alive_1_0 : 1;
 unsigned int use_vhosts_name : 1;
 unsigned int use_range : 1;
 unsigned int use_range_1_0 : 1;
 unsigned int use_adv_range : 1; /* 8th bitfield */
 unsigned int use_public_only : 1;
 unsigned int use_enc_content_replacement : 1;

 unsigned int use_err_406 : 1;
 unsigned int use_canonize_host : 1;
 unsigned int use_host_err_400 : 1;
 unsigned int use_internal_host_chk : 1;
 unsigned int use_host_chk : 1;
 unsigned int use_hdrs_no_x2 : 1; /* 16th bitfield */
 unsigned int use_hdrs_non_spc : 1;
 unsigned int use_hdrs_err_411 : 1;
 unsigned int allow_trace_op : 1;
 unsigned int allow_http_0_9 : 1;
 
 unsigned int remove_url_frag : 1;
 unsigned int remove_url_query : 1;
 unsigned int use_secure_dirs : 1;
 unsigned int use_friendly_dirs : 1;

 unsigned int use_posix_fadvise : 1; /* 24th bitfield */
 unsigned int use_tcp_cork : 1;
 
 unsigned int use_req_conf : 1;
 unsigned int allow_hdr_split : 1;
 unsigned int allow_hdr_nil : 1;
 
 unsigned int chk_dot_dir : 1;
 
 unsigned int chk_encoded_slash : 1;
 unsigned int chk_encoded_dot   : 1;

 unsigned int add_def_port : 1; /* 32nd bitfield */

 unsigned int use_noatime : 1;

 unsigned int use_text_plain_redirect : 1; /* 36th bitfield */

 unsigned int max_header_sz;

 unsigned int max_requests;
 
 unsigned int max_neg_A_nodes;
 unsigned int max_neg_AL_nodes;
 
 unsigned int max_A_nodes;
 unsigned int max_AC_nodes;
 unsigned int max_AE_nodes;
 unsigned int max_AL_nodes;
 
 unsigned int max_connection_nodes;
 unsigned int max_etag_nodes;
 
 unsigned int max_range_nodes;
 
 unsigned int max_req_conf_sz;
} Httpd_policy_opts; /* NOTE: remember to copy changes to
                      * httpd_policy.c:httpd_policy_init
                      * httpd_policy.c:httpd_policy_copy */

typedef struct Httpd_opts
{
 Opt_serv_opts s[1];

 time_t beg_time;

 Date_store *date;
 
 Conf_parse *conf;
 unsigned int conf_num;

 Conf_token match_connection[1];
 Conf_token tmp_match_connection[1];
 Conf_token match_request[1];
 Conf_token tmp_match_request[1];
 Conf_token match_response[1];
 Conf_token tmp_match_response[1];
} Httpd_opts;
#define HTTPD_CONF_MAIN_DECL_OPTS(N)                            \
    Httpd_opts N[1] = {                                         \
     {                                                          \
      {{OPT_SERV_CONF_INIT_OPTS(HTTPD_CONF_PROG_NAME, HTTPD_CONF_VERSION)}}, \
      (time_t)-1,                                               \
      NULL,                                                     \
      NULL,                                                     \
      0,                                                        \
      {CONF_TOKEN_INIT},                                        \
      {CONF_TOKEN_INIT},                                        \
      {CONF_TOKEN_INIT},                                        \
      {CONF_TOKEN_INIT},                                        \
      {CONF_TOKEN_INIT},                                        \
      {CONF_TOKEN_INIT},                                        \
     }                                                          \
    }

extern int  httpd_conf_main_init(Httpd_opts *);
extern void httpd_conf_main_free(Httpd_opts *);

extern int httpd_match_request_tst_d1(struct Con *, struct Httpd_req_data *,
                                      Conf_parse *, Conf_token *,
                                      int *, int,
                                      int (*)(Conf_parse *, Conf_token *,
                                              int *, int, void *),
                                      void *);
extern int httpd_match_request_sc_tst_d1(struct Con *, struct Httpd_req_data *,
                                         Conf_parse *, Conf_token *,
                                         int *, int);


/* these are in match_*.c */
extern int httpd_policy_connection(struct Con *,
                                   Conf_parse *, const Conf_token *);
extern int httpd_policy_request(struct Con *, struct Httpd_req_data *,
                                Conf_parse *, const Conf_token *);
extern int httpd_policy_response(struct Con *, struct Httpd_req_data *,
                                 Conf_parse *, const Conf_token *);


extern int httpd_conf_main(Httpd_opts *, Conf_parse *, Conf_token *);
extern int httpd_conf_main_parse_cstr(Vstr_base *, Httpd_opts *, const char *);
extern int httpd_conf_main_parse_file(Vstr_base *, Httpd_opts *, const char *);
extern int httpd_sc_conf_main_parse_dir_file(Vstr_base *, void *, const char *);

#endif

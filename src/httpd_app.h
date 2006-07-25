#ifndef HTTPD_APP_H
#define HTTPD_APP_H 1

/* use single node */
#define HTTP_APP_HDR_CONST_CSTR(o, h, c)                        \
    vstr_add_cstr_ptr(out, (out)->len, h ": " c HTTP_EOL)

extern void httpd_app_init(Vlg *);
extern void httpd_app_exit(void);

extern void http_app_hdr_cstr(Vstr_base *, const char *, const char *);

extern void http_app_hdr_vstr(Vstr_base *, const char *,
                              const Vstr_base *, size_t, size_t, unsigned int);

extern void http_app_hdr_vstr_def(Vstr_base *, const char *,
                                  const Vstr_base *, size_t, size_t);

extern void http_app_hdr_conf_vstr(Vstr_base *, const char *,
                                   const Vstr_base *);

extern void http_app_hdr_fmt(Vstr_base *, const char *, const char *, ...)
   VSTR__COMPILE_ATTR_FMT(3, 4);

extern void http_app_hdr_uintmax(Vstr_base *, const char *, uintmax_t);

extern void http_app_def_hdrs(struct Con *, Httpd_req_data *,
                              unsigned int, const char *, time_t,
                              const char *, int, uintmax_t);
extern void http_app_end_hdrs(Vstr_base *);

extern void http_app_hdrs_url(struct Con *, Httpd_req_data *);
extern void http_app_hdrs_file(struct Con *, Httpd_req_data *);
extern void http_app_hdrs_mpbr(struct Con *, struct File_sect *);

#endif

#ifndef HTTPD_REQ_H
#define HTTPD_REQ_H 1

#define HTTP_REQ__X_HDR_CHK(x, y, z) do {                       \
      if (!req->policy->allow_hdr_split &&                      \
          vstr_srch_cstr_chrs_fwd(x, y, z, HTTP_EOL))           \
        return (FALSE);                                         \
      if (!req->policy->allow_hdr_nil &&                        \
          vstr_srch_chr_fwd(x, y, z, 0))                        \
        return (FALSE);                                         \
    } while (FALSE)

#define HTTP_REQ__X_CONTENT_HDR_CHK(x)                                  \
    HTTP_REQ__X_HDR_CHK(req-> x ## _vs1, req-> x ## _pos, req-> x ## _len)

#define HTTP_REQ__CONT_PARAMS(req, x)                        \
    (req)-> x ## _vs1, (req)-> x ## _pos, (req)-> x ## _len


extern void httpd_req_init(Vlg *);
extern void httpd_req_exit(void);

extern Httpd_req_data *http_req_make(struct Con *);
extern void http_req_free(Httpd_req_data *);
extern void http_req_exit(void);

extern int http_req_chk_dir(struct Con *, Httpd_req_data *,
                            const char *);
extern int http_req_chk_file(struct Con *, Httpd_req_data *, const char *);
extern void http_req_split_method(struct Con *, struct Httpd_req_data *);
extern void http_req_split_hdrs(struct Con *, struct Httpd_req_data *);


extern void httpd_req_absolute_uri(struct Con *, Httpd_req_data *,
                                   Vstr_base *, size_t, size_t);

extern int http_req_content_type(Httpd_req_data *);

extern int http_req_op_get(struct Con *, Httpd_req_data *);
extern int http_req_op_opts(struct Con *, Httpd_req_data *);
extern int http_req_op_trace(struct Con *, Httpd_req_data *);

extern int http_req_1_x(struct Con *, Httpd_req_data *,
                        unsigned int *, const char **);

extern int http_req_make_path(struct Con *, Httpd_req_data *);

extern size_t http_req_xtra_content(Httpd_req_data *, const Vstr_base *,
                                    size_t, size_t *);

#endif

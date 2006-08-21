#ifndef HTTPD_PARSE_H
#define HTTPD_PARSE_H 1

/* HTTP crack -- Implied linear whitespace between tokens, note that it
 * is *LWS == *([CRLF] 1*(SP | HT)) */
#define HTTP_SKIP_LWS(s1, p, l) do {                                    \
      char http__q_tst_lws = 0;                                         \
                                                                        \
      if (!l) break;                                                    \
      http__q_tst_lws = vstr_export_chr(s1, p);                         \
      if ((http__q_tst_lws != '\r') && (http__q_tst_lws != ' ') &&      \
          (http__q_tst_lws != '\t'))                                    \
        break;                                                          \
                                                                        \
      http_parse_skip_lws(s1, &p, &l);                                       \
    } while (FALSE)

/* test for >= 1.1 ... so 1.2, 1.3, 1.n requests, 1.0 doesn't work */
/* 2.x doesn't work... */
#define HTTPD_VER_GE_1_1(x) ((x)->ver_1_1 || (x)->ver_1_x)


extern void httpd_parse_init(Vlg *);
extern void httpd_parse_exit(void);

extern void http_parse_skip_lws(const Vstr_base *, size_t *, size_t *);

extern int http_parse_version(struct Con *, struct Httpd_req_data *);

extern void http_parse_clear_hdrs(struct Httpd_req_data *);
extern int http_parse_hdrs(struct Con *, Httpd_req_data *);

extern void http_parse_connection(struct Con *, struct Httpd_req_data *);

extern int http_parse_1_x(struct Con *, struct Httpd_req_data *);

extern unsigned int http_parse_accept(Httpd_req_data *,
                                      const Vstr_base *, size_t, size_t);
extern int http_parse_accept_encoding(Httpd_req_data *, int);
extern unsigned int http_parse_accept_language(Httpd_req_data *,
                                               const Vstr_base *,
                                               size_t, size_t);
extern int httpd_match_etags(Httpd_req_data *,
                             const Vstr_base *, size_t, size_t,
                             const Vstr_base *, size_t, size_t,
                             int);

extern void httpd_parse_sc_try_fd_encoding(struct Con *, Httpd_req_data *,
                                           const struct stat64 *, off64_t *,
                                           Vstr_base *);

extern int http_parse_range(struct Con *, Httpd_req_data *);

extern unsigned short httpd_parse_host_port(Vstr_base *, size_t, size_t);

extern int http_parse_host(struct Con *, struct Httpd_req_data *);

extern void http_parse_skip_blanks(Vstr_base *, size_t *, size_t *);

extern int http_parse_req(struct Con *);

#endif

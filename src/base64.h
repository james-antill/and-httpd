#ifndef BASE64_H
#define BASE64_H 1

extern int vstr_x_conv_base64_encode(Vstr_base *, size_t,
                                     const Vstr_base *, size_t, size_t,
                                     unsigned int);

extern int vstr_x_conv_base64_decode(Vstr_base *, size_t,
                                     const Vstr_base *, size_t, size_t);

#endif

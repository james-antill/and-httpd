
#define EX_UTILS_NO_FUNCS 1
#include "ex_utils.h"

#include "base64.h"

/*
 * Translation Table as described in RFC1113
 */
static const char b64[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "abcdefghijklmnopqrstuvwxyz"
                            "0123456789" "+/";


int vstr_x_conv_base64_encode(Vstr_base *dst, size_t dpos,
                              const Vstr_base *src, size_t spos, size_t slen,
                              unsigned int flags)
{
  unsigned char sbuf[3];
  unsigned char dbuf[4];
  size_t orig_dpos = dpos;
  size_t orig_dlen = dst->len;
  unsigned int nonl = 76 / 4;
  
  while (slen)
  {
    unsigned int i24 = 0;
    unsigned int used = 3;

    /* operate on 24 bits at once, zero extending */
    /* 3 8bit bytes IN */
    if (slen >= 3)
      vstr_export_buf(src, spos, used, sbuf, sizeof(sbuf));
    else
    {
      vstr_export_buf(src, spos, slen, sbuf, sizeof(sbuf));
      switch (used = slen)
      {
        case 1: sbuf[1] = 0;
        case 2: sbuf[2] = 0;
          
          ASSERT_NO_SWITCH_DEF();
      }
    }

    i24 |= sbuf[0]; i24 <<= 8;
    i24 |= sbuf[1]; i24 <<= 8;
    i24 |= sbuf[2];

    /* 4 6bit "bytes" OUT */    
    ASSERT(sizeof(b64) == 64);
    ASSERT(((i24 & 0x00FC0000) >> 18) < 64);
    ASSERT(((i24 & 0x0003F000) >> 12) < 64);
    ASSERT(((i24 & 0x00000FC0) >>  6) < 64);
    ASSERT(((i24 & 0x0000003F)        < 64));
    
    dbuf[0] = (i24 & 0x00FC0000) >> 18; dbuf[0] = b64[dbuf[0]];
    dbuf[1] = (i24 & 0x0003F000) >> 12; dbuf[1] = b64[dbuf[1]];
    dbuf[2] = (i24 & 0x00000FC0) >>  6; dbuf[2] = b64[dbuf[2]];
    dbuf[3] = (i24 & 0x0000003F);       dbuf[3] = b64[dbuf[3]];

    if (used == 3)
    {
      if (!vstr_add_buf(dst, dpos, dbuf, sizeof(dbuf)))
        goto failed_add;
      dpos += sizeof(dbuf);
    }
    else
    { /* if we didn't use 3 8bit bytes, we are at the end ... so do special
       * case for = byte endings */
      unsigned int out_map[3] = {0, 2, 3};

      ASSERT(used && (out_map[used] <= sizeof(dbuf)));
      if (!vstr_add_buf(dst, dpos, dbuf, out_map[used]))
        goto failed_add;
      dpos += out_map[used];
      
      if (!vstr_add_rep_chr(dst, dpos, '=', 4 - out_map[used]))
        goto failed_add;
      dpos += 4 - out_map[used];
    }
    
    slen -= used; spos += used;
    
    if (flags && (!--nonl || !slen)) /* ever 76 output bytes, newline */
    {
      nonl = 76 / 4;
      if (!vstr_add_cstr_buf(dst, dpos, "\n"))
        goto failed_add;      
      ++dpos;
    }
  }

  return (TRUE);
  
 failed_add:
  vstr_del(dst, orig_dpos, dst->len - orig_dlen);
  return (FALSE);
}

#if 0
int vstr_x_conv_base64_decode(Vstr_base *dst, size_t dpos,
                              const Vstr_base *src, size_t spos, size_t slen)
{
  assert(FALSE);
  return (FALSE);
}
#endif

#! /bin/sh

if false; then
 echo "Not reached."
elif [ -f ./configure ]; then
        c=./configure
elif [ -f ../configure ]; then
        c=../configure
else
  echo "Not in right place, dying."
  exit 1;
fi

CFLAGS='-DVSTR_COMPILE_INLINE=0' \
 $c --sysconfdir=/etc --prefix=/usr --localstatedir=/var \
    --enable-debug --enable-debug-vstr --enable-debug-timer_q $@ && \
    make clean && make check

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

CFLAGS='-DVSTR_COMPILE_INLINE=0' $c --enable-debug $@ && make clean && make check

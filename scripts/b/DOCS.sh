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

CFLAGS="-O2 -march=i386 -mtune=i686" \
  $c --prefix=/usr --localstatedir=/var $@ && make clean && make

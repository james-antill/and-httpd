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

export CFLAGS="-g -fprofile-arcs -ftest-coverage -DUSE_SYSCALL_MAIN $CFLAGS"
$c \
  --enable-tst-noinline \
  --enable-static \
    $@ && make clean && make check

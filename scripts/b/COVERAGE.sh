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

# Turn Vstr inline off, so we don't see coverage data for Vstr
export CFLAGS="-g -fprofile-arcs -ftest-coverage -DUSE_SYSCALL_MAIN -DVSTR_COMPILE_INLINE=0 $CFLAGS"
$c --prefix=/usr --localstatedir=/var \
  --enable-tst-noinline \
  --enable-static \
    $@ && make clean && make check

#! /bin/sh

if false; then
 echo "Not reached."
elif [ -f ./configure.in ]; then
        t=.
elif [ -f ../configure.in ]; then
        t=../
else
  echo "Not in right place, dying."
  exit 1;
fi

cd $t

libtoolize -c --force && aclocal && automake -a -c --force-missing && autoconf

# Fix automake...
rm -f COPYING
ln Documentation/COPYING.LIB COPYING


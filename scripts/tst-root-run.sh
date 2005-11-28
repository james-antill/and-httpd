#! /bin/sh -e

if false; then
 echo "Not reached."
elif [ -f ./configure -a -f VERSION ]; then                      # <root>
        r=./
        b=./
elif [ -f ../configure -a -f VERSION ]; then       # <root>/<build-dir>
        r=../
        b=./
elif [ -f ../configure ]; then                     # <root>/src
        r=../
        b=../
elif [ -f ../../configure -a -f autoconf.h ]; then # <root>/<build-dir>/<src>
        r=../../
        b=../
else
  echo "Not in right place, or not built and-httpd ... dying."
  exit 1;
fi

fake_root="$r/tmp/code.and.org-fake-root"

exec sudo $b/src/and-httpd --config-file $fake_root/and-httpd.conf \
                           --config-file $fake_root/and-httpd-root.conf \
                           --config-dir  /etc/and-httpd/conf.d $@


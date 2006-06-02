#! /bin/sh -e

if false; then
 echo "Not reached."
elif [ -f ../configure ]; then
        s=../scripts
else
  echo "Not in right place, goto a seperate build directory."
  exit 1;
fi


# Remove ccache... 
if [ "x$CC" = "x" ]; then
for i in `perl -e 'print join "\n", split ":", $ENV{PATH}'`; do
  if [ "x$CC" = "x" ]; then
    if [ -f $i/gcc ]; then
      if ! readlink $i/gcc | egrep -q ccache; then
        export CC=$i/gcc
      fi
    fi
  fi
done
fi


rm -f *.info

function del()
{
    rm -rf Documentation/ include/ src/ tst/ tools/ \
    Makefile config.log config.status libtool and-httpd.spec
}

function linkup()
{
  for dir in src; do
  cd $dir

  lndir ../$s/../$dir

## 4.0 does everything different, again.
### Newer GCCs put them in the $srcdir
 ## if [ ! -f ex_httpd-ex_httpd.da -a -f ex_httpd -a ! -f vstr.da ]; then
 ##   for i in .libs/*.da; do
 ##     ln -f $i; rm -f $i
 ##   done
 ## fi

  cd ..
  done
}

function cov()
{
  type=$1; shift
  del
  $s/b/COVERAGE.sh $@
  linkup
  $s/lcov.sh $type
}

cov dbg --enable-debug --enable-debug-vstr --enable-debug-timer_q
cov opt


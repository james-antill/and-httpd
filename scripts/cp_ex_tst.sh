#! /bin/sh

if false; then
echo "Do nothing"
elif [ -r ./scripts ]; then
# In source dir
       sex=./tst
       bex=./src
elif [ -r ../scripts ]; then
# In build dir or source dir/examples
if [ -r src ]; then
# In build dir
       sex=../tst
       bex=./src
else
# In source dir/src
       sex=../tst
       bex=.
fi
elif [ -r ../../scripts ]; then
# In build dir/examples
       sex=../../tst
       bex=.
else
 echo "No scripts dir"
 exit 1;
fi

if [ "x$1" = "x" ] || [ "x$2" = "x" ]; then
  echo " Format: $0 <tst-name> <num>"
  exit 1
fi

prefix=$1
num=$2

# Break the symlink, if one exists...
rm -f ${sex}/ex_${prefix}_out_$num
cp ${bex}/ex_${prefix}_tmp_$num ${sex}/ex_${prefix}_out_$num

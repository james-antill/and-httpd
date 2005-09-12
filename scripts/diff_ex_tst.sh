#! /bin/sh

if false; then
echo "Do nothing"
elif [ -r ./scripts ]; then
# In source dir
       sex=./tst
       bex=./src
elif [ -r ../scripts ]; then
# In build dir or source dir/examples
if [ -r examples ]; then
# In build dir
       sex=./tst
       bex=../src
else
# In source dir/examples
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

prefix=$1
num=$2

diff -u ${sex}/ex_${prefix}_out_$num ${bex}/ex_${prefix}_tmp_$num 


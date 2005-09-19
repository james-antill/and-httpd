#! /bin/bash -e

if [ ! -r VERSION -o ! -r and-httpd.spec -o ! -r configure ]; then
  if [ -r configure ]; then
#    ./scripts/b/DOCS.sh
    ./scripts/b/def-opt.sh
  else
    echo "No VERSION, and-httpd.spec or configure file." &>2
    exit 1
  fi
fi

v="`cat VERSION`"
s="`pwd`"
cd ../build/and-httpd

rm -rf and-httpd-$v
cp -a $s ./and-httpd-$v
cd ./and-httpd-$v

./scripts/clean.sh full

# Backup files...
find . \
 \( -name "*.o" -o -name ".*[%~]" -o -name "*[%~]" -o -name "#*#" \) \
 -print0 | xargs --no-run-if-empty -0 rm -f

# Arch stuff...
rm -rf ./{arch}
find . -name .arch-ids -type d -print0 | xargs -0 rm -rf

# Create tarballs/RPMS
cp $s/and-httpd.spec .

cd ..

tar -cf and-httpd-$v.tar and-httpd-$v
bzip2 -9f and-httpd-$v.tar

tar -cf and-httpd-$v.tar and-httpd-$v
gzip -9f and-httpd-$v.tar

chk=1
rel=1
if [ "x$1" = "xnochk" ]; then
echo Not doing checking.
chk=0
shift
else
echo Doing checking.
args="$args  --define \"chk 1\""
fi

if [ "x$1" = "xrel" ]; then
shift
echo Using custom release $1.
rel=$1
shift
else
echo Using normal release of 1.
fi

sudo rpmbuild -ta --define "chk $chk" --define "rel $rel" and-httpd-$v.tar.gz

echo "/usr/src/redhat/RPMS/*/and-httpd*-$v-$rel-*"
echo "/usr/src/redhat/SRPMS/and-httpd*-$v-$rel-*"

ls -aslhF /usr/src/redhat/RPMS/*/and-httpd*-$v-$rel-*
ls -aslhF /usr/src/redhat/SRPMS/and-httpd*-$v-$rel-*


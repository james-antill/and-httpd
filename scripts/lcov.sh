#! /bin/sh

if false; then
 echo "Not reached."
# elif [ -f ./configure ]; then
        s=./scripts
        s=./Documentation
	doln=false
elif [ -f ../configure ]; then
        s=../scripts
        d=../Documentation
	doln=true
else
  echo "Not in right place, goto a seperate build directory."
  exit 1;
fi

if [ "x$1" = "x" ]; then
  echo "Not got arg."
  exit 1;
fi

gendesc $d/coverage_descriptions.txt -o descriptions

cd src
lcov --capture --directory . --output-file ../app-$1.info --test-name app-$1
cd ..

cd tools
lcov --capture --directory . --output-file ../tools-$1.info --test-name tools-$1
cd ..

mkdir output || true
genhtml app*.info --output-directory output/app --title "And-httpd coverage" --show-details --description-file descriptions
genhtml tools*.info --output-directory output/tools --title "And-httpd tools coverage" --show-details --description-file descriptions
genhtml *.info --output-directory output/all --title "And-httpd ALL coverage" --show-details --description-file descriptions
echo Point your browser at file:`pwd`/output/app/index.html

#! /bin/sh -e

for i in 400 401 403 404 406 410 500 503; do
  for j in en fr de es it jp; do
    lynx -dump $i.en.html > $i.$j.txt
  done
done

#!/bin/bash
i=1
cd private
for i in {1,2,3,4,5}
do
echo $i
#openssl genrsa -out korisnik$i-enc.pem
openssl rsa -in korisnik$i-enc.pem -out korisnik$i-dgst.key -inform PEM -outform DER
done

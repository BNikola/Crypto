#!/bin/bash
#counter
i=1
#cd private
for i in {1,2,3,4,5}
do
# extracting public keys
#openssl rsa -in korisnik$i-dgst.key -out korisnik$i-enc.key -inform DER -outform DER -pubout
cp private/korisnik$i-dgst.key ../DgstKey/
done





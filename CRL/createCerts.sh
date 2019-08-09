#!/bin/bash
i=1
for i in {1,2,3,4}; do
    echo $i
    openssl req -new -key private/korisnik$i.key -out requests/korisnik$i.csr -config openssl.cnf
    openssl ca -in requests/korisnik$i.csr -keyfile private/private4096.key -key sigurnost -out certs/korisnik$i.crt -config openssl.cnf
done

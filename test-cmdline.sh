#!/bin/bash

set -e

rm -rf .cmdline-test
mkdir .cmdline-test
cd .cmdline-test

cp ../test-files/* .

for i in pkcs7 rsa2048 ; do
  echo "-----BEGIN PKCS7-----" > real-$i
  cat $i >> real-$i
  echo "-----END PKCS7-----" >> real-$i
done

# Test the pkcs7 endpoint
openssl smime -verify -in real-pkcs7 -inform PEM -content document -certfile pkcs7-pubkey -noverify > /dev/null
if [ $? -eq 0 ] ; then echo PKCS7 file validates ;  else echo PKCS7 Failed ; exit 1 ; fi

# Test the rsa2048 endpoint
#openssl smime -verify -in real-rsa2048 -inform PEM -content document -certfile rsa2048-pubkey -noverify > /dev/null
valgrind --leak-check=full openssl smime -verify -in real-rsa2048 -inform PEM -content document -certfile rsa2048-pubkey -noverify
if [ $? -eq 0 ] ; then echo RSA2048 file validates ; else echo RSA2048 Failed ; exit 1 ; fi

# Benchmark RSA2048
s="$(date +%s)"
for i in {0..1000} ; do
  openssl smime -verify -in real-rsa2048 -inform PEM -content document -certfile rsa2048-pubkey -noverify &> /dev/null
done
e="$(date +%s)"

echo Did 1000 iterations in $((e - s)) seconds




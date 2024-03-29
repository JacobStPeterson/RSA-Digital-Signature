#!/bin/bash

# "Script to Generate RSA Public/Private key Pair"
# "Written by: Mohamed Aboutabl"
# "Edited by: Jacob Peterson and Jessy Bradshaw"

#echo "Amal sends an unencrypted file to Basim"
#echo "Amal digitally signs that file using her RSA private key"
echo
echo

# Generate  2048-bit public/private key-pair for Amal
cd amal
rm -f *.pem 
openssl genpkey -algorithm RSA -out amal_priv_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa   -in amal_priv_key.pem -pubout > amal_pubKey.pem

echo "====================================="
echo "Here is Amal's RSA Key Information"
echo "====================================="
openssl  rsa -text -in amal_priv_key.pem
echo
echo "====================================="

# Now, share Amal's public key with Basim using Linux Symbolic Links
cd ../basim
rm -f *.pem
ln -s  ../amal/amal_pubKey.pem  amal_pubKey.pem

#back to dispatcher's folder
cd ../

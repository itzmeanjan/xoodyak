#!/bin/bash

# Script for ease of execution of Known Answer Tests against Xoodyak implementation

# generate shared library object
make lib

# ---

mkdir -p tmp
pushd tmp

# download compressed NIST LWC submission of Xoodyak
wget -O xoodyak.zip https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-submissions/xoodyak.zip
# uncomress
unzip xoodyak.zip

# copy Known Answer Tests outside of uncompressed NIST LWC submission directory
cp xoodyak/Implementations/crypto_hash/xoodyakround3/LWC_HASH_KAT_256.txt ../

popd

# ---

# remove NIST LWC submission zip
rm -rf tmp

# move Known Answer Tests to execution directory
mv LWC_HASH_KAT_256.txt wrapper/python/

# ---

pushd wrapper/python

# run tests
pytest -v

# clean up
rm LWC_*_KAT_*.txt

popd

# ---

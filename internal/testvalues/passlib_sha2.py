#!/usr/bin/env python3

from passlib.hash import sha256_crypt, sha512_crypt

rounds=10000
salt = "randomsaltishard"
password = "password"

print("EncodedSHA256 = `", sha256_crypt.hash(password, salt=salt, rounds=rounds), "`", sep="")
print("EncodedSHA512 = `", sha512_crypt.hash(password, salt=salt, rounds=rounds), "`", sep="")
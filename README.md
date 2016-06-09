# CryptoFault Attacks against RSA-CRT - ICR labo 3

A way to accelerate the RSA signature procedure consists in exploiting the fact that one knows the two primes p and q, as it is a private-key operation, 
and to use the Chinese Remainder Theorem (CRT). 

This repository implementing a fast RSA signature procedure that exploits the CRT and study the security of such an implementation at the light of fault attacks. 
The implementation is in C, with the big-numbers arithmetic library GMP.

This work was conducted under the ICR court the Master of Science HES-SO.
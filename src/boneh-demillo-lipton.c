#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#include <gmp.h>
#include "sha256.c"
#include "rsa.h"

int main () 
{
    printf("Implementation of Boneh-DeMillo-Lipton\n");
    printf("attack against RSA-CRT\n");

    mpz_t s, p, q, h, se;
    mpz_inits (s, p, q, h, se, NULL);

    char msg[] = "ICR - labo 3 fault attack";

    SHA256_CTX *sha256 = malloc (sizeof (SHA256_CTX));
    uchar hash[32];

    sha256_init(sha256);
    sha256_update(sha256, msg, strlen(msg));
    sha256_final(sha256, hash);

    mpz_import (h, sizeof (hash), 1, 1, 1, 0, hash);

    RSA_public_key_t *pubkey;
    RSA_private_key_t *privkey;


    if (init_RSA_pubkey (&pubkey)) {
        fprintf (stderr, "\nError: impossible to initialize an RSA public key\n");
        return EXIT_FAILURE;
    }

    if (init_RSA_privkey (&privkey)) {
        fprintf (stderr, "\nError: impossible to initialize an RSA private key\n");
        return EXIT_FAILURE;
    }

    /* Key generation procedure */
    generate_textbookRSA_keys (pubkey, privkey);

    generate_textbookRSA_CRT_signature (s, msg, privkey);

    if ( !verify_textbookRSA_standard_signature (s, msg, pubkey) ) {
        fprintf (stderr, "\nError: signature not valid\n");
    }

    generate_fault_RSACRT_signature (s, msg, privkey);

    if ( !verify_textbookRSA_standard_signature (s, msg, pubkey) ) {
        fprintf (stderr, "\nError: signature not valid\n");
        fprintf (stderr, "Attack begin...\n");

        /* Make $p = \textrm{GCD}(S^e - h(m), n)$ */
        mpz_powm (se, s, pubkey->e, pubkey->n);
        mpz_sub (se, se, h);
        mpz_gcd (p, se, pubkey->n);
        mpz_cdiv_q (q, pubkey->n, p);

        TRACEVAR (p, "p");
        TRACEVAR (privkey->p, "privkey->p");

        TRACEVAR (q, "q");
        TRACEVAR (privkey->q, "privkey->q");

        if ( mpz_cmp (p, privkey->p) == 0 &&
             mpz_cmp (q, privkey->q) == 0 ) {
            printf("\n**********************");
            printf("\n* Successful attack! *");
            printf("\n**********************\n");
        } else {
            printf("\n**********************");
            printf("\n*   Failed attack!   *");
            printf("\n**********************\n");
        }
    }

    printf("generate_RSACRT_signature_shamir");
    generate_RSACRT_signature_shamir (s, msg, privkey);
    TRACEVAR (s, "s");
    if ( !verify_textbookRSA_standard_signature (s, msg, pubkey) ) {
        fprintf (stderr, "\nError: signature not valid\n");
    }

    printf("generate_textbookRSA_CRT_signature");
    generate_textbookRSA_CRT_signature (s, msg, privkey);
    TRACEVAR (s, "s");
    if ( !verify_textbookRSA_standard_signature (s, msg, pubkey) ) {
        fprintf (stderr, "\nError: signature not valid\n");
    }

    /* Destroy keys */
    clear_RSA_pubkey (pubkey);
    clear_RSA_privkey (privkey);

    mpz_clears (s, p, q, h, se, NULL);

    return EXIT_SUCCESS;
}
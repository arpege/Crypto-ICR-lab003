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

    /* Destroy keys */
    clear_RSA_pubkey (pubkey);
    clear_RSA_privkey (privkey);

    return EXIT_SUCCESS;
}
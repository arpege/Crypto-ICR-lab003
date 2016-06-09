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
    printf("ICR - labo 3!\n");
    unsigned long   start_time_std,
                    end_time_std,
                    start_time_crt,
                    end_time_crt;
    mpz_t m, s;
    RSA_public_key_t *pubkey;
    RSA_private_key_t *privkey;

    char msg[] = "ICR - labo 3 RSA signature";

    /* Initialization of all variables */
    mpz_inits (m, s, NULL);

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

    generate_textbookRSA_standard_signature (s, msg, privkey);

    printf ("\nRSA-CRT signature:");
    generate_textbookRSA_CRT_signature (s, msg, privkey);

    if ( !verify_textbookRSA_standard_signature (s, msg, pubkey) ) {
        fprintf (stderr, "\nError: signature not valid\n");
    }

    char msg2[] = "New message";

    if ( !verify_textbookRSA_standard_signature (s, msg2, pubkey) ) {
        fprintf (stderr, "\nError: signature not valid\n");
    }

    /* Speed test */
    start_time_std = my_ftime();
    for (int i = 0; i < 10000; i++) {
        generate_textbookRSA_standard_signature (s, msg, privkey);
    }
    end_time_std = my_ftime() - start_time_std;

    start_time_crt = my_ftime();
    for (int i = 0; i < 10000; i++) {
        generate_textbookRSA_CRT_signature (s, msg, privkey);
    }
    end_time_crt = my_ftime() - start_time_crt;

    printf("\nStandard=%g\tCRT=%g\n",
                end_time_std/1000.0,
                end_time_crt/1000.0);

    clear_RSA_pubkey (pubkey);
    clear_RSA_privkey (privkey);

    mpz_clears (m, s, NULL);

    return EXIT_SUCCESS;
}
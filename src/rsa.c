#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <fcntl.h>
#include <fcntl.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <gmp.h>
#include "./sha256.c"

#define RSA_KEY_BITLENGTH       2048
#define RSA_KEY_BYTELENGTH      (RSA_KEY_BITLENGTH >> 3)
#define RSA_PUBLIC_EXPONENT     65537

#define TRACE

#ifdef TRACE
#define TRACEVAR(x,msg) {fprintf (stdout, "\n"msg" : "); \
    mpz_out_str (stdout, 16, (x)); \
    fprintf (stdout, "\n"); }
#else
#define TRACEVAR(x,msg)
#endif /* TRACE */

typedef struct {
    mpz_t n;
    mpz_t e;
} RSA_public_key_t;

typedef struct {
    mpz_t p;
    mpz_t q;
    mpz_t dP;
    mpz_t dQ;
    mpz_t qInv;
    mpz_t n;
    mpz_t d;
} RSA_private_key_t;

int generate_textbookRSA_keys (RSA_public_key_t *pubkey,
                               RSA_private_key_t *privkey)
{
    mpz_t p, q, pm1qm1, pm1, qm1, r, gcd, m1;
    char rnd[RSA_KEY_BYTELENGTH >> 1];
    int fd;

    assert (pubkey != NULL);
    assert (privkey != NULL);

    mpz_inits (p, q, pm1, qm1, pm1qm1, r, gcd, NULL);

    /* A cryptographically secure random number generator is required */ 
    /* to generate a key. This method will work on most Unix-like */ 
    /* operating systems, but not on Windows operating systems. */ 
    if ( (fd = open ("/dev/urandom", O_RDONLY)) == -1) {
        perror ("Error: impossible to open the randomness source");
        return EXIT_FAILURE; 
    }

    do {
        /* For a 2048-bit RSA key, we need primes of size 1024 bits, or 128 */
        /* bytes. For this, we first generate 128 random bytes. */
        if ( read (fd, rnd, RSA_KEY_BYTELENGTH >> 1) != (RSA_KEY_BYTELENGTH >> 1) ) {
            perror ("Error: impossible to read enough random bytes");
            /* Don’t forget to close the file descriptor */
            if ( close (fd) ) {
                perror ("Error: impossible to close the randomness source");
            }
            return EXIT_FAILURE; 
        }

        /* We ensure that the random number has *exactly* 1024 bits */
        rnd[0] |= 0x80;

        /* Transformation of an array of bytes into a big number */ 
        /* according to a big-endian, most significant byte first */ 
        /* strategy. */ 
        mpz_import (r, 128, 1, 1, 1, 0, rnd);

        /* We look for the first prime number that is greater than */ 
        /* our random number */ 
        mpz_nextprime (p, r);
        TRACEVAR (r, "r");
        TRACEVAR (p, "p");

        /* Performing the same operation to generate the second */ 
        /* prime number. */ 
        if ( read (fd, rnd, RSA_KEY_BYTELENGTH >> 1) !=
            (RSA_KEY_BYTELENGTH >> 1) ) {
            perror ("Error: impossible to read enough random bytes");

            if ( close (fd) ) {
                perror ("Error: impossible to close the randomness source");
            }
            return EXIT_FAILURE;
        }

        /* We ensure that the random number has *exactly* 1024 bits */
        rnd[0] |= 0x80;

        mpz_import (r, 128, 1, 1, 1, 0, rnd);
        mpz_nextprime (q, r);
        TRACEVAR (r, "r");
        TRACEVAR (q, "q");

        /* n = p*q */
        mpz_mul (pubkey->n, p, q);

        /* Copying n to the private key structure */
        mpz_set (privkey->n, pubkey->n);
        TRACEVAR (pubkey->n, "n");

        mpz_set_ui (pubkey->e, RSA_PUBLIC_EXPONENT);
        TRACEVAR (pubkey->e, "e");

        /* Computing p-1 */
        mpz_sub_ui (pm1, p, 1);
        /* Computing q-1 */
        mpz_sub_ui (qm1, q, 1);
        /* Computing (p-1)*(q-1) */
        mpz_mul (pm1qm1, pm1, qm1);

        mpz_set (privkey->p, p);
        mpz_set (privkey->q, q);

        /* dP = (1/e) mod (p-1) */
        mpz_invert (privkey->dP, pubkey->e, pm1);
        TRACEVAR (privkey->dP, "dP");
        /* dQ = (1/e) mod (q-1) */
        mpz_invert (privkey->dQ, pubkey->e, qm1);
        TRACEVAR (privkey->dQ, "dQ");
        /* qInv = (1/q) mod p */
        mpz_invert (privkey->qInv, privkey->q, p);
        TRACEVAR (privkey->qInv, "qInv");

        TRACEVAR (pm1, "p-1");
        TRACEVAR (qm1, "q-1");
        TRACEVAR (pm1qm1, "(p-1)(q-1)");
        /* Ensuring that gcd (e, (p-1)(q-1)) == 1, otherwise */
        /* we cannot invert d mod (p-1)(q-1) */
        mpz_gcd (gcd, pm1qm1, pubkey->e);
    
    } while (mpz_cmp_ui (gcd, 1));

    /* Now, we don’t need the randomness source anymore */
    if(close(fd)){
        perror ("Error: impossible to close the randomness source");
        return EXIT_FAILURE;
    }

    /* Computing d = e^{-1} mod (p-1)(q-1) */
    mpz_invert (privkey->d, pubkey->e, pm1qm1);
    TRACEVAR (privkey->d, "d");

    mpz_clears (p, q, pm1, qm1, pm1qm1, r, gcd, NULL);

    return EXIT_SUCCESS ;
}

int init_RSA_privkey (RSA_private_key_t **privkey)
{
    RSA_private_key_t *ptr;
    if ( (ptr = malloc (sizeof (RSA_private_key_t))) == NULL) {
        perror ("Error: impossible to allocate RSA private key structure"); 
        return EXIT_FAILURE;
    }

    mpz_inits (ptr->p, 
               ptr->q, 
               ptr->dP, 
               ptr->dQ, 
               ptr->qInv, 
               ptr->n, 
               ptr->d, 
               NULL);

    *privkey = ptr;

    return EXIT_SUCCESS;
}

void clear_RSA_pubkey (RSA_public_key_t *pubkey)
{
    mpz_clears (pubkey->n, pubkey->e, NULL);
    free (pubkey);
}

void clear_RSA_privkey (RSA_private_key_t *privkey)
{
    mpz_clears (privkey->p, 
                privkey->q, 
                privkey->dP, 
                privkey->dQ, 
                privkey->qInv, 
                privkey->n, 
                privkey->d, 
                NULL);
    free (privkey);
}

int init_RSA_pubkey (RSA_public_key_t **pubkey) 
{
    RSA_public_key_t *ptr;

    if ( (ptr = malloc (sizeof (RSA_public_key_t))) == NULL) {
        perror ("Error: impossible to allocate RSA public key structure"); 
        return EXIT_FAILURE;
    }
    mpz_inits (ptr->n, ptr->e, NULL); 
    
    *pubkey = ptr;

    return EXIT_SUCCESS;
}



int generate_textbookRSA_standard_signature (mpz_t s,
                                             uchar data[],
                                             const RSA_private_key_t *privkey)
{
    /* Process of signing the message m (which is BigInteger) : */ 
    /* it uses the secret key $sk=(p,q,d)$ so that $s = m^d mod n$ where $n=p*q$. */
    assert(s != NULL);
    assert(data != NULL);
    assert(privkey != NULL);

    SHA256_CTX *sha256 = malloc (sizeof (SHA256_CTX));
    uchar hash[32];
    mpz_t m;

    mpz_inits (m, NULL);

    sha256_init(sha256);
    sha256_update(sha256, data, strlen(data));
    sha256_final(sha256, hash);

    mpz_import (m, sizeof (hash), 1, 1, 1, 0, hash);

    /* Computing $s = m^d mod n$ */
    mpz_powm (s, m, privkey->d, privkey->n);

    TRACEVAR (s, "s");

    mpz_clears (m, NULL);
    return EXIT_SUCCESS;
}


int generate_textbookRSA_CRT_signature (mpz_t s,
                                        uchar data[],
                                        const RSA_private_key_t *privkey)
{
    /* Process of signing the message m (which is BigInteger) : */ 
    /* it uses the secret key $sk=(p,q,d)$ so that $s = m^d mod n$ where $n=p*q$. */
    assert(s != NULL);
    assert(data != NULL);
    assert(privkey != NULL);

    SHA256_CTX *sha256 = malloc (sizeof (SHA256_CTX));
    uchar hash[32];
    mpz_t m, m1, m2, h, hq, qh, m1m2;

    mpz_inits (m, m1, m2, h, hq, qh, m1m2, NULL);

    sha256_init(sha256);
    sha256_update(sha256, data, strlen(data));
    sha256_final(sha256, hash);

    mpz_import (m, sizeof (hash), 1, 1, 1, 0, hash);

    /* Computing $s = m^d mod n$ with RSA-CRT */
    //mpz_powm (s, m, privkey->d, privkey->n);
    /* 
    m1 = m^dP mod p
    m2 = m^dQ mod q
    h = qInv * (m1 - m2) mod p
    s = m2 + h * q */
    mpz_powm (m1, m, privkey->dP, privkey->p);
    mpz_powm (m2, m, privkey->dQ, privkey->q);
    mpz_sub (m1m2, m1, m2);
    mpz_mul (qh, privkey->qInv, m1m2);
    mpz_powm_ui (h, qh, 1, privkey->p);
    mpz_mul (hq, h, privkey->q);
    mpz_add (s, m2, hq);


    TRACEVAR (s, "s");

    mpz_clears (m, m1, m2, h, hq, qh, m1m2, NULL);
    return EXIT_SUCCESS;
}


int verify_textbookRSA_standard_signature (mpz_t s,
                                           uchar data[],
                                           RSA_public_key_t *pubkey) 
{
    /* Uses sender A's public key (n, e) to compute integer $v = s^e mod n$. */
    /* Extracts the message digest from this integer. */
    /* Independently computes the message digest of the information that has been signed. */
    /* If both message digests are identical, the signature is valid. */
    assert(s != NULL);
    assert(data != NULL);
    assert(pubkey != NULL);

    SHA256_CTX *sha256 = malloc (sizeof (SHA256_CTX));
    uchar hash[32];
    mpz_t m, v;

    mpz_inits (m, v, NULL);

    sha256_init(sha256);
    sha256_update(sha256, data, strlen(data));
    sha256_final(sha256, hash);

    mpz_import (m, sizeof (hash), 1, 1, 1, 0, hash);

    /* Computing $v = s^e mod n$ */
    mpz_powm (v, s, pubkey->e, pubkey->n);

    TRACEVAR (v, "v");
    TRACEVAR (m, "m");

    /* $s^e mon n = Hash(m) mod n$ */
    if ( mpz_cmp (v, m) ) {
        mpz_clears (m, v, NULL);
        return EXIT_SUCCESS;
    } else {
        mpz_clears (m, v, NULL);
        return EXIT_FAILURE;
    }
}

int main ()
{
    printf("ICR - labo 3!\n");
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

    clear_RSA_pubkey (pubkey);
    clear_RSA_privkey (privkey);

    mpz_clears (m, s, NULL);

    return EXIT_SUCCESS;
}
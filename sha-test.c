/*
 * Test for various crypt functions.
 *
 * (C) 2014 Syntech Systems, Inc., Jate Sujjavanich
 */

#include "crypt-fips.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/fips.h>


int main ()
{
	char *hashed = 0;

	if (!FIPS_mode_set(1))
	  {
	    ERR_load_crypto_strings();
	    ERR_print_errors_fp(stderr);
	    exit(1);
	  }
	else
	  printf("*** IN FIPS MODE***\n");

	hashed = (char *)crypt("123456", "$6$Lbwbyd56");
	printf("crypt sha512(3) result: %s\n", hashed);

        hashed = (char *)crypt("123456", "$5$Lbwbyd56");
        printf("crypt sha256(3) result: %s\n", hashed);
        if (hashed == NULL) {
            printf("errno = %d\n", errno);
        }

        hashed = (char *)crypt("123456", "$1$Lbwbyd56");
        printf("crypt md5   (3) result: %s\n", hashed);
        if (hashed == NULL) {
            printf("errno = %d\n", errno);
        }
	return 0;
}

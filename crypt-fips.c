/*
 * crypt-fips.c
 *
 * (C) 2014 Syntech Systems, Inc., Jate Sujjavanich
 *
 *  Provides an interface to OpenSSL/FIPS implementation of crypt functions.
 */

#include <errno.h>
#include <unistd.h>
#include <stdio.h>

/* Steal crypt, crypt_r, __crypt_r from eglibc */
/* Some defines to get things working */
#undef __OPTION_EGLIBC_CRYPT_UFC
/* not available on eglibc 2.11.1 Ubuntu 10.04 */
#undef __set_errno
#define __set_errno(val) errno = (val)
/* FIPS enabled macro */
#define fips_enabled_p FIPS_mode
/* Copy definition from eglibc/libc/crypt/crypt.h */
struct crypt_data
  {
    char keysched[16 * 8];
    char sb0[32768];
    char sb1[32768];
    char sb2[32768];
    char sb3[32768];
    /* end-of-aligment-critical-data */
    char crypt_3_buf[14];
    char current_salt[2];
    long int current_saltbits;
    int  direction, initialized;
  };

/* Define our magic string to mark salt for MD5 encryption
   replacement.  This is meant to be the same as for other MD5 based
   encryption implementations.  */
static const char md5_salt_prefix[] = "$1$";

/* Magic string for SHA256 encryption.  */
static const char sha256_salt_prefix[] = "$5$";

/* Magic string for SHA512 encryption.  */
static const char sha512_salt_prefix[] = "$6$";

char *
__crypt_r (key, salt, data)
     const char *key;
     const char *salt;
     struct crypt_data * __restrict data;
{
  /* Try to find out whether we have to use MD5 encryption replacement.  */
  if (strncmp (md5_salt_prefix, salt, sizeof (md5_salt_prefix) - 1) == 0)
   {
     /* FIPS rules out MD5 password encryption.  */
     if (fips_enabled_p ())
       {
         __set_errno (EPERM);
         return NULL;
       }
     return __md5_crypt_r (key, salt, (char *) data,
                           sizeof (struct crypt_data));
   }
  /* Try to find out whether we have to use SHA256 encryption replacement.  */
  if (strncmp (sha256_salt_prefix, salt, sizeof (sha256_salt_prefix) - 1) == 0)
    return __sha256_crypt_r (key, salt, (char *) data,
                             sizeof (struct crypt_data));

  /* Try to find out whether we have to use SHA512 encryption replacement.  */
  if (strncmp (sha512_salt_prefix, salt, sizeof (sha512_salt_prefix) - 1) == 0)
    return __sha512_crypt_r (key, salt, (char *) data,
                             sizeof (struct crypt_data));

  __set_errno (ENOSYS);
  return NULL;
}

char * crypt_r (const char *key, const char *salt, struct crypt_data * __restrict data)
__attribute__ ((weak, alias ("__crypt_r")));

char *
crypt (key, salt)
     const char *key;
     const char *salt;
{
  /* Try to find out whether we have to use MD5 encryption replacement.  */
  if (strncmp (md5_salt_prefix, salt, sizeof (md5_salt_prefix) - 1) == 0
      /* Let __crypt_r deal with the error code if FIPS is enabled.  */
      && !fips_enabled_p ())
    return __md5_crypt (key, salt);

  /* Try to find out whether we have to use SHA256 encryption replacement.  */
  if (strncmp (sha256_salt_prefix, salt, sizeof (sha256_salt_prefix) - 1) == 0)
    return __sha256_crypt (key, salt);

  /* Try to find out whether we have to use SHA512 encryption replacement.  */
  if (strncmp (sha512_salt_prefix, salt, sizeof (sha512_salt_prefix) - 1) == 0)
    return __sha512_crypt (key, salt);

  __set_errno (ENOSYS);
  return NULL;
}

char * fcrypt(const char *key, const char *salt) __attribute__ ((weak, alias ("crypt")));

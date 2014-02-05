# Makefile

# march and mtune added for cmov
CPUFLAGS=-march=i686 -mtune=generic
CFLAGS?=$(CPUFLAGS) -fno-builtin -Iinclude_libc/ -I$(FIPS_INCLUDE)

# Set DEBUG=1 during make for debugging
ifeq ($(DEBUG),1)
CFLAGS += -g -O0
endif

#
# Main executable. Currently used for test.
#
OBJS=sha-test.o
EXEC=sha-test
LIBS=

# Cert executable
CERT_OBJS=cert.o
CERT_EXEC=cert

# OpenSSL FIPS Associated vars   
FIPS_DIR=/usr/local/ssl/fips
FIPS_INCLUDE=$(FIPS_DIR)/include
FIPS_LIB=$(FIPS_DIR)/lib

#
# Variables to control crypt-fips so
#
CRYPT_FIPS_SO=libcrypt-2.17fips.so
CRYPT_FIPS_SONAME=libcrypt.so.1
CRYPT_FIPS_OBJS=crypt.o crypt-fips.o crypt_util.o md5-crypt.o sha256-crypt.o sha512-crypt.o

all: $(EXEC) $(CERT_EXEC)

$(EXEC): $(CRYPT_FIPS_SO) $(OBJS) libcrypt.so.1
	$(CC) -o $(EXEC) $(OBJS) /lib/$(CRYPT_FIPS_SONAME) -L$(FIPS_LIB) -lcrypto -lssl $(LIBS)

$(CERT_EXEC): $(CERT_OBJS) $(CRYPT_FIPS_SONAME)
	$(CC) -o $@ $(CERT_OBJS) /lib/$(CRYPT_FIPS_SONAME) -L$(FIPS_LIB) -lcrypto -lssl $(LIBS)

$(CRYPT_FIPS_SONAME):
	ln -sf $(CRYPT_FIPS_SO) $@

$(CRYPT_FIPS_SO): $(CRYPT_FIPS_OBJS)
	gcc -shared -Wl,-soname,$(CRYPT_FIPS_SONAME) -Wl,--version-script=Versions \
		-o $(CRYPT_FIPS_SO) $(CRYPT_FIPS_OBJS) \
		-L$(FIPS_LIB) -lcrypto -lssl

crypt_util.o crypt.o:
	echo Trying $@ $*
	$(CC) $(CFLAGS) -imacros include_libc/libc-symbols.h -c $*.c -o $@

clean:
	rm -f $(EXEC) $(CRYPT_FIPS_SO) $(CRYPT_FIPS_SONAME) $(CRYPT_FIPS_OBJS) $(CERT_EXEC) *.o

# Dependencies
cert.c: crypt.h
crypt.c: ufc-crypt.h crypt.h crypt-private.h
crypt-fips.c: crypt-fips.h
crypt_util.c: ufc-crypt.h
md5-crypt.c: md5.h
sha256-crypt.c: sha256.h
sha512-crypt.c: sha512.h
sha-test.c: crypt-fips.h

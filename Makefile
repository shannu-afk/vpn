CC = gcc
CFLAGS = -Wall -Iinclude -Imbedtls-2.28.7/include
LDFLAGS = -lws2_32
MBED_SRC = \
    mbedtls-2.28.7/library/aes.c \
    mbedtls-2.28.7/library/aesni.c \
    mbedtls-2.28.7/library/arc4.c \
    mbedtls-2.28.7/library/aria.c \
    mbedtls-2.28.7/library/asn1parse.c \
    mbedtls-2.28.7/library/asn1write.c \
    mbedtls-2.28.7/library/base64.c \
    mbedtls-2.28.7/library/bignum.c \
    mbedtls-2.28.7/library/blowfish.c \
    mbedtls-2.28.7/library/camellia.c \
    mbedtls-2.28.7/library/ccm.c \
    mbedtls-2.28.7/library/certs.c \
    mbedtls-2.28.7/library/chacha20.c \
    mbedtls-2.28.7/library/chachapoly.c \
    mbedtls-2.28.7/library/cipher.c \
    mbedtls-2.28.7/library/cipher_wrap.c \
    mbedtls-2.28.7/library/cmac.c \
    mbedtls-2.28.7/library/ctr_drbg.c \
    mbedtls-2.28.7/library/debug.c \
    mbedtls-2.28.7/library/des.c \
    mbedtls-2.28.7/library/entropy.c \
    mbedtls-2.28.7/library/entropy_poll.c \
    mbedtls-2.28.7/library/error.c \
    mbedtls-2.28.7/library/gcm.c \
    mbedtls-2.28.7/library/hkdf.c \
    mbedtls-2.28.7/library/hmac_drbg.c \
    mbedtls-2.28.7/library/md.c \
    mbedtls-2.28.7/library/md2.c \
    mbedtls-2.28.7/library/md4.c \
    mbedtls-2.28.7/library/md5.c \
    mbedtls-2.28.7/library/net_sockets.c \
    mbedtls-2.28.7/library/oid.c \
    mbedtls-2.28.7/library/padlock.c \
    mbedtls-2.28.7/library/pem.c \
    mbedtls-2.28.7/library/pk.c \
    mbedtls-2.28.7/library/pkparse.c \
    mbedtls-2.28.7/library/pkwrite.c \
    mbedtls-2.28.7/library/pkcs5.c \
    mbedtls-2.28.7/library/pkcs12.c \
    mbedtls-2.28.7/library/platform.c \
    mbedtls-2.28.7/library/platform_util.c \
    mbedtls-2.28.7/library/poly1305.c \
    mbedtls-2.28.7/library/ripemd160.c \
    mbedtls-2.28.7/library/rsa.c \
    mbedtls-2.28.7/library/rsa_internal.c \
    mbedtls-2.28.7/library/sha1.c \
    mbedtls-2.28.7/library/sha256.c \
    mbedtls-2.28.7/library/sha512.c \
    mbedtls-2.28.7/library/constant_time.c \
    mbedtls-2.28.7/library/ecp.c \
    mbedtls-2.28.7/library/ecp_curves.c \
    mbedtls-2.28.7/library/ecdh.c \
    mbedtls-2.28.7/library/ecdsa.c \
    mbedtls-2.28.7/library/timing.c \
    mbedtls-2.28.7/library/x509.c \
    mbedtls-2.28.7/library/x509_crt.c \
    mbedtls-2.28.7/library/x509_create.c \
    mbedtls-2.28.7/library/x509write_crt.c \
    mbedtls-2.28.7/library/x509write_csr.c \
    mbedtls-2.28.7/library/x509_csr.c \
    mbedtls-2.28.7/library/pk_wrap.c \
    mbedtls-2.28.7/library/ssl_tls.c \
    mbedtls-2.28.7/library/ssl_cli.c \
    mbedtls-2.28.7/library/dhm.c\
    mbedtls-2.28.7/library/ssl_srv.c \
    mbedtls-2.28.7/library/ssl_msg.c \
    mbedtls-2.28.7/library/ssl_ciphersuites.c \
    mbedtls-2.28.7/library/ssl_cookie.c \
    mbedtls-2.28.7/library/ssl_ticket.c \
    mbedtls-2.28.7/library/ssl_tls13_keys.c

SRC = src/main.c src/vpn.c src/network.c src/log.c src/auth.c src/crypto.c
EXEC = vpn
all: $(EXEC).exe server.exe

$(EXEC).exe: $(SRC) $(MBED_SRC)
	$(CC) $(CFLAGS) $(SRC) $(MBED_SRC) -o $(EXEC).exe $(LDFLAGS)

server.exe: server.c src/crypto.c auth_utils.c $(MBED_SRC)
	$(CC) $(CFLAGS) server.c src/crypto.c auth_utils.c $(MBED_SRC) -o server.exe $(LDFLAGS)

clean:
	del /Q *.exe *.o 2>nul

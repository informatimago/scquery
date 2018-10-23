OBJECTS=scquery.o smartcard-certificate.o certificate-list.o pkcs11errors.o pkcs11module.o error.o
CFLAGS_DEBUG=-g3 -ggdb
CFLAGS=--std=c11 $(CFLAGS_DEBUG)
LDFLAGS=-ldl
all:scquery
scquery:$(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) $(LDFLAGS) -o $@
scquery.o: scquery.c smartcard-certificate.h
smartcard-certificate.o: smartcard-certificate.c smartcard-certificate.h error.h certificate-list.h
certificate-list.o: certificate-list.c certificate-list.h error.h
pkcs11errors.o:pkcs11errors.c pkcs11errors.h
pkcs11module.o:pkcs11module.c pkcs11module.h pkcs11errors.h error.h
error.o:error.c error.h
clean:
	rm -f *.o scquery core

OBJECTS=scquery.o smartcard-certificate.o pkcs11errors.o pkcs11module.o error.o
CFLAGS=-g3
LDFLAGS=-ldl
all:scquery
scquery:$(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) $(LDFLAGS) -o $@
scquery.o: scquery.c smartcard-certificate.h
smartcard-certificate.o: smartcard-certificate.c smartcard-certificate.h pkcs11errors.h error.h
pkcs11errors.o:pkcs11errors.c pkcs11errors.h
pkcs11module.o:pkcs11module.c pkcs11module.h pkcs11errors.h error.h
error.o:error.c error.h

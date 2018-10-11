OBJECTS=scquery.o smartcard-certificate.o pkcs11errors.o
CFLAGS=-I/opt/local/include
all:scquery
scquery:$(OBJECTS)
scquery.o: scquery.c smartcard-certificate.h
smartcard-certificate.o: smartcard-certificate.c smartcard-certificate.h pkcs11errors.h
pkcs11errors.o:pkcs11errors.c pkcs11errors.h

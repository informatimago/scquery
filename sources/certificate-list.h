#ifndef CERTIFICATE_LIST_H
#define CERTIFICATE_LIST_H
#include <stddef.h>
#include <pkcs11-helper-1.0/pkcs11.h>

typedef struct {
    CK_ULONG size;
    CK_BYTE* data;
} buffer_t, *buffer;

typedef struct {
    CK_SLOT_ID          slot_id;
    char*               token_label;
    char*               id;
    char*               label;
    CK_CERTIFICATE_TYPE type;
    buffer              issuer;
    buffer              subject;
    buffer              value;
    CK_KEY_TYPE         key_type;
} smartcard_certificate_t, *smartcard_certificate;

typedef struct certificate_list {
    smartcard_certificate certificate;
    struct certificate_list* rest;
} certificate_list_t, *certificate_list;

smartcard_certificate certificate_first(certificate_list list);
certificate_list      certificate_rest(certificate_list list);

#define DO_CERTIFICATE_LIST(certificate,current,list)                                   \
    for((current=list,                                                                  \
         certificate=((current!=NULL)?certificate_first(current):CK_INVALID_HANDLE));   \
        (current!=NULL);                                                                \
        (current=certificate_rest(current),                                             \
         certificate=((current!=NULL)?certificate_first(current):CK_INVALID_HANDLE)))

/* certificate_list_cons
allocates a new list node containing the certificate and the next list. */
certificate_list certificate_list_cons(smartcard_certificate certificate,certificate_list rest);

/* certificate_list_deepfree
deepfrees the certificates and the list nodes */
void certificate_list_deepfree(certificate_list list);

/* certificate_list_free
frees only the current list nodes (not the next ones). */
void certificate_list_free(certificate_list list);

/* certificate_deepfree
deepfrees smartcard_certificate structure and all its fields. */
void certificate_deepfree(smartcard_certificate certificate);


/* certificate_allocate
allocates an empty smartcard_certificate structure. */
smartcard_certificate certificate_allocate();

/* certificate_new
allocates and initialize a new smartcard_certificate */
smartcard_certificate certificate_new(CK_SLOT_ID          slot_id,
                                      char*               token_label,
                                      char*               id,
                                      char*               label,
                                      CK_CERTIFICATE_TYPE type,
                                      buffer              issuer,
                                      buffer              subject,
                                      buffer              value,
                                      CK_KEY_TYPE         key_type);

/* certificate_free
frees only the smartcard_certificate structure (not the fields). */
void certificate_free(smartcard_certificate certificate);

#endif

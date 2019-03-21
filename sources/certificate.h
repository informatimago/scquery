#ifndef CERTIFICATE_H
#define CERTIFICATE_H
#include <stddef.h>
#include "buffer.h"

typedef struct {
    CK_SLOT_ID          slot_id;
	char*               slot_description; /* ReaderName */
	char*               token_label;      /* CardName */
	char*               token_serial;
    char*               id;
    char*               label;
    CK_CERTIFICATE_TYPE type;
    buffer              issuer;
    buffer              subject;
    buffer              value;
    CK_KEY_TYPE         key_type;
	int                 protected_authentication_path;
} smartcard_certificate_t, *smartcard_certificate;

/* certificate_new
allocates and initialize a new smartcard_certificate */
smartcard_certificate certificate_new(CK_SLOT_ID          slot_id,
                                      char*               slot_description,
                                      char*               token_label,
                                      char*               token_serial,
                                      char*               id,
                                      char*               label,
                                      CK_CERTIFICATE_TYPE type,
                                      buffer              issuer,
                                      buffer              subject,
                                      buffer              value,
                                      CK_KEY_TYPE         key_type,
                                      int                 protected_authentication_path);

/* certificate_free
frees only the smartcard_certificate structure (not the fields). */
void certificate_free(smartcard_certificate certificate);

/* certificate_deepfree
deepfrees smartcard_certificate structure and all its fields. */
void certificate_deepfree(smartcard_certificate certificate);

/* certificate_allocate
allocates an empty smartcard_certificate structure. */
smartcard_certificate certificate_allocate();

#endif

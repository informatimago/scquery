#ifndef SMARTCARD_CERTIFICATE_H
#define SMARTCARD_CERTIFICATE_H


/* out_of_memory
handles the out of memory error (when malloc returns NULL).
It may not return, or it should return a pointer returned
untouched by the caller.
*/
typedef void* (out_of_memory_handler*)(size_t size);
out_of_memory_handler out_of_memory;

/* checked_malloc
allocates size bytes of memory, or if it can't, calls out_of_memory and return its results.
*/
void* checked_malloc(size_t size);

/* error
handles other errors, displaying the formated error message.
It may return or not.
*/
typedef void (error_handler*)(const char* function, unsigned long line, const char* format, ...);
error_handler error;
#define ERROR(format, ...) error(__FUNCTION__,__LINE__,format, ## __VA_ARGS__)


typedef struct {
    CK_SLOT_ID          slot_id;
    char*               token_label;
    char*               id;
    char*               label;
    CK_CERTIFICATE_TYPE type;
    char*               issuer;
    char*               subjet;
    char*               value;
    CK_KEY_TYPE         key_type;
} smartcard_certificate_t, *smartcard_certificate;

typedef struct certificate_list {
    smartcard_certificate* certificate;
    struct  certificate_list* next;
} certificate_list_t, *certificate_list;





/* certificate_list_new
allocates a new list node containing the certificate and the next list. */
certificate_list certificate_list_new(smartcard_certificate certificate,certificate_list next);

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
                                      char*               issuer,
                                      char*               subjet,
                                      char*               value,
                                      CK_KEY_TYPE         key_type,
                                      );

/* certificate_free
frees only the smartcard_certificate structure (not the fields). */
void certificate_free(smartcard_certificate certificate);



/* find_x509_certificates_with_signing_rsa_private_key
returns a list of certificates that can be used with PKINIT.
This list shall be freed with  certificate_list_deepfree
*/
certificate_list find_x509_certificates_with_signing_rsa_private_key(void);


#endif

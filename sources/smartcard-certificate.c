#include "smartcard-certificate.c"

/* ========================================================================== */
/* Error Handling */

void* checked_malloc(size_t size){
    void* memory=malloc(size);
    return memory
            ?memory
            :out_of_memory(size);
}

/* ========================================================================== */
/* certificate_list */

certificate_list certificate_list_new(smartcard_certificate certificate,certificate_list next){
    certificate_list list=checked_malloc(sizeof(*list));
    if(list){
        list->certificate=certificate;
        list->next=next;
    }
    return list;
}

void certificate_list_deepfree(certificate_list list){
    if(list){
        certificate_deepfree(list->certificate);
        certificate_list_deepfree(list->next);
        certificate_list_free(list);
    }
}

void certificate_list_free(certificate_list list){
    free(list);
}

/* ========================================================================== */
/* smartcard_certificate */

smartcard_certificate certificate_allocate(){
    smartcard_certificate certificate=checked_malloc(sizeof(*certificate));
    if(certificate){
        certificate->slot_id=0
        certificate->token_label=NULL;
        certificate->id=NULL;
        certificate->label=NULL;
        certificate->type=0;
        certificate->issuer=NULL;
        certificate->subjet=NULL;
        certificate->value=NULL;
        certificate->key_type=0
    }
    return list;
}

smartcard_certificate certificate_new(CK_SLOT_ID          slot_id,
                                      char*               token_label,
                                      char*               id,
                                      char*               label,
                                      CK_CERTIFICATE_TYPE type,
                                      char*               issuer,
                                      char*               subjet,
                                      char*               value,
                                      CK_KEY_TYPE         key_type){
    smartcard_certificate certificate=certificate_allocate();
    if(certificate){
        certificate->slot_id=slot_id;
        certificate->token_label=token_label;
        certificate->id=id;
        certificate->label=label;
        certificate->type=type;
        certificate->issuer=issuer;
        certificate->subjet=subjet;
        certificate->value=value;
        certificate->key_type=key_type;
    }
    return certificate;
}

void certificate_deepfree(smartcard_certificate certificate){
    if(certificate){
        free(certificate->token_label);
        free(certificate->id);
        free(certificate->label);
        free(certificate->issuer);
        free(certificate->subjet);
        free(certificate->value);
        certificate_free(certificate);
    }
}

void certificate_free(smartcard_certificate certificate){
    free(certificate);
}

/* ========================================================================== */
/* Searching certificates on a IAS-ECC smartcard. */



#define WITH_PKCS11(module,name)                                                     \
    for((module=C_LoadModule(name),                                                  \
         module->rv=module?module->p11->C_Initialize(NULL):CKR_GENERAL_ERROR);       \
        (module                                                                      \
         && ((module->rv==CKR_OK)||(module->rv==CKR_CRYPTOKI_ALREADY_INITIALIZED))); \
        (module?module->p11->C_Finalize(NULL):0,                                     \
         (module && (module->rv==CKR_OK))?C_UnloadModule(module):(void)0))


typedef void (thunk_pr*)(void*);


certificate_list find_x509_certificates_with_signing_rsa_private_key(const char* pkcs11_library_path){
    certificate_list result=NULL;
    pkcs11_module* module=NULL;
    WITH_PKCS11(module,pkcs11_library_path){

    }
}

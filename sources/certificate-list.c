#include <stdlib.h>
#include "certificate-list.h"
#include "error.h"

/* ========================================================================== */
/* certificate_list */

certificate_list certificate_list_cons(smartcard_certificate certificate,certificate_list rest){
    certificate_list list=checked_malloc(sizeof(*list));
    if(list){
        list->certificate=certificate;
        list->rest=rest;}
    return list;}

void certificate_list_deepfree(certificate_list list){
    if(list){
        certificate_deepfree(list->certificate);
        certificate_list_deepfree(list->rest);
        certificate_list_free(list);}}

void certificate_list_free(certificate_list list){
    free(list);}

smartcard_certificate certificate_first(certificate_list list){return list->certificate;}
certificate_list      certificate_rest(certificate_list list){return list->rest;}

/* ========================================================================== */
/* smartcard_certificate */

smartcard_certificate certificate_allocate(){
    smartcard_certificate certificate=checked_malloc(sizeof(*certificate));
    if(certificate){
        certificate->slot_id=0;
        certificate->token_label=NULL;
        certificate->id=NULL;
        certificate->label=NULL;
        certificate->type=0;
        certificate->issuer=NULL;
        certificate->subject=NULL;
        certificate->value=NULL;
        certificate->key_type=0;
    }
    return certificate;
}

smartcard_certificate certificate_new(CK_SLOT_ID          slot_id,
                                      char*               token_label,
                                      char*               id,
                                      char*               label,
                                      CK_CERTIFICATE_TYPE type,
                                      char*               issuer,
                                      char*               subject,
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
        certificate->subject=subject;
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
        free(certificate->subject);
        free(certificate->value);
        certificate_free(certificate);
    }
}

void certificate_free(smartcard_certificate certificate){
    free(certificate);
}

/**** THE END ****/

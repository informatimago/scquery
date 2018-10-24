#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <pkcs11-helper-1.0/pkcs11.h>
#include "smartcard-certificate.h"
#include "pkcs11module.h"
#include "pkcs11errors.h"
#include "error.h"
#include "string.h"


/* ========================================================================== */
/* Searching certificates on a IAS-ECC smartcard. */

static char* bytes_to_hexadecimal(CK_BYTE* bytes,CK_ULONG count){
	char* buffer = checked_malloc(2 * count + 1);
	char* current = buffer;
	if (buffer==NULL){
		return buffer;}
	while(count>0){
		sprintf(current, "%02x", * bytes);
		bytes++;
		current+=2;
		count--;}
	*current='\0';
	return buffer;}


CK_OBJECT_HANDLE object_handle_ensure_one(object_handle_list list,char* what){
    if((list==NULL)||(object_handle_rest(list)!=NULL)){
        WARN(0,"Something strange: there is %s %s when exactly one was expected.",
             (list==NULL)?"zero":"more than one",what);}
    return (list==NULL)
            ?CK_INVALID_HANDLE
            :object_handle_first(list);}

CK_ULONG position_of_attribute(CK_ULONG attribute_type,template* template){
    CK_ULONG i;
    for(i=0;i<template->count;i++){
        if(template->attributes[i].type==attribute_type){
            return i;}}
    return CK_UNAVAILABLE_INFORMATION;}

char* string_attribute(CK_ULONG attribute,template* template){
    CK_ULONG index=position_of_attribute(attribute,template);
    if(index==CK_UNAVAILABLE_INFORMATION){
        const char* text="unavailable";
        return check_memory(strdup(text),1+strlen(text));}
    else{
        return check_memory(strndup(template->attributes[index].pValue,
                                    template->attributes[index].ulValueLen),
                            template->attributes[index].ulValueLen+1);}}

certificate_list find_x509_certificates_with_signing_rsa_private_key_in_slot(pkcs11_module* module,
                                                                             CK_ULONG slot_id,
                                                                             CK_TOKEN_INFO* info,
                                                                             CK_SESSION_HANDLE session,
                                                                             certificate_list result){
    CK_OBJECT_CLASS oclass=CKO_PRIVATE_KEY;
    CK_BBOOL sign=CK_TRUE;
    CK_KEY_TYPE ktype=CKK_RSA;
    template privkey_template={3,
                               {{CKA_CLASS,&oclass,sizeof(oclass)},
                                {CKA_SIGN,&sign,sizeof(sign)},
                                {CKA_KEY_TYPE,&ktype,sizeof(ktype)}}};
    object_handle_list privkey_list=find_all_object(module,session,&privkey_template);
    object_handle_list current;
    CK_OBJECT_HANDLE privkey_handle;
    VERBOSE(module->verbose,"Found %lu private keys",object_handle_list_length(privkey_list));
    DO_OBJECT_HANDLE_LIST(privkey_handle,current,privkey_list){
        template privkey_attributes={2,
                                     {{CKA_CLASS,NULL,0},
                                      {CKA_ID,NULL,0}}};
        CK_BYTE* id;
        CK_ULONG id_size;
        object_get_attributes(module,session,privkey_handle,&privkey_attributes);
        id=privkey_attributes.attributes[1].pValue;
        id_size=privkey_attributes.attributes[1].ulValueLen;
        if(id && (id_size!=CK_UNAVAILABLE_INFORMATION)){
            CK_OBJECT_CLASS oclass=CKO_CERTIFICATE;
            CK_CERTIFICATE_TYPE ctype=CKC_X_509;
            template certificate_template={3,
                                           {{CKA_CLASS,&oclass,sizeof(oclass)},
                                            {CKA_CERTIFICATE_TYPE,&ctype,sizeof(ctype)},
                                            {CKA_ID,id,id_size}}};
            CK_OBJECT_HANDLE certificate_handle;
            char* idstring=bytes_to_hexadecimal(id,id_size);
            VERBOSE(module->verbose,"Private key ID %s",idstring);
            certificate_handle=object_handle_ensure_one(find_all_object(module,session,&certificate_template),
                                                        "certificate handle");
            if(certificate_handle==CK_INVALID_HANDLE){
                VERBOSE(module->verbose,"Found no certificate for private key ID %s",idstring);
                free(idstring);
                continue;}
            free(idstring);
            template certificate_attributes={8,
                                             {/*0*/{CKA_CLASS,NULL,0},
                                              /*1*/{CKA_ID,NULL,0},
                                              /*2*/{CKA_OBJECT_ID,NULL,0},
                                              /*3*/{CKA_LABEL,NULL,0},
                                              /*4*/{CKA_CERTIFICATE_TYPE,NULL,0},
                                              /*5*/{CKA_CERTIFICATE_CATEGORY,NULL,0},
                                              /*6*/{CKA_ISSUER,NULL,0},
                                              /*7*/{CKA_SUBJECT,NULL,0},
                                              /*8*/{CKA_VALUE,NULL,0},
                                              /*9*/{CKA_KEY_TYPE,NULL,0}}};
            object_get_attributes(module,session,certificate_handle,&certificate_attributes);
            smartcard_certificate certificate;
            CK_ULONG id_index=position_of_attribute(CKA_ID,&certificate_attributes);
            CK_ULONG certype_index=position_of_attribute(CKA_CERTIFICATE_TYPE,&certificate_attributes);
            CK_ULONG keytype_index=position_of_attribute(CKA_KEY_TYPE,&certificate_attributes);
            certificate=certificate_new(slot_id,
                                        check_memory(strndup((char*)info->label,32),33),
                                        ((id_index!=CK_UNAVAILABLE_INFORMATION)
                                         ?(bytes_to_hexadecimal(certificate_attributes.attributes[id_index].pValue,
                                                             certificate_attributes.attributes[id_index].ulValueLen))
                                         :string_attribute(CKA_ID,&certificate_attributes)),
                                        string_attribute(CKA_LABEL,&certificate_attributes),
                                        ((certype_index!=CK_UNAVAILABLE_INFORMATION)
                                         ?(*(CK_CERTIFICATE_TYPE*)certificate_attributes.attributes[certype_index].pValue)
                                         :0),
                                        string_attribute(CKA_ISSUER,&certificate_attributes),
                                        string_attribute(CKA_SUBJECT,&certificate_attributes),
                                        string_attribute(CKA_VALUE,&certificate_attributes),
                                        ((keytype_index!=CK_UNAVAILABLE_INFORMATION)
                                         ?(*(CK_KEY_TYPE*)certificate_attributes.attributes[keytype_index].pValue)
                                         :0));
            VERBOSE(module->verbose,"Certificate slot_id=%lu token_label=%s id=%s label=%s type=%lu issuer=%s subject=%s value=%s key_type=%lu",certificate->slot_id,certificate->token_label,certificate->id,certificate->label,certificate->type,certificate->issuer,certificate->subject,certificate->value,certificate->key_type);
            result=certificate_list_cons(certificate,result);
            template_free_buffers(&certificate_attributes);
            template_free_buffers(&privkey_attributes);}
        else{
            VERBOSE(module->verbose,"Private key has no ID!");}}
    return result;}


certificate_list find_x509_certificates_with_signing_rsa_private_key(const char* pkcs11_library_path,int verbose){
    /* Find PRIVATE-KEYs of KEY-TYPE = RSA, that can SIGN, and that have a X-509 certificate with same ID. */
    certificate_list result=NULL;
    pkcs11_module* module=NULL;
    slot_id_list   slots;
    WITH_PKCS11_MODULE(module,pkcs11_library_path){
        module->verbose=verbose;
        get_list_of_slots_with_token(module,&slots);
        VERBOSE(module->verbose,"Found %d slots", slots.count);
        if(slots.count==0){
            printf("No smartcard\n");}
        else{
            CK_ULONG i;
            for(i=0;i<slots.count;i++){
                CK_TOKEN_INFO info;
                CK_ULONG slot_id=slots.slot_id[i];
                VERBOSE(module->verbose,"Processing slot id %lu", slot_id);
                if(check_rv(module->p11->C_GetTokenInfo(slot_id, &info),"C_GetTokenInfo")){
                    CK_SESSION_HANDLE session;
                    WITH_PKCS11_OPEN_SESSION(session,module,slot_id,CKF_SERIAL_SESSION,NULL,NULL){
                        VERBOSE(module->verbose,"Opened PKCS#11 session %lu", session);
                        result=find_x509_certificates_with_signing_rsa_private_key_in_slot(module,slot_id,&info,session,result);}}}}}
    return result;}

/**** THE END ****/

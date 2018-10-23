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
    object_handle_list current;
    CK_OBJECT_HANDLE privkey_handle;
    DO_OBJECT_HANDLE_LIST(privkey_handle,current,
                          find_all_object(module,session,&privkey_template)){
        template privkey_attributes={3,
                                     {{CKA_CLASS,NULL,0},
                                      {CKA_ID,NULL,0},
                                      {CKA_OBJECT_ID,NULL,0}}};
        CK_BYTE* id;
        CK_ULONG id_size;
        object_get_attributes(module,session,privkey_handle,&privkey_attributes);
        id=privkey_attributes.attributes[1].pValue;
        id_size=privkey_attributes.attributes[1].ulValueLen;
        if(id && ((unsigned long)id!=CK_UNAVAILABLE_INFORMATION)){
            CK_OBJECT_CLASS oclass=CKO_PRIVATE_KEY;
            CK_CERTIFICATE_TYPE ctype=CKC_X_509;
            template certificate_template={3,
                                           {{CKA_CLASS,&oclass,sizeof(oclass)},
                                            {CKA_CERTIFICATE_TYPE,&ctype,sizeof(ctype)},
                                            {CKA_ID,id,id_size}}};
            CK_OBJECT_HANDLE certificate_handle=object_handle_ensure_one(find_all_object(module,session,&certificate_template),
                                                                         "certificate handle");
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
            result=certificate_list_cons(certificate_new(slot_id,
                                                         check_memory(strndup((char*)info->label,32),33),
                                                         bytes_to_hexadecimal(certificate_attributes.attributes[1].pValue,
                                                                              certificate_attributes.attributes[1].ulValueLen),
                                                         check_memory(strndup(certificate_attributes.attributes[3].pValue,
                                                                              certificate_attributes.attributes[3].ulValueLen),
                                                                      certificate_attributes.attributes[3].ulValueLen+1),
                                                         *(CK_CERTIFICATE_TYPE*)certificate_attributes.attributes[4].pValue,
                                                         check_memory(strndup(certificate_attributes.attributes[6].pValue,
                                                                              certificate_attributes.attributes[6].ulValueLen),
                                                                      certificate_attributes.attributes[6].ulValueLen+1),
                                                         check_memory(strndup(certificate_attributes.attributes[7].pValue,
                                                                              certificate_attributes.attributes[7].ulValueLen),
                                                                      certificate_attributes.attributes[7].ulValueLen+1),
                                                         check_memory(strndup(certificate_attributes.attributes[8].pValue,
                                                                              certificate_attributes.attributes[8].ulValueLen),
                                                                      certificate_attributes.attributes[8].ulValueLen+1),
                                                         *(CK_KEY_TYPE*)certificate_attributes.attributes[9].pValue),
                                         result);
            template_free_buffers(&certificate_attributes);
            template_free_buffers(&privkey_attributes);}}
    return result;}


certificate_list find_x509_certificates_with_signing_rsa_private_key(const char* pkcs11_library_path){
    /* Find PRIVATE-KEYs of KEY-TYPE = RSA, that can SIGN, and that have a X-509 certificate with same ID. */
    certificate_list result=NULL;
    pkcs11_module* module=NULL;
    slot_id_list   slots;
    WITH_PKCS11_MODULE(module,pkcs11_library_path){
        get_list_of_slots_with_token(module,&slots);
        if(slots.count==0){
            printf("No smartcard\n");}
        else{
            CK_ULONG i;
            for(i=0;i<slots.count;i++){
                CK_TOKEN_INFO info;
                CK_ULONG slot_id=slots.slot_id[i];
                if(check_rv(module->p11->C_GetTokenInfo(slot_id, &info),"C_GetTokenInfo")){
                    CK_SESSION_HANDLE session;
                    WITH_PKCS11_OPEN_SESSION(session,module,slot_id,CKF_SERIAL_SESSION,NULL,NULL){
                        result=find_x509_certificates_with_signing_rsa_private_key_in_slot(module,slot_id,&info,session,result);}}}}}
    return result;}

/**** THE END ****/

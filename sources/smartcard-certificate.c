#include <stdio.h>
#include <stdbool.h>
#include <pkcs11-helper-1.0/pkcs11.h>
#include "smartcard-certificate.h"
#include "pkcs11module.h"
#include "pkcs11errors.h"
#include "error.h"

/* ========================================================================== */
/* Searching certificates on a IAS-ECC smartcard. */


typedef struct {
    CK_ULONG count;
    CK_ULONG slot_id[64];
}   slot_id_list;

CK_BBOOL check_rv(CK_RV rv,const char* function){
    if(rv==CKR_OK){
        return CK_TRUE;
    }
    ERROR(EX_OSERR,"PKCS#11 function %s returned error: %s",function,pkcs11_return_value_label(rv));
    return CK_FALSE;}

void get_list_of_slots_with_token(pkcs11_module* module,slot_id_list* list){
    list->count=sizeof(list->slot_id)/sizeof(list->slot_id[0]);
    if(check_rv(module->p11->C_GetSlotList(CK_TRUE,&(list->slot_id[0]),&(list->count)),"C_GetSlotList")){
        if(list->count==0){
            printf("No smartcard\n");}}
    else{
        list->count=0;}}

certificate_list find_x509_certificates_with_signing_rsa_private_key(const char* pkcs11_library_path){
    /* Find PRIVATE-KEYs of KEY-TYPE = RSA, that can SIGN, and that have a X-509 certificate with same ID. */
    certificate_list result=NULL;
    pkcs11_module* module=NULL;
    slot_id_list   slots;

    WITH_PKCS11_MODULE(module,pkcs11_library_path){
        get_list_of_slots_with_token(module,&slots);
        CK_ULONG i;
        for(i=0;i<slots.count;i++){
            CK_TOKEN_INFO info;
            if(check_rv(module->p11->C_GetTokenInfo(slots.slot_id[i], &info),"C_GetTokenInfo")){

            }}}}

/**** THE END ****/

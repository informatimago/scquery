#ifndef PKCS11MODULE_H
#define PKCS11MODULE_H

#include <pkcs11-helper-1.0/pkcs11.h>

typedef struct
{
	void* library;
	CK_FUNCTION_LIST_PTR p11;
    CK_RV rv;
} pkcs11_module;

pkcs11_module* C_LoadModule(const char* mspec);
CK_RV C_UnloadModule(pkcs11_module* module);

#define WITH_PKCS11_MODULE(module,name)                                 \
    for(((module=C_LoadModule(name))                                    \
         ?(module->rv=module->p11->C_Initialize(NULL))                  \
         :0);                                                           \
        ((module!=NULL)                                                 \
         && ((module->rv==CKR_OK)                                       \
             ||(module->rv==CKR_CRYPTOKI_ALREADY_INITIALIZED)));        \
        (((module!=NULL)                                                \
          ?(module->p11->C_Finalize(NULL),                              \
            C_UnloadModule(module))                                     \
          :0),                                                          \
         module=NULL))

#endif

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

#define WITH_PKCS11_MODULE(module,name)                                              \
    for((module=C_LoadModule(name),                                                  \
         module->rv=module?module->p11->C_Initialize(NULL):CKR_GENERAL_ERROR);       \
        (module                                                                      \
         && ((module->rv==CKR_OK)||(module->rv==CKR_CRYPTOKI_ALREADY_INITIALIZED))); \
        (module?module->p11->C_Finalize(NULL):0,                                     \
         (module && (module->rv==CKR_OK))?C_UnloadModule(module):(void)0))


#endif

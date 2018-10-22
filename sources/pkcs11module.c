#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11module.h"
#include "pkcs11errors.h"
#include "error.h"


/*
C_LoadModule
Allocate the pkcs11_module and load the library.
*/
pkcs11_module* C_LoadModule(const char* library_path)
{
	pkcs11_module* module;
	CK_RV rv, (*c_get_function_list)(CK_FUNCTION_LIST_PTR_PTR);

	if (library_path == NULL)
	{
		ERROR(ENODATA, "dlopen failed: %s", dlerror());
		goto failed;
	}

    if (!(module = checked_calloc(1, sizeof(*module))))
    {
        goto failed;
    }

	if (!(module->library = dlopen(library_path, RTLD_LAZY)))
	{
		ERROR(-1, "dlopen failed: %s", dlerror());
		free(module);
		goto failed;
	}

	/* Get the list of function pointers */
	c_get_function_list = (CK_RV(*)(CK_FUNCTION_LIST_PTR_PTR))dlsym(module->library, "C_GetFunctionList");

	if (!c_get_function_list)
	{
		goto unload_and_failed;
	}

	rv = c_get_function_list(& module->p11);

	if (rv == CKR_OK)
	{
		return (void*) module;
	}

	ERROR(rv, "C_GetFunctionList() failed with %s.", pkcs11_return_value_label(rv));

unload_and_failed:
	C_UnloadModule(module);
failed:
	ERROR(-1, "Failed to load PKCS#11 module %s", library_path ? library_path : "NULL");
	return NULL;
}


/*
C_UnloadModule
Unload the library and free the pkcs11_module
*/
CK_RV C_UnloadModule(pkcs11_module* module)
{
	if (!module)
	{
		return CKR_ARGUMENTS_BAD;
	}

	if (module->library != NULL && dlclose(module->library) < 0)
	{
		return CKR_FUNCTION_FAILED;
	}

	memset(module, 0, sizeof(*module));
	free(module);
	return CKR_OK;
}


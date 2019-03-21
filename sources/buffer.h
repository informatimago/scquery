#ifndef BUFFER_H
#define BUFFER_H
#include <pkcs11-helper-1.0/pkcs11.h>

typedef void* buffer;
CK_ULONG buffer_size(buffer buf);
CK_BYTE* buffer_data(buffer buf);

buffer buffer_new_copy(CK_ULONG size, CK_BYTE* data);
buffer buffer_new(CK_ULONG size, CK_BYTE* data);
void buffer_free(buffer that);

#endif

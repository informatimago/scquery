#ifndef SCQUERy_STRING_H
#define SCQUERy_STRING_H

#include <string.h>

#if _POSIX_C_SOURCE >= 200809L || defined(_GNU_SOURCE)
/* strndup and strnlen are defined in string.h */
#else

size_t strnlen(const char* string,size_t length);
char* strndup(const char* string,size_t length);

#endif
#endif          

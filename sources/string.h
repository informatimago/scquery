#ifndef SCQUERy_STRING_H
#define SCQUERy_STRING_H

#include <string.h>

#if (_POSIX_C_SOURCE >= 200809L) || defined(_GNU_SOURCE)
/* strndup and strnlen are defined in string.h */
#else

size_t strnlen(const char* string,size_t length);
char* strndup(const char* string,size_t length);

#endif

#if (_XOPEN_SOURCE >= 500) || (_POSIX_C_SOURCE >= 200809L) || _BSD_SOURCE || _SVID_SOURCE
/* strdup is defined in string.h */
#else

char* strdup(const char* string);

#endif


#endif

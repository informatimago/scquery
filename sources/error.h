#ifndef ERROR_H
#define ERROR_H
#include <stddef.h>
#include <errno.h>
#include <sysexits.h>

/* out_of_memory
handles the out of memory error (when malloc returns NULL).
It may not return, or it should return a pointer returned
untouched by the caller.
*/
typedef void* (*out_of_memory_handler)(size_t size);
out_of_memory_handler out_of_memory;

/* checked_malloc
allocates size bytes of memory, or if it can't, calls out_of_memory and return its results.
*/
void* checked_malloc(size_t size);

/* checked_calloc
allocates nmemb * size bytes of memory and clears it,
or if it can't, calls out_of_memory and return its results.
*/
void* checked_calloc(size_t nmemb, size_t size);

/* error
handles other errors, displaying the formated error message.
It may return or not.
*/
typedef void (*error_handler)(const char* file, unsigned long line, const char* function, int status, const char* format, ...);
error_handler error;
#define ERROR(status,format, ...) error(__FILE__, __LINE__, __FUNCTION__, status, format, ## __VA_ARGS__)


#endif

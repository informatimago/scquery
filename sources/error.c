#include <stdlib.h>

#include "error.h"

/* ========================================================================== */
/* Error Handling */

void* checked_malloc(size_t size){
    void* memory=malloc(size);
    return memory
            ?memory
            :out_of_memory(size);
}

void* checked_calloc(size_t nmemb, size_t size){
    void* memory=calloc(nmemb, size);
    return memory
            ?memory
            :out_of_memory(nmemb * size);
}



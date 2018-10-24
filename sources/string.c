#include "string.h"

static void dummy(void){} /* some compilers complain on empty sources. */

#if _POSIX_C_SOURCE >= 200809L || defined(_GNU_SOURCE)
/* strndup and strnlen are defined in string.h */
#else

size_t strnlen(const char* string,size_t length){
    size_t i=0;
    if(string==NULL){
        return i;}
    while((i<length) &&(string[i]!='\0')){
        i++;}
    return i;}

char* strndup(const char* string,size_t length){
    if(string==NULL){
        return NULL;}
    else{
        size_t i;
        size_t size=1+strnlen(string,length);
        char* result=checked_malloc(size);
        if(result==NULL){
            errno=ENOMEM;
            return NULL;}
        for(i=0;i<size-1;i++){
            result[i]=string[i];}
        result[size-1]='\0';
        return result;}}

#endif


#if (_XOPEN_SOURCE >= 500) || (_POSIX_C_SOURCE >= 200809L) || _BSD_SOURCE || _SVID_SOURCE
/* strdup is defined in string.h */
#else

char* strdup(const char* string){
    if(string==NULL){
        return NULL;}
    else{
        size_t size=;
        char* result=checked_malloc(1+strlen(string));
        if(result==NULL){
            errno=ENOMEM;
            return NULL;}
        strcpy(result,string);
        return result;}}

#endif

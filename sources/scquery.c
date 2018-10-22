#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "smartcard-certificate.h"
#include "error.h"

#define sizeof(a) (sizeof(a)/sizeof(a[0]))

void report_error_and_exit(const char * file, unsigned long line, const char* function, int status,const char* format,...){
    va_list ap;
    fflush(stdout);
    fprintf(stderr,"\n%s:%lu: in %s() ", file, line, function);
    va_start(ap,format);
    vfprintf(stderr,format,ap);
    va_end(ap);
    fprintf(stderr,"\n");
    fflush(stderr);
    exit(status); }

void* error_out_of_memory(size_t size){
    ERROR(EX_OSERR,"Out of memory, could not allocate %u bytes",size);
    return NULL;}

void initialize_error_handling(void){
    out_of_memory=error_out_of_memory;
    error=report_error_and_exit;}

const char* default_module_path(void){
    static const char* default_libraries[]={
#if defined(__linux)
        "/usr/lib/libiaspkcs11.so",
        "/usr/local/lib/libiaspkcs11.so",
#elif defined(__darwin)
        "/opt/local/lib/opensc-pkcs11.bundle/Contents/MacOS/opensc-pkcs11",
        "/opt/local/lib/libopensc.dylib",
        "/opt/local/lib/libpkcs11-helper.dylib"
#else
        "/usr/lib/libiaspkcs11.so",
#endif
    };
    for(size_t i=0;i<sizeof(default_libraries);i++){
        if(access(default_libraries[i],R_OK)==0){
            return default_libraries[i];}}
    return NULL;}

void query_X509_user_identities(const char* module){
    certificate_list list=find_x509_certificates_with_signing_rsa_private_key(module);
    while(list){
        smartcard_certificate entry=first(list);
        printf("PKCS11:module_name=%s:slotid=%lu:token=%s:certid=%s\n",
               module,entry->slot_id,entry->label,entry->id);
    /*
    (loop :for (kind info) :in (certificate-extract-subject-alt-names (getf entry :certificate))
          :for skind := (escape #\: (format nil "~(~A~)" kind))
          :do (if (listp info)
                  (format t "~&subjectAltName:~A:~{~A:~A~^:~}~%" skind
                          (mapcar (lambda (item)
                                    (etypecase item
                                      (string (escape #\: item))
                                      (symbol (escape #\: (format nil "~(~A~)" item)))
                                      (vector (flatten-vector item))))
                                  info)
                          )
                  (format t "~&subjectAltName:~A:~A~%" skind (escape #\: info))))))
    */
        list=rest(list);}}

typedef struct {
    const char* module;
} options_t;

void parse_options(options_t* options,int argc,const char** argv){
    int i=1;
    while(i<argc){
        const char* option=argv[i++];
        if(0==strcmp(option,"--module")){
            if(i<argc){
                options->module=argv[i++];}
            else{
                ERROR(EX_USAGE, "Missing path to the pkcs11 library after the --module option.");}}
        else{
            const char* prefix="--module=";
            size_t prefix_len=strlen(prefix);
            if((prefix_len<=strlen(option)) && (0==strncmp(prefix,option,prefix_len))){
                const char* module=option+prefix_len;
                if(0==strlen(module)){
                    ERROR(EX_USAGE,"Missing path to the pkcs11 library attached to the --module= option.");}
                options->module=module;}
            else{
                ERROR(EX_USAGE,"Invalid option: %s",option);}}}}

int main(int argc,const char** argv){
    initialize_error_handling();
    options_t options={0};
    parse_options(&options,argc,argv);
    if(!options.module){
        options.module=default_module_path();}
    if(!options.module){
        ERROR(EX_UNAVAILABLE,"Cannot find a Cryptoki pkcs11 library (libiaspkcs11).");}
    query_X509_user_identities(options.module);
    return 0;
}

/*

exec-path("/opt/local/bin" "/opt/local/sbin" "/usr/local/bin" "/Users/pjb/bin/" "/usr/bin" "/bin" "/usr/sbin" "/sbin" "/Applications/Emacs.app/Contents/MacOS/bin-x86_64-10_9" "/Applications/Emacs.app/Contents/MacOS/libexec-x86_64-10_9" "/Applications/Emacs.app/Contents/MacOS/libexec" "/Applications/Emacs.app/Contents/MacOS/bin")

*/

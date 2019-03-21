#include <ctype.h>
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
#include "string.h"
#include "x509_alt_names.h"

#define sizeof(a) (sizeof(a)/sizeof(a[0]))

void* error_out_of_memory(size_t size){
    ERROR(EX_OSERR,"Out of memory, could not allocate %u bytes",size);
    return NULL;}

void report_error_and_exit(const char * file, unsigned long line, const char* function, int status,const char* format,...){
    va_list ap;
    fflush(stdout);
    fprintf(stderr,"\n%s:%lu: ERROR in %s() ", file, line, function);
    va_start(ap,format);
    vfprintf(stderr,format,ap);
    va_end(ap);
    fprintf(stderr,"\n");
    fflush(stderr);
    exit(status); }

void report_warning(const char * file, unsigned long line, const char* function, int status,const char* format,...){
    va_list ap;
    fflush(stdout);
    fprintf(stderr,"\n%s:%lu: WARNING in %s() (%d) ", file, line, function, status);
    va_start(ap,format);
    vfprintf(stderr,format,ap);
    va_end(ap);
    fprintf(stderr,"\n");
    fflush(stderr);}

void report_verbose(const char * file, unsigned long line, const char* function, const char* format,...){
    va_list ap;
    fflush(stdout);
    fprintf(stderr,"\n%s:%lu: VERBOSE in %s() ", file, line, function);
    va_start(ap,format);
    vfprintf(stderr,format,ap);
    va_end(ap);
    fprintf(stderr,"\n");
    fflush(stderr);}

void initialize_error_handling(void){
    handle_out_of_memory=error_out_of_memory;
    handle_error=report_error_and_exit;
    handle_warning=report_warning;
    handle_verbose=report_verbose;}

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

char * escape_colon(const char * string){
    const char escape='\\';
    const char colon=':';
    size_t colon_count=string_count(string,colon);
    size_t length=strlen(string);
    char* result=checked_malloc(1+length+colon_count);
    size_t i;
    size_t j=0;
    if(result==NULL){
        return NULL;}
    for(i=0;i<length;i++){
        if ((string[i]==escape) || (string[i]==colon)){
            result[j++]=escape;}
        result[j++]=tolower(string[i]);}
    result[j]='\0';
    return result;}

void query_X509_user_identities(const char* module,int verbose){
    smartcard_certificate entry;
    certificate_list current;
    certificate_list clist=find_x509_certificates_with_signing_rsa_private_key(module,NULL,NULL,verbose);
    DO_CERTIFICATE_LIST(entry,current,clist){
        alt_name name;
        alt_name_list current;
        alt_name_list alist;
        printf("PKCS11:module_name=%s:slotid=%lu:token=%s:certid=%s\n",
               module,entry->slot_id,entry->token_label,entry->id);
        alist=certificate_extract_subject_alt_names(entry->value);
        DO_ALT_NAME_LIST(name,current,alist){
            char* stype=escape_colon(name->type);
            char* sname=string_mapconcat(escape_colon,(string_postprocess_pr)free,
                                         name->count,(const char**)name->components,":");
            printf("subjectAltName:%s:%s\n",stype,sname);
            free(stype);
            free(sname);}
        alt_name_list_deepfree(alist);}
    certificate_list_deepfree(clist);}

typedef struct {
    const char* module;
    int verbose;
} options_t;

void usage(const char* pname)
{
    const char* basename=strrchr(pname,'/');
    if(basename==NULL){
        basename=pname;}
    printf("\n%s usage:\n\n", basename);
    printf("\t%s [-h|--help]\n", basename);
    printf("\t%s [-v|--verbose] [ --module=$libiaspcks11 ]\n", basename);
    printf("\n");}

void parse_options(options_t* options,int argc,const char** argv){
    int i=1;
    while(i<argc){
        const char* option=argv[i++];
        if(0==strcmp(option,"--module")){
            if(i<argc){
                options->module=argv[i++];}
            else{
                ERROR(EX_USAGE, "Missing path to the pkcs11 library after the --module option.");}}
        else if((0==strcmp(option,"--verbose")) || (0==strcmp(option,"-v"))){
            options->verbose=1;}
        else if((0==strcmp(option,"--help")) || (0==strcmp(option,"-h"))){
            usage(argv[0]);
            exit(EX_OK);}
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
    options_t options={0,0};
    parse_options(&options,argc,argv);
    if(!options.module){
        options.module=default_module_path();}
    if(!options.module){
        ERROR(EX_UNAVAILABLE,"Cannot find a Cryptoki pkcs11 library (libiaspkcs11).");}
    query_X509_user_identities(options.module,options.verbose);
    return 0;
}

/**** THE END ****/

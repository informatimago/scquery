#include <string.h>
#include <openssl/x509v3.h>
#include <openssl/x509v3.h>
#include <openssl/stack.h>
#include <openssl/safestack.h>
#include "x509_alt_names.h"
#include "error.h"
#include "string.h"

void string_list_free(unsigned count, char** components){
    unsigned i;
    for(i=0;i<count;i++){
        free(components[i]);}
    free(components);}

alt_name alt_name_new_with_components(char* type,unsigned count,char** components){
    alt_name name=alt_name_new(type,count);
    if(name==NULL){
        return NULL;}
    name->count=count;
    name->allocated=count;
    name->components=components;
    return name;}

alt_name alt_name_new(char* type,unsigned allocated){
    alt_name result=checked_malloc(sizeof(*result));
    if(result==NULL){
        return NULL;}
    result->type=check_memory(strdup(type),1+strlen(type));
    result->count=0;
    result->allocated=allocated;
    result->components=((allocated==0)
                        ?NULL
                        :checked_calloc(result->allocated,sizeof(result->components[0])));
    if((result->type==NULL) || (result->components==NULL)){
        free(result->type);
        string_list_free(result->allocated,result->components);
        free(result);
        return NULL;}
    return result;}

void alt_name_add_component(alt_name name,char* component){
    if((name==NULL) || (component==NULL)){
        return;}
    if(name->count>=name->allocated){
        unsigned new_allocated=((name->allocated==0)
                                ?8
                                :2*name->allocated);
        char** new_components=realloc(name->components,
                                     new_allocated*sizeof(name->components[0]));
        if(new_components==NULL){
            ERROR(EX_OSERR,"Cannot add component '%s'",component);
            return;}
        name->components=new_components;
        name->allocated=new_allocated;}
    unsigned index=name->count++;
    name->components[index]=check_memory(strdup(component),1+strlen(component));
    return;}

void alt_name_free(alt_name name) {
    if(name==NULL){
        return;}
    free(name->type);
    string_list_free(name->count, name->components);
    free(name);}

alt_name_list alt_name_list_cons(alt_name name, alt_name_list rest){
    alt_name_list list=checked_malloc(sizeof(*list));
    if(list==NULL) {
        return NULL;}
    list->name=name;
    list->rest=rest;
    return list;}

alt_name      alt_name_list_first(alt_name_list list){ return ((list==NULL)?NULL:list->name);}
alt_name_list alt_name_list_rest(alt_name_list list){  return ((list==NULL)?NULL:list->rest);}
void          alt_name_list_free(alt_name_list list){  free(list);}

void          alt_name_list_deepfree(alt_name_list list){
    while(list!=NULL){
        alt_name_free(list->name);
        alt_name_list rest=list->rest;
        alt_name_list_free(list);
        list=rest;}}

char* general_name_type_label(int general_name_type){

    static const char* labels[]={"OTHERNAME","EMAIL","DNS","X400",
        "DIRNAME","EDIPARTY","URI","IPADD","RID"};

    if((general_name_type<0)||(general_name_type>=(int)(sizeof(labels)/sizeof(labels[0])))){
        char* result=checked_malloc(64);
        if(result==NULL){
            return NULL;}
        sprintf(result,"Unknown GENERAL_NAME type %d",general_name_type);
        return result;}
    return strdup(labels[general_name_type]);}
    
void extract_asn1_string(GENERAL_NAME* name,alt_name alt_name){
	char* result=NULL;
	unsigned char* string=NULL;
    switch(name->type){
      case GEN_URI:
      case GEN_DNS:
      case GEN_EMAIL:
          if (ASN1_STRING_to_UTF8(&string, name->d.ia5)<0){
              char* type=general_name_type_label(name->type);
              ERROR(EX_OSERR,"Error converting with ASN1_STRING_to_UTF8 a %s general name",type);
              free(type);
              return;}
          result=check_memory(strdup((char*)string),1+strlen((char*)string));
          OPENSSL_free(string);
          alt_name_add_component(alt_name,result);}}

char* type_id_to_oid_string(ASN1_OBJECT * type_id){
    return "NOT IMPLEMENTED YET";}

char* asn1_string_to_string(ASN1_TYPE* value){
    return "NOT IMPLEMENTED YET";}

char* asn1_boolean_to_string(ASN1_TYPE* value){
    return "NOT IMPLEMENTED YET";}
    
void collect_components(alt_name alt_name,ASN1_TYPE* value){
    switch(value->type){
      case V_ASN1_EOC:
          /* not processed yet */
          break;
          
      case V_ASN1_BOOLEAN:
          alt_name_add_component(alt_name,asn1_boolean_to_string(value));
          break;
          
      case V_ASN1_INTEGER:
      case V_ASN1_BIT_STRING:
      case V_ASN1_OCTET_STRING:
          /* not processed yet */
          break;
          
      case V_ASN1_NULL:
          alt_name_add_component(alt_name,"null");
          break;

      case V_ASN1_SEQUENCE:
          {
              ASN1_SEQUENCE_ANY* elements=d2i_ASN1_SEQUENCE_ANY(NULL,
                                            (const unsigned char**)&value->value.sequence->data,
                                            value->value.sequence->length);
              if(elements==NULL){
                  return;}
              int count=OPENSSL_sk_num((const OPENSSL_STACK *)elements);
              for(int i=0;i<count;i++){
                  ASN1_TYPE* element=OPENSSL_sk_value((const OPENSSL_STACK *)elements,i);
                  collect_components(alt_name,element);}
              OPENSSL_sk_pop_free((OPENSSL_STACK *)elements, (void(*)(void*))ASN1_TYPE_free);
              
              alt_name_add_component(alt_name,asn1_string_to_string(value));
          }
          break;

      case V_ASN1_UTF8STRING:
      case V_ASN1_NUMERICSTRING:
      case V_ASN1_PRINTABLESTRING:
      case V_ASN1_T61STRING:
      case V_ASN1_VIDEOTEXSTRING:
      case V_ASN1_IA5STRING:
      case V_ASN1_GRAPHICSTRING:
      case V_ASN1_ISO64STRING:
      case V_ASN1_GENERALSTRING:
      case V_ASN1_UNIVERSALSTRING:
      case V_ASN1_BMPSTRING:
          alt_name_add_component(alt_name,asn1_string_to_string(value));
          break;

      case V_ASN1_OBJECT:
      case V_ASN1_OBJECT_DESCRIPTOR:
      case V_ASN1_EXTERNAL:
      case V_ASN1_REAL:
      case V_ASN1_ENUMERATED:
      case V_ASN1_UTCTIME:
      case V_ASN1_GENERALIZEDTIME:
          /* not processed yet */
          break;}}

void extract_othername_object(GENERAL_NAME* name,alt_name alt_name){
    switch(name->type){
      case GEN_OTHERNAME:
          alt_name_add_component(alt_name,type_id_to_oid_string(name->d.otherName->type_id));
          collect_components(alt_name,name->d.otherName->value);}}
 


typedef alt_name(*extract_alt_name_pr)(GENERAL_NAME* name, unsigned i);

alt_name extract_alt_name(GENERAL_NAME* name, unsigned i){
    (void)i;
    alt_name alt_name;
    switch (name->type){
      case GEN_URI:
      case GEN_DNS:
      case GEN_EMAIL:
          alt_name=alt_name_new(general_name_type_label(name->type),1);
          extract_asn1_string(name,alt_name);
          return alt_name;
      case GEN_OTHERNAME:
          alt_name=alt_name_new(general_name_type_label(name->type),1);
          extract_othername_object(name,alt_name);
          return alt_name;
      default:
          return NULL;}
    ;}

alt_name_list map_subject_alt_names(X509 * certificate, void * what, extract_alt_name_pr extract_alt_name){
	STACK_OF(GENERAL_NAME)* gens=X509_get_ext_d2i(certificate,NID_subject_alt_name,NULL,NULL);
    alt_name_list results=NULL;
    if(gens==NULL){
        return NULL;}
    int count=sk_GENERAL_NAME_num(gens);
    for(int i=0;i<count;i++){
        GENERAL_NAME* name=sk_GENERAL_NAME_value(gens,i);
        alt_name alt_name=extract_alt_name(name,i);
        if(alt_name!=NULL){
            results=alt_name_list_cons(alt_name,results);}}
    sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
    return results;}

alt_name_list certificate_extract_subject_alt_names(buffer certificate_data){
    X509 * certificate = d2i_X509(NULL,(const unsigned char**)&(certificate_data->data),
                                  certificate_data->size);
    alt_name_list result = map_subject_alt_names(certificate, NULL, extract_alt_name);
    X509_free(certificate);
    return result;}


/**** THE END ****/

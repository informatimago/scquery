#include <string.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/safestack.h>
#include <openssl/ssl.h>
#include <openssl/stack.h>
#include <openssl/x509v3.h>
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
    if((result->type==NULL) || ((result->allocated>0) && (result->components==NULL))){
        free(result->type);
        string_list_free(result->allocated,result->components);
        free(result);
        return NULL;}
    return result;}

void alt_name_add_component(alt_name name,char* component){
    if((name==NULL) || (component==NULL)){
        return;}
    printf("Adding component: %s\n",component);
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
    char small_buffer[1];
    int buffer_size=1+OBJ_obj2txt(small_buffer,1,type_id,/*no_name=*/1);
    char* buffer=checked_malloc(buffer_size);
    if(buffer==NULL){
        return NULL;}
    OBJ_obj2txt(buffer,buffer_size,type_id,/*no_name=*/1);
    return buffer;}

char* asn1_string_to_string(ASN1_TYPE* value){
    unsigned char * utf8string=NULL;
    int result=ASN1_STRING_to_UTF8(&utf8string,value->value.asn1_string);
    if(result<0){
        return check_memory(strdup(""),1);}
    char* string=check_memory(strdup((char*)utf8string),1+result);
    OPENSSL_free(utf8string);
    return string;}

char* asn1_boolean_to_string(ASN1_TYPE* value){
    return check_memory(strdup(value->value.boolean
                               ?"true"
                               :"false"),6);}

void dump(unsigned char* data,unsigned length){
    unsigned i=0;
    while(i<length){
        if(i%16==0){
            printf("%8p: ",data+i);}
        int w=16;
        while(0<w--){
            printf("%02x ",data[i++]);}
        printf("\n");}
    printf("\n");}


unsigned decode_der_item_collect(unsigned char* data, unsigned length,collector_pr collect,void* collect_data){
    /* decode tag */
    unsigned char tag=data[0];
    unsigned char class=(tag>>6)&0b11;
    unsigned char primitive=((tag&32)==0);
    tag&=31;
    if(class==2){

    }else{

    }
    /* decode length */
    i=decode_der_length(data,i,&length);
    assert(len+i<=length);
    /* decode elements */
}

unsigned decode_der_length(unsigned char* data, unsigned i,unsigned* length){
    unsigned len=0;
    unsigned char b=data[i++];
    if(b<128){
        len=b;}
    else {
        unsigned char c=b&0x7f;
        while(0<c--){
            len=(len<<8)|data[i++];}}
    (*length)=len;
    return i;}

void decode_der_sequence_collect(unsigned char* data, unsigned length,collector_pr collect,void* collect_data){
    /* decode tag */
    unsigned char tag=data[0];
    assert(tag==30);
    /* decode length */
    i=decode_der_length(data,i,&length);
    assert(len+i<=length);
    /* decode element */
    unsigned e=i+len;
    while(i<e){
        i+=decode_der_item_collect(data+i,len,collect,collect_data);}}

void collect_components(alt_name alt_name,ASN1_TYPE* value){
    printf("value->type=%d\n",value->type);
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

      case V_ASN1_SET:
          /* not processed yet */
          break;

      case V_ASN1_OTHER:
          /* KPN are sequences of other. */
          {
              printf("other\n");
              ASN1_TYPE * item = d2i_ASN1_TYPE(NULL, (const unsigned char**) & value->value.asn1_string->data, value->value.asn1_string->length);
              dump(value->value.asn1_string->data, value->value.asn1_string->length);
              collect_components(alt_name, item);
          }
          break;
      case V_ASN1_SEQUENCE:
          {
              printf("sequence\n");
              dump(value->value.sequence->data,value->value.sequence->length);
              ASN1_SEQUENCE_ANY* elements=d2i_ASN1_SEQUENCE_ANY(NULL,
                                            (const unsigned char**)&value->value.sequence->data,
                                            value->value.sequence->length);
              if(elements==NULL){
                  return;}
              int count=OPENSSL_sk_num((const OPENSSL_STACK *)elements);
              int i;
              for(i=0;i<count;i++){
                  ASN1_TYPE* element=OPENSSL_sk_value((const OPENSSL_STACK *)elements,i);
                  collect_components(alt_name,element);
                  printf("%d: %d components\n",i,alt_name->count);}
              OPENSSL_sk_pop_free((OPENSSL_STACK *)elements, (void(*)(void*))ASN1_TYPE_free);

              alt_name_add_component(alt_name,asn1_string_to_string(value));
              printf("%d components\n",alt_name->count);
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

void cert_info_kpn(X509* x509, alt_name alt_name){
	int i;
    int j = 0;
	STACK_OF(GENERAL_NAME) *gens;
	GENERAL_NAME* name;
	ASN1_OBJECT* krb5PrincipalName;
	gens = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
	krb5PrincipalName = OBJ_txt2obj("1.3.6.1.5.2.2", 1);
	if (!gens){
		return; /* no alternate names */}
	if (!krb5PrincipalName){
		ERROR(0, "Cannot map KPN object");
		return;}
	for (i = 0; (i < sk_GENERAL_NAME_num(gens)); i++){
		name = sk_GENERAL_NAME_value(gens, i);
		if (name && name->type == GEN_OTHERNAME){
			if (OBJ_cmp(name->d.otherName->type_id, krb5PrincipalName)){
				continue; /* object is not a UPN */}
			else{
				/* NOTE:
				from PKINIT RFC, I deduce that stored format for kerberos
				Principal Name is ASN1_STRING, but not sure at 100%
				Any help will be granted
				*/
				unsigned char* txt;
				ASN1_TYPE* val = name->d.otherName->value;
				ASN1_STRING* str = val->value.asn1_string;
				if ((ASN1_STRING_to_UTF8(&txt, str)) < 0){
                    ERROR(0, "ASN1_STRING_to_UTF8() failed: %s", ERR_error_string(ERR_get_error(), NULL));}
				else{
                    alt_name_add_component(alt_name, check_memory(strdup((const char*)txt), 1 + strlen(txt)));
                    j++;}}}}
	sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
	ASN1_OBJECT_free(krb5PrincipalName);
	if (j == 0){
		ERROR(0, "Certificate does not contain a KPN entry");}}


alt_name_list map_subject_alt_names(X509 * certificate, extract_alt_name_pr extract_alt_name){
	STACK_OF(GENERAL_NAME)* gens=X509_get_ext_d2i(certificate,NID_subject_alt_name,NULL,NULL);
    alt_name_list results=NULL;
    if(gens==NULL){
        return NULL;}
    int count=sk_GENERAL_NAME_num(gens);
    int i;
    for(i=0;i<count;i++){
        GENERAL_NAME* name=sk_GENERAL_NAME_value(gens,i);
        alt_name alt_name=extract_alt_name(name,i);
        if(alt_name!=NULL){
            results=alt_name_list_cons(alt_name,results);}}
    /* It looks like it's not possible to free the general_name themselves
       (they may be taken directly from the certificate data?).
       sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free) crashes. */
    sk_GENERAL_NAME_free(gens);
    return results;}

alt_name_list certificate_extract_subject_alt_names(buffer certificate_data){
    if(certificate_data==NULL){
        return NULL;}
    else{
        X509 * certificate = d2i_X509(NULL,(const unsigned char**)&(certificate_data->data),
                                      certificate_data->size);
        alt_name_list result = map_subject_alt_names(certificate, extract_alt_name);
        alt_name alt_name = alt_name_new("1.3.6.1.5.2.2",1);
        cert_info_kpn(certificate, alt_name);
        result = alt_name_list_cons(alt_name, result);
        X509_free(certificate);
        return result;}}


/**** THE END ****/

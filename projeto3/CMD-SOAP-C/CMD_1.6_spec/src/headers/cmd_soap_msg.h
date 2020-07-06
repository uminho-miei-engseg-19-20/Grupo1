
#ifndef _cmd_soap_msg_h_
#define _cmd_soap_msg_h_

char * to_sha256(char* string, int opt);

char * mystrdup(const char * s);

char* strcut(char * str, char * delimiter);
/*static size_t WriteMemoryCallback(void *ptr, size_t size, size_t nmemb, void *context);*/
char* base64Decoder(char encoded[], int len_str);

char* base64Encoder(char input_str[], int len_str); 

char* getcertificate(char *applicationId, char *userId);

char* ccmovelsign(char *applicationId, char *docName, char * hash, char *pin, char *userId);
	  
char* ccmovelmultiplesign(char *applicationId, char *pin, char *userId);

char* validate_otp(char *applicationId, char *processId, char *code);

#endif /* _cmd_soap_msg_h_ */ 

 /**
 * @file cmd_soap_msg.c  (C)
 * @brief Teste das operações do serviço CMD (versão 1.6 da "CMD - Especificação dos serviços de Assinatura"). 
 *
 * Copyright (c) 2020 Tempus, Lda.
 * Developed by Ricardo Pereira and Tiago Ramires - a73577@alunos.uminho.pt and pg41101@alunos.uminho.pt
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#include "headers/cmd_soap_msg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <openssl/sha.h>

 
#define SIZE_BASE 1000
#define SIZE_ASCII 100 

struct MemoryStruct {
  char *memory;
  size_t size;
};


char * mystrdup(const char * s)
{
  size_t len = 1+strlen(s);
  char *p = malloc(len);

  return p ? memcpy(p, s, len) : NULL;
}

char * to_sha256(char* string, int opt){
	if(opt == 0){

		char str[1024] = "";
		char straux[1024] = "";
		const char *s = string;
		unsigned char *d = SHA256((uint8_t*) s, strlen(s), 0);
		int i;
		for (i = 0; i < SHA256_DIGEST_LENGTH; i++){
			sprintf(straux, "%02x", d[i]);
			strcat(str, straux);
		}

		return mystrdup(str);}
	else{
		char str[1075] = "";
		char straux[1024] = "";
		char prefix[51] = "010\r\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x00\x04 ";
		strcpy(str, prefix);
		const char *s = string;
		unsigned char *d = SHA256((uint8_t*) s, strlen(s), 0);
		int i;
		for (i = 0; i < SHA256_DIGEST_LENGTH; i++){
			sprintf(straux, "%02x", d[i]);
			strcat(str, straux);
		}

		return mystrdup(str);}
}

char* strcut(char * str, char * delimiter){
	int i, j;
	char* result = NULL;
	for(i = 0; i < (int) strlen(str); i++) {
		for(j = 0; str[i] == delimiter[j] && j < (int) strlen(delimiter) && i < (int) strlen(str); j++, i++);
		if(j== (int) strlen(delimiter)){
			result = mystrdup(str);
			result[i] = '\0';
			return result;
		}
	}
	
	return mystrdup(str);		
}

static size_t WriteMemoryCallback (void *ptr, size_t size, size_t nmemb, void *context) {
  size_t bytec = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)context;
  mem->memory = realloc(mem->memory, mem->size + bytec + 1);
  if(mem->memory == NULL) {
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }
  memcpy(&(mem->memory[mem->size]), ptr, bytec);
  mem->size += bytec;
  mem->memory[mem->size] = 0;
  return nmemb;
}

char* base64Decoder(char encoded[], int len_str) 
{ 
    char* decoded_string; 
  
    decoded_string = (char*)malloc(sizeof(char) * SIZE_ASCII); 
  
    int i, j, k = 0; 
  
    /* stores the bitstream. */
    int num = 0; 
  
    /* count_bits stores current */
    /* number of bits in num. */
    int count_bits = 0; 
  
    /* selects 4 characters from */
    /* encoded string at a time. */
    /* find the position of each encoded */
    /* character in char_set and stores in num. */
    for (i = 0; i < len_str; i += 4) { 
        num = 0, count_bits = 0; 
        for (j = 0; j < 4; j++) { 
            /* make space for 6 bits. */
            if (encoded[i + j] != '=') { 
                num = num << 6; 
                count_bits += 6; 
            } 
  
            /* Finding the position of each encoded  
            character in char_set  
            and storing in "num", use OR  
            '|' operator to store bits.*/
  
            /* encoded[i + j] = 'E', 'E' - 'A' = 5 */
            /* 'E' has 5th position in char_set. */
            if (encoded[i + j] >= 'A' && encoded[i + j] <= 'Z') 
                num = num | (encoded[i + j] - 'A'); 
  
            /* encoded[i + j] = 'e', 'e' - 'a' = 5, */
            /* 5 + 26 = 31, 'e' has 31st position in char_set. */
            else if (encoded[i + j] >= 'a' && encoded[i + j] <= 'z') 
                num = num | (encoded[i + j] - 'a' + 26); 
  
            /* encoded[i + j] = '8', '8' - '0' = 8 */
            /* 8 + 52 = 60, '8' has 60th position in char_set. */
            else if (encoded[i + j] >= '0' && encoded[i + j] <= '9') 
                num = num | (encoded[i + j] - '0' + 52); 
  
            /* '+' occurs in 62nd position in char_set. */
            else if (encoded[i + j] == '+') 
                num = num | 62; 
  
            /* '/' occurs in 63rd position in char_set. */
            else if (encoded[i + j] == '/') 
                num = num | 63; 
  
            /* ( str[i + j] == '=' ) remove 2 bits */
            /* to delete appended bits during encoding. */
            else { 
                num = num >> 2; 
                count_bits -= 2; 
            } 
        } 
  
        while (count_bits != 0) { 
            count_bits -= 8; 
  
            /* 255 in binary is 11111111 */
            decoded_string[k++] = (num >> count_bits) & 255; 
        } 
    } 
  
    /* place NULL character to mark end of string. */ 
    decoded_string[k] = '\0'; 
  
    return decoded_string; 
} 
  

/* C program to encode an ASCII  
 string in Base64 format   
 Takes string to be encoded as input 
 and its length and returns encoded string*/ 
char* base64Encoder(char input_str[], int len_str) 
{ 
    /* Character set of base64 encoding scheme */
    char char_set[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; 
      
    /* Resultant string */
    char *res_str = (char *) malloc(SIZE_BASE * sizeof(char)); 
      
    int index, no_of_bits = 0, padding = 0, val = 0, count = 0, temp; 
    int i, j, k = 0; 
      
    /* Loop takes 3 characters at a time from  */
    /* input_str and stores it in val */
    for (i = 0; i < len_str; i += 3) 
        { 
            val = 0, count = 0, no_of_bits = 0; 
  
            for (j = i; j < len_str && j <= i + 2; j++) 
            { 
                /* binary data of input_str is stored in val */
                val = val << 8;  
                  
                /* (A + 0 = A) stores character in val */
                val = val | input_str[j];  
                  
                /* calculates how many time loop  */
                /* ran if "MEN" -> 3 otherwise "ON" -> 2 */
                count++; 
              
            } 
  
            no_of_bits = count * 8;  
  
            /* calculates how many "=" to append after res_str. */
            padding = no_of_bits % 3;  
  
            /* extracts all bits from val (6 at a time) */ 
            /* and find the value of each block */
            while (no_of_bits != 0)  
            { 
                /* retrieve the value of each block */
                if (no_of_bits >= 6) 
                { 
                    temp = no_of_bits - 6; 
                      
                    /*binary of 63 is (111111) f */
                    index = (val >> temp) & 63;  
                    no_of_bits -= 6;          
                } 
                else
                { 
                    temp = 6 - no_of_bits; 
                      
                    /* append zeros to right if bits are less than 6 */
                    index = (val << temp) & 63;  
                    no_of_bits = 0; 
                } 
                res_str[k++] = char_set[index]; 
            } 
    } 
  
    /* padding is done here */
    for (i = 1; i <= padding; i++)  
    { 
        res_str[k++] = '='; 
    } 
  
    res_str[k] = '\0'; 
  
    return res_str; 
  
} 

char *str_replace(char *orig, char *rep, char *with) {
    char *result; /* the return string */
    char *ins;    /* the next insert point */
    char *tmp;    /* varies */
    int len_rep;  /* length of rep (the string to remove) */
    int len_with; /* length of with (the string to replace rep with) */
    int len_front; /* distance between rep and end of last rep */
    int count;    /* number of replacements */

    /* sanity checks and initialization */
    if (!orig || !rep)
        return NULL;
    len_rep = strlen(rep);
    if (len_rep == 0)
        return NULL; /* empty rep causes infinite loop during count  */
    if (!with)
        with = "";
    len_with = strlen(with);

    /* count the number of replacements needed */
    ins = orig;
    for (count = 0; (tmp = strstr(ins, rep)); ++count) {
        ins = tmp + len_rep;
    }

    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);

    if (!result)
        return NULL;

    /* first time through the loop, all the variable are set correctly */
    /* from here on, */
    /*    tmp points to the end of the result string */
    /*    ins points to the next occurrence of rep in orig */
    /*    orig points to the remainder of orig after "end of rep" */
    while (count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep; /* move to next "end of rep" */
    }
    strcpy(tmp, orig);
    return result;
}

char* getcertificate(char *applicationId, char *userId) {
  char* parsed = NULL;
  char xml_to_send[2048] = "";
  CURL *curl;
  CURLcode res;
  struct MemoryStruct chunk;
  chunk.memory = malloc(1);
  chunk.size = 0;
  chunk.memory[chunk.size] = 0;
  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc");

    strcat(xml_to_send, "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"> <soapenv:Header/> <soapenv:Body> <GetCertificate xmlns=\"http://Ama.Authentication.Service/\"> <applicationId>");
    strcat(xml_to_send, base64Encoder(applicationId, strlen(applicationId)));
    strcat(xml_to_send, "</applicationId> <userId>");
    strcat(xml_to_send, userId);
    strcat(xml_to_send, "</userId> </GetCertificate> </soapenv:Body> </soapenv:Envelope>");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, xml_to_send);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: text/xml; charset=utf-8");
    headers = curl_slist_append(headers, "SOAPAction: \"http://Ama.Authentication.Service/CCMovelSignature/GetCertificate\"");
    headers = curl_slist_append(headers, "Accept: text/plain"); /* Example output easier to read as plain text. */
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    /* Make the example URL work even if your CA bundle is missing. */
    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
      exit(EXIT_FAILURE);
    } else {

      char value[1000000];
      sscanf(chunk.memory, "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><GetCertificateResponse xmlns=\"http://Ama.Authentication.Service/\"><GetCertificateResult>%[^<]</GetCertificateResult></GetCertificateResponse></s:Body></s:Envelope>", value);
      parsed = str_replace(value, "&#xD;", "");
      /*printf("%s\n",parsed);*/
    }
    /* Remember to call the appropriate "free" functions. */
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(chunk.memory);
    curl_global_cleanup();
  }
  return parsed;
}


char* ccmovelsign(char *applicationId, char *docName, char * hash, char *pin, char *userId) {
  char value[1000000]="";
  char xml_to_send[2048] = "";
  CURL *curl;
  CURLcode res;
  struct MemoryStruct chunk;
  chunk.memory = malloc(1);
  chunk.size = 0;
  chunk.memory[chunk.size] = 0;
  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc");



   	strcat(xml_to_send, "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"> <soapenv:Body> <CCMovelSign xmlns=\"http://Ama.Authentication.Service/\"> <!-- Optional --> <request> <ApplicationId xmlns=\"http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature\">");
    strcat(xml_to_send, base64Encoder(applicationId, strlen(applicationId)));
    strcat(xml_to_send, "</ApplicationId> <DocName xmlns=\"http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature\">");
    strcat(xml_to_send, (docName) ? docName : "docname teste");
    strcat(xml_to_send, "</DocName> <Hash xmlns=\"http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature\">");
    strcat(xml_to_send, hash);
    strcat(xml_to_send, "</Hash> <Pin xmlns=\"http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature\">");
    strcat(xml_to_send, pin);
    strcat(xml_to_send, "</Pin> <UserId xmlns=\"http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature\">");
    strcat(xml_to_send, userId);
    strcat(xml_to_send, "</UserId> </request> </CCMovelSign> </soapenv:Body> </soapenv:Envelope>");
    
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, xml_to_send);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: text/xml; charset=utf-8");
    headers = curl_slist_append(headers, "SOAPAction: \"http://Ama.Authentication.Service/CCMovelSignature/CCMovelSign\"");
    headers = curl_slist_append(headers, "Accept: text/plain"); /* Example output easier to read as plain text. */
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    /* Make the example URL work even if your CA bundle is missing. */
    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    } else {
      
      char aux[1000000]="";

      strcpy(aux, strstr(chunk.memory, "<a:Code>"));
      memmove(aux, aux+8, strlen(aux));
      strcat(value, strtok(aux, "<"));
      strcat(value, "|");

      strcpy(aux, strstr(chunk.memory, "<a:ProcessId>"));
      memmove(aux, aux+13, strlen(aux));
      strcat(value, strtok(aux, "<"));
      
      
    }
    /* Remember to call the appropriate "free" functions. */
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(chunk.memory);
    curl_global_cleanup();
  }
  return mystrdup(value);
}

char* ccmovelmultiplesign(char *applicationId, char *pin, char *userId) {
  char value[1000000]="";
  char xml_to_send[2048] = "";
  CURL *curl;
  CURLcode res;
  struct MemoryStruct chunk;
  chunk.memory = malloc(1);
  chunk.size = 0;
  chunk.memory[chunk.size] = 0;
  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc");


    strcat(xml_to_send, "<Envelope xmlns=\"http://schemas.xmlsoap.org/soap/envelope/\"> <Body> <CCMovelMultipleSign xmlns=\"http://Ama.Authentication.Service/\"> <!-- Optional --> <request> <ApplicationId xmlns=\"http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature\">");
    strcat(xml_to_send, base64Encoder(applicationId, strlen(applicationId)));
    strcat(xml_to_send, "</ApplicationId> <Pin xmlns=\"http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature\">");
    strcat(xml_to_send, pin);
    strcat(xml_to_send, "</Pin> <UserId xmlns=\"http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature\">");
    strcat(xml_to_send, userId);
    strcat(xml_to_send, "</UserId> </request> <!-- Optional --> <documents> <!-- Optional --> <HashStructure xmlns=\"http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature\"> <Hash>");
    strcat(xml_to_send, to_sha256("Nobody inspects the spammish repetition", 0));
    strcat(xml_to_send, "</Hash> <Name>");
    strcat(xml_to_send, "f1");
    strcat(xml_to_send, "</Name> <id>");
    strcat(xml_to_send, "11");
    strcat(xml_to_send, "</id> </HashStructure> <HashStructure xmlns=\"http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature\"> <Hash>");
    strcat(xml_to_send, to_sha256("Always inspect the spammish repetition", 0));
    strcat(xml_to_send, "</Hash> <Name>");
    strcat(xml_to_send, "f2");
    strcat(xml_to_send, "</Name> <id>");
    strcat(xml_to_send, "22");
    strcat(xml_to_send, "</id> </HashStructure> </documents> </CCMovelMultipleSign> </Body> </Envelope>");


    /*
   	strcat(xml_to_send, "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"> <soapenv:Body> <CCMovelSign xmlns=\"http://Ama.Authentication.Service/\"> <!-- Optional --> <request> <ApplicationId xmlns=\"http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature\">");
    strcat(xml_to_send, base64Encoder(applicationId, strlen(applicationId)));
    strcat(xml_to_send, "</ApplicationId> <DocName xmlns=\"http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature\">");
    strcat(xml_to_send, (docName) ? docName : "docname teste");
    strcat(xml_to_send, "</DocName> <Hash xmlns=\"http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature\">");
    strcat(xml_to_send, hash);
    strcat(xml_to_send, "</Hash> <Pin xmlns=\"http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature\">");
    strcat(xml_to_send, pin);
    strcat(xml_to_send, "</Pin> <UserId xmlns=\"http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature\">");
    strcat(xml_to_send, userId);
    strcat(xml_to_send, "</UserId> </request> </CCMovelSign> </soapenv:Body> </soapenv:Envelope>");
    */

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, xml_to_send);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: text/xml; charset=utf-8");
    headers = curl_slist_append(headers, "SOAPAction: \"http://Ama.Authentication.Service/CCMovelSignature/CCMovelMultipleSign\"");
    headers = curl_slist_append(headers, "Accept: text/plain"); /* Example output easier to read as plain text. */
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    /* Make the example URL work even if your CA bundle is missing. */
    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    } else {
      
      char aux[1000000]="";

      strcpy(aux, strstr(chunk.memory, "<a:Code>"));
      memmove(aux, aux+8, strlen(aux));
      strcat(value, strtok(aux, "<"));
      strcat(value, "|");

      strcpy(aux, strstr(chunk.memory, "<a:ProcessId>"));
      memmove(aux, aux+13, strlen(aux));
      strcat(value, strtok(aux, "<"));
      
      
    }
    /* Remember to call the appropriate "free" functions. */
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(chunk.memory);
    curl_global_cleanup();
  }

  return mystrdup(value);
}

char* validate_otp(char *applicationId, char *processId, char *code) {
  char value[1000000]="";
  char xml_to_send[2048] = "";
  char xml_code[1000000]="";
  CURL *curl;
  CURLcode res;
  struct MemoryStruct chunk;
  chunk.memory = malloc(1);
  chunk.size = 0;
  chunk.memory[chunk.size] = 0;
  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc");

    

   	strcat(xml_to_send, "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"> <soapenv:Body> <ValidateOtp xmlns=\"http://Ama.Authentication.Service/\"> <code>");
   	strcat(xml_to_send, code); printf("%s\n", code);
   	strcat(xml_to_send, "</code> <processId>");
   	strcat(xml_to_send, processId);
   	strcat(xml_to_send, "</processId> <applicationId>");
   	strcat(xml_to_send, base64Encoder(applicationId, strlen(applicationId)));
   	strcat(xml_to_send, "</applicationId> </ValidateOtp> </soapenv:Body> </soapenv:Envelope>");

	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, xml_to_send);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: text/xml; charset=utf-8");
    headers = curl_slist_append(headers, "SOAPAction: \"http://Ama.Authentication.Service/CCMovelSignature/ValidateOtp\"");
    headers = curl_slist_append(headers, "Accept: text/plain"); /* Example output easier to read as plain text. */
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    /* Make the example URL work even if your CA bundle is missing. */
    res = curl_easy_perform(curl);

    if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    	exit(EXIT_FAILURE);
    } else {
      
      char aux[1000000]="";


      strcpy(xml_code, strstr(chunk.memory, "<a:Code>"));
      memmove(xml_code, xml_code+8, strlen(xml_code));
      strcpy(xml_code, strtok(xml_code, "<"));

      if(!strcmp(xml_code,"200")) {

      	strcpy(aux, strstr(chunk.memory, "<a:Code>"));
      	memmove(aux, aux+8, strlen(aux));
      	strcat(value, strtok(aux, "<"));

      	strcat(value, "|");

      	strcpy(aux, strstr(chunk.memory, "<a:Signature>"));
      	memmove(aux, aux+13, strlen(aux));
      	strcat(value, strtok(aux, "<"));
      	
      }
      else {
      	strcpy(aux, strstr(chunk.memory, "<a:Code>"));
      	memmove(aux, aux+8, strlen(aux));
      	strcat(value, strtok(aux, "<"));
      }





      
      
      
    }
    /* Remember to call the appropriate "free" functions. */
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(chunk.memory);
    curl_global_cleanup();
  }
  return mystrdup(value);
}


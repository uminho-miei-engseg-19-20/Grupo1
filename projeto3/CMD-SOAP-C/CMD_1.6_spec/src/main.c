#include "headers/cmd_config.h"
#include "headers/cmd_soap_msg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmodule.h>
#include <regex.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/x509v3.h>



#define NR_OPERATIONS 5
#define NR_CERTS 3

regex_t pin_regex, user_regex, option_regex, id_regex, otp_regex;

enum operation{gc, ms, mms, otp, test};

GHashTable *table[NR_OPERATIONS];


static const char* TEXT = "test Command Line Program (for Preprod/Prod Signature CMD (SOAP) version 1.6 technical specification)";
static const char* VERSION = "version: 1.0";

static const char* APPLICATION_ID;

/*
int spc_verify(unsigned char *msg, unsigned int mlem, unsigned char *sig, unsigned int siglen, RSA *r){
	unsigned char hashhash[20];
	BN_CTX *c;
	int ret;

	
	if(!(c = BN_CTX_new())) return 0;

	if(!SHA1(msg, mlem, hashhash) || !RSA_blinding_on(r,c)){
		BN_CTX_free(c);
		return 0;
	}

	ret = RSA_verify(NID_sha1, hashhash, 20, sig, siglen, r);
	RSA_blinding_off(r);
	BN_CTX_free(c);
	return ret;
}*/










int RSAVerifySignature( RSA* rsa,
                         char* MsgHash,
                         int MsgHashLen,
                         char* Msg,
                         int MsgLen,
                         int* Authentic) {
  MsgHashLen = 256;							 
  *Authentic = 0;
  EVP_PKEY* pubKey  = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(pubKey, rsa);
  EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

  if (EVP_DigestVerifyInit(m_RSAVerifyCtx,NULL, EVP_sha256(),NULL,pubKey)<=0) {
      return 0;
  }
  if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
      return 0;
  }
  int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, (const unsigned char *) MsgHash, MsgHashLen);
  if (AuthStatus==1) {
    *Authentic = 1;
    return 1;
  } else if(AuthStatus==0){
    *Authentic = 0;
    return 1;
  } else{
    *Authentic = 0;
    return 0;
  }
}

int verifySignature(RSA* publicRSA, char* plainText, char* signatureBase64) {
  char* encMessage;
  int encMessageLength;
  int authentic;
  encMessage = base64Decoder(signatureBase64, strlen(signatureBase64));
  encMessageLength = strlen(encMessage);
  int result = RSAVerifySignature(publicRSA, encMessage, encMessageLength, plainText, strlen(plainText), &authentic);
  return result & authentic;
}











int testall() {
	char * signature = NULL;
	enum ct{user, root, ca}; 
	GHashTable *certs = g_hash_table_new(g_str_hash, g_str_equal);
	int i = 0;

	char buf[7];


	BIO *bio;
	X509 *certificate;


	char *gc_answer = NULL;
	char *ms_answer = NULL;
	char *otp_answer = NULL;	

	printf("%s\n%s\n", TEXT, VERSION);
	printf("\n++++ Test All inicializado ++++\n");
	/*printf("  0%% ... Leitura de argumentos da linha de comando - file: %s user: %s pin: %s\n", 
          (char *) g_hash_table_lookup(table[test], "file"),
          (char *) g_hash_table_lookup(table[test], "user"),
          (char *) g_hash_table_lookup(table[test], "pin"));*/
	printf(" 10%% ... A contactar servidor SOAP CMD para operação GetCertificate\n");

	gc_answer = getcertificate((char *) g_hash_table_lookup(table[test], "-applicationId"), (char *) g_hash_table_lookup(table[test], "user"));



	if(!strlen(gc_answer)){
		printf("Impossível obter certificado\n");
		exit(EXIT_FAILURE);
	}



	for(i = 0; i < 	NR_CERTS; i++){
		char crt [1000000] = "";
		strcpy(crt, strstr(gc_answer, "-----BEGIN CERTIFICATE-----"));
		strcpy(crt, strcut(crt, "-----END CERTIFICATE-----"));
		
		if(i == user)
			g_hash_table_insert(certs, "user",(gchar *) crt);
		else if(i == root)
			g_hash_table_insert(certs, "root",(gchar *) crt);
		else if(i == ca)
			g_hash_table_insert(certs, "ca",(gchar *) crt);
		if(strlen(gc_answer)<28) {
			strcpy(gc_answer, strstr(gc_answer, "-----BEGIN CERTIFICATE-----"));
			memmove(gc_answer, gc_answer+27, strlen(gc_answer));
			strcpy(gc_answer, strstr(gc_answer, "-----BEGIN CERTIFICATE-----"));
		}
	}
	

	/*************POR EM FORMATO DE CERTIFICADO*****************/
	const unsigned char * x = (const unsigned char *) mystrdup(g_hash_table_lookup(certs, "user"));

	bio = BIO_new(BIO_s_mem());
	BIO_puts(bio, (const char *) x);
	certificate = PEM_read_bio_X509(bio, NULL, NULL, NULL);

	/******************************/

	
	printf(" 20%% ... Certificado emitido.\n");
	printf(" 30%% ... Leitura do ficheiro %s\n", (char *) g_hash_table_lookup(table[test], "file"));
	printf(" 40%% ... Geração de hash do ficheiro %s\n", (char *) g_hash_table_lookup(table[test], "file"));

	char * hash = NULL;
	char * buffer = 0;
	long length;
	FILE * f = fopen ((char *) g_hash_table_lookup(table[test], "file"), "rb");

	if (f)
	{
	  fseek (f, 0, SEEK_END);
	  length = ftell (f);
	  fseek (f, 0, SEEK_SET);
	  buffer = malloc (length);
	  if (buffer)
	  {
	    if(fread (buffer, 1, length, f))
	    	printf("%s\n", "Conteúdo do ficheiro lido.");
	  }
	  fclose (f);
	}

	if (buffer)
	{
		hash = to_sha256(buffer, 0);	
	}

	

	printf(" 50%% ... Hash gerada (em base64): %s\n", hash);
	printf(" 60%% ... A contactar servidor SOAP CMD para operação CCMovelSign\n");

	ms_answer = ccmovelsign((char *) g_hash_table_lookup(table[test], "-applicationId"),
		(char *) g_hash_table_lookup(table[test], "file"),
		hash,
		(char *) g_hash_table_lookup(table[test], "pin"),
		(char *) g_hash_table_lookup(table[test], "user"));


	if(!strcmp(strtok(ms_answer,"|"), "200")) {
		g_hash_table_insert(table[test],"-processId",strtok(NULL,"|"));
	}
	else 
		printf("%s\n", "Command failed");

	printf(" 70%% ... ProcessID devolvido pela operação CCMovelSign: %s\n", (char *) g_hash_table_lookup(table[test], "-processId"));
	printf(" 80%% ... A iniciar operação ValidateOtp\n");

	printf("Introduza o OTP recebido no seu dispositivo: \n"); 
    if(fgets(buf, 7, stdin))
		buf[6] = '\0';
	else printf("Erro na leitura do OTP\n");

    

    if(!regexec(&otp_regex, buf, 0, NULL, 0)){
			g_hash_table_insert(table[test],"code",buf);

	printf(" 90%% ... A contactar servidor SOAP CMD para operação ValidateOtp\n");

		otp_answer = validate_otp((char *) g_hash_table_lookup(table[test], "-applicationId"),
			(char *) g_hash_table_lookup(table[test], "-processId"),
			(char *) g_hash_table_lookup(table[test], "code"));
	}
	else printf("Formato do OTP errado.\n");


	if(!strcmp(strtok(otp_answer, "|"),"200")){
    	signature = strtok(NULL, "|");
    	printf("%s\n", signature);
	}
	else {
		printf("%s\n", "Erro");
		exit(EXIT_FAILURE);
	}

	

	printf("100%% ... Assinatura (em base 64) devolvida pela operação ValidateOtp: %s\n", signature);
		
	printf("110%% ... A validar assinatura ...\n");
	
	char * digest = to_sha256(buffer, 0);

	EVP_PKEY *pkey = X509_get_pubkey(certificate);

	RSA * rsa_pkey  = EVP_PKEY_get1_RSA(pkey); 

	int resfinal = RSA_verify(NID_sha1, (const unsigned char *) digest, strlen(buffer), (const unsigned char *) buffer, strlen(signature), rsa_pkey);
	
	/*int resfinal = verifySignature(rsa_pkey, buffer, signature);*/

	if (resfinal)
		printf("A assinatura%d\n", resfinal);




	for(i = 0; i < NR_OPERATIONS; i++)
		g_hash_table_destroy (table[i]);

	return 0;
}





/**
 * @brief Função que analisa os vários argumentos do comando linha.
 * @return Não tem valor de retorno.
 */
void args_parse(int argc, char **argv){
	APPLICATION_ID = get_appid();

	int i;
	int required_args = 5;

	for(i = 0; i < NR_OPERATIONS; i++){
		table[i] = g_hash_table_new(g_str_hash, g_str_equal);
		g_hash_table_insert(table[i],"-applicationId",(gchar *)APPLICATION_ID);
	}


	regcomp(&option_regex, "^-\\(applicationId\\|prod\\|D\\|-debug\\)$", 0);
	regcomp(&otp_regex, "^[0-9]\\{6\\}$", 0);
	regcomp(&id_regex, "^[a-zA-Z0-9]\\{8\\}\\(-[a-zA-Z0-9]\\{4\\}\\)\\{3\\}-[a-zA-Z0-9]\\{12\\}$", 0);
	regcomp(&pin_regex, "^[0-9]\\{4,8\\}$", 0);
	regcomp(&user_regex, "^\\+[0-9]\\{3\\} [0-9]\\{9\\}$", 0);


	if(APPLICATION_ID == NULL || !strlen(APPLICATION_ID)){
		printf("%s\n", "Configure o APPLICATION_ID");
		exit(EXIT_FAILURE);
	}

	if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
		char help_text[1024] = "";
		strcat(help_text, "usage: ./program [-h] [-V]\n");
		strcat(help_text, "                        {GetCertificate,gc,CCMovelSign,ms,CCMovelMultipleSign,mms,ValidateOtp,otp,TestAll,test}\n");
		strcat(help_text, "                        ...\n\n");
		strcat(help_text, "test Command Line Program (for Preprod/Prod Signature CMD (SOAP) version 1.6 technical specification)\n\n");
		strcat(help_text, "optional arguments:\n");
		strcat(help_text, "  -h, --help            show this help message and exit\n");
		strcat(help_text, "  -V, --version         show program version\n\n");
		strcat(help_text, "CCMovelDigitalSignature Service:\n");
		strcat(help_text, "  {GetCertificate,gc,CCMovelSign,ms,CCMovelMultipleSign,mms,ValidateOtp,otp,TestAll,test}\n");
		strcat(help_text, "                        Signature CMD (SCMD) operations\n");
		strcat(help_text, "    GetCertificate (gc)\n");
		strcat(help_text, "                        Get user certificate\n");
		strcat(help_text, "    CCMovelSign (ms)    Start signature process\n");
		strcat(help_text, "    CCMovelMultipleSign (mms)\n");
		strcat(help_text, "                        Start multiple signature process\n");
		strcat(help_text, "    ValiadteOtp (otp)   Validate OTP\n");
		strcat(help_text, "    TestAll (test)      Automatically test all commands\n");
		printf("%s", help_text);
	}
	else if (!strcmp(argv[1], "--version") || !strcmp(argv[1], "-V")) {
		printf("%s\n", VERSION);
	}
	else if (!strcmp(argv[1], "GetCertificate") || !strcmp(argv[1], "gc")) {
		required_args = 1;
		char * gc_answer = NULL;
		for(i = 2; i < argc; i++)
			if(!regexec(&user_regex, argv[i], 0, NULL, 0)){
				g_hash_table_insert(table[gc],"user",argv[i]);
				required_args--;
			}
			else if(!regexec(&option_regex, argv[i], 0, NULL, 0)){
				if (!strcmp(argv[i], "-applicationId") && !regexec(&id_regex, argv[i+1], 0, NULL, 0))
					g_hash_table_replace(table[gc],argv[i],(gchar *) argv[++i]);
				else if (!strcmp(argv[i], "-applicationId")){
					char help_text[1024] = "";
					/*strcat(help_text, "usage: ./program [-h] [-V]\n");
					strcat(help_text, "                        {GetCertificate,gc,CCMovelSign,ms,CCMovelMultipleSign,mms,ValidateOtp,otp,TestAll,test}\n");
					strcat(help_text, "                        ...\n");*/
					printf("%s%s: error: unrecognized arguments: %s\n", help_text, argv[0], argv[i]);
					exit(EXIT_FAILURE);
				}
				else
					g_hash_table_insert(table[gc],argv[i],argv[i]);
			}
			else{
				char help_text[1024] = "";
				strcat(help_text, "usage: ./program [-h] [-V]\n");
				strcat(help_text, "                        {GetCertificate,gc,CCMovelSign,ms,CCMovelMultipleSign,mms,ValidateOtp,otp,TestAll,test}\n");
				strcat(help_text, "                        ...\n");
				printf("%s%s: error: unrecognized arguments: %s\n", help_text, argv[0], argv[i]);
				exit(EXIT_FAILURE);
			}
		
		if(required_args != 0){
			printf("Error: wrong arguments. \n");
			exit(EXIT_FAILURE);
		}

		gc_answer = getcertificate((char *) g_hash_table_lookup(table[gc], "-applicationId"), 
									(char *) g_hash_table_lookup(table[gc], "user"));



		if(!strlen(gc_answer)){
			printf("Impossível obter certificado\n");
			exit(EXIT_FAILURE);
		}
		else
			printf("Certificado:\n%s\n", gc_answer);



	}
	else if (!strcmp(argv[1], "CCMovelSign") || !strcmp(argv[1], "ms")) {
		required_args = 2;
		char * ms_answer = NULL; 
		for(i = 2; i < argc; i++)
			if(!regexec(&user_regex, argv[i], 0, NULL, 0)){
				g_hash_table_insert(table[ms],"user",argv[i]);
				required_args--;
			}
			else if(!regexec(&pin_regex, argv[i], 0, NULL, 0)){
				g_hash_table_insert(table[ms],"pin",argv[i]);
				required_args--;
			}
			else if(!regexec(&option_regex, argv[i], 0, NULL, 0)){
				if (!strcmp(argv[i], "-applicationId") && !regexec(&id_regex, argv[i+1], 0, NULL, 0))
					g_hash_table_replace(table[ms],argv[i],(gchar *) argv[++i]);
				else if (!strcmp(argv[i], "-applicationId")){
					char help_text[1024] = "";
					/*strcat(help_text, "usage: ./program [-h] [-V]\n");
					strcat(help_text, "                        {GetCertificate,gc,CCMovelSign,ms,CCMovelMultipleSign,mms,ValidateOtp,otp,TestAll,test}\n");
					strcat(help_text, "                        ...\n");*/
					printf("%s%s: error: unrecognized arguments: %s\n", help_text, argv[0], argv[i]);
					exit(EXIT_FAILURE);
				}
				else
					g_hash_table_insert(table[ms],argv[i],argv[i]);
			}
			else{
				char help_text[1024] = "";
				strcat(help_text, "usage: ./program [-h] [-V]\n");
				strcat(help_text, "                        {GetCertificate,gc,CCMovelSign,ms,CCMovelMultipleSign,mms,ValidateOtp,otp,TestAll,test}\n");
				strcat(help_text, "                        ...\n");
				printf("%s%s: error: unrecognized arguments: %s\n", help_text, argv[0], argv[i]);
				exit(EXIT_FAILURE);
			}	
		
		if(required_args != 0){
			printf("Error: wrong arguments. \n");
			exit(EXIT_FAILURE);
		}

		ms_answer = ccmovelsign((char *) g_hash_table_lookup(table[ms], "-applicationId"),
								(char *) g_hash_table_lookup(table[ms], "file"),
								to_sha256("Nobody inspects the spammish repetition", 0),
								(char *) g_hash_table_lookup(table[ms], "pin"),
								(char *) g_hash_table_lookup(table[ms], "user"));

		if(!strcmp(strtok(ms_answer,"|"), "200"))
			printf("ProcessID: %s\n", strtok(NULL,"|"));
		else 
			printf("%s\n", "Command failed"); 

	}
	else if (!strcmp(argv[1], "CCMovelMultipleSign") || !strcmp(argv[1], "mms")) {
		char * mms_answer = NULL;
		required_args = 2;
		for(i = 2; i < argc; i++)
			if(!regexec(&user_regex, argv[i], 0, NULL, 0)){
				g_hash_table_insert(table[mms],"user",argv[i]);
				required_args--;
			}
			else if(!regexec(&pin_regex, argv[i], 0, NULL, 0)){
				g_hash_table_insert(table[mms],"pin",argv[i]);
				required_args--;
			}
			else if(!regexec(&option_regex, argv[i], 0, NULL, 0)){
				if (!strcmp(argv[i], "-applicationId") && !regexec(&id_regex, argv[i+1], 0, NULL, 0))
					g_hash_table_replace(table[mms],argv[i],(gchar *) argv[++i]);
				else if (!strcmp(argv[i], "-applicationId")){
					char help_text[1024] = "";
					/*strcat(help_text, "usage: ./program [-h] [-V]\n");
					strcat(help_text, "                        {GetCertificate,gc,CCMovelSign,ms,CCMovelMultipleSign,mms,ValidateOtp,otp,TestAll,test}\n");
					strcat(help_text, "                        ...\n");*/
					printf("%s%s: error: unrecognized arguments: %s\n", help_text, argv[0], argv[i]);
					exit(EXIT_FAILURE);
				}
				else
					g_hash_table_insert(table[mms],argv[i],argv[i]);
			}
			else{
				char help_text[1024] = "";
				strcat(help_text, "usage: ./program [-h] [-V]\n");
				strcat(help_text, "                        {GetCertificate,gc,CCMovelSign,ms,CCMovelMultipleSign,mms,ValidateOtp,otp,TestAll,test}\n");
				strcat(help_text, "                        ...\n");
				printf("%s%s: error: unrecognized arguments: %s\n", help_text, argv[0], argv[i]);
				exit(EXIT_FAILURE);
			}

		if(required_args != 0){
			printf("Error: wrong arguments. \n");
			exit(EXIT_FAILURE);
		}

		mms_answer = ccmovelmultiplesign((char *) g_hash_table_lookup(table[mms], "-applicationId"),
								(char *) g_hash_table_lookup(table[mms], "pin"),
								(char *) g_hash_table_lookup(table[mms], "user"));

		if(!strcmp(strtok(mms_answer,"|"), "200"))
			printf("ProcessID: %s\n", strtok(NULL,"|"));
		else 
			printf("%s\n", "Command failed");
	}
	else if (!strcmp(argv[1], "ValidateOtp") || !strcmp(argv[1], "otp")) {
		char * signature = NULL;
		char * otp_answer = NULL;
		required_args = 2;
		for(i = 2; i < argc; i++)
			if(!regexec(&otp_regex, argv[i], 0, NULL, 0)){
				g_hash_table_insert(table[otp],"code",argv[i]);
				required_args--;
			}
			else if(!regexec(&id_regex, argv[i], 0, NULL, 0)){
				g_hash_table_insert(table[otp],"-processId",argv[i]);
				required_args--;
			}
			else if(!regexec(&option_regex, argv[i], 0, NULL, 0)){
				if (!strcmp(argv[i], "-applicationId") && !regexec(&id_regex, argv[i+1], 0, NULL, 0))
					g_hash_table_replace(table[otp],argv[i],(gchar *) argv[++i]);
				else if (!strcmp(argv[i], "-applicationId")){
					char help_text[1024] = "";
					/*strcat(help_text, "usage: ./program [-h] [-V]\n");
					strcat(help_text, "                        {GetCertificate,gc,CCMovelSign,ms,CCMovelMultipleSign,mms,ValidateOtp,otp,TestAll,test}\n");
					strcat(help_text, "                        ...\n");*/
					printf("%s%s: error: unrecognized arguments: %s\n", help_text, argv[0], argv[i]);
					exit(EXIT_FAILURE);
				}
				else
					g_hash_table_insert(table[otp],argv[i],argv[i]);
			}
			else{
				char help_text[1024] = "";
				strcat(help_text, "usage: ./program [-h] [-V]\n");
				strcat(help_text, "                        {GetCertificate,gc,CCMovelSign,ms,CCMovelMultipleSign,mms,ValidateOtp,otp,TestAll,test}\n");
				strcat(help_text, "                        ...\n");
				printf("%s%s: error: unrecognized arguments: %s\n", help_text, argv[0], argv[i]);
				exit(EXIT_FAILURE);
			}

		if(required_args != 0){
			printf("Error: wrong arguments. \n");
			exit(EXIT_FAILURE);
		}

		
		if(!g_hash_table_lookup(table[otp],"code")){
			printf("%s\n", "OTP não foi detetado.");
			exit(EXIT_FAILURE);
		}


		otp_answer = validate_otp((char *) g_hash_table_lookup(table[otp], "-applicationId"),
			(char *) g_hash_table_lookup(table[otp], "-processId"),
			(char *) g_hash_table_lookup(table[otp], "code"));
	

		if(!strcmp(strtok(otp_answer, "|"),"200")){
	    	signature = strtok(NULL, "|");
	    	printf("%s\n", signature);
		}
		else {
			printf("%s\n", "OTP incorreto.");
			exit(EXIT_FAILURE);
		}
	}
	else if (!strcmp(argv[1], "TestAll") || !strcmp(argv[1], "test")) {
		required_args = 3;
		for(i = 2; i < argc; i++)
			if(!regexec(&user_regex, argv[i], 0, NULL, 0)){
				g_hash_table_insert(table[test],"user",argv[i]);
				required_args--;
			}
			else if(!regexec(&pin_regex, argv[i], 0, NULL, 0)){
				g_hash_table_insert(table[test],"pin",argv[i]);
				required_args--;
			}
			else if(!regexec(&option_regex, argv[i], 0, NULL, 0)){
				if (!strcmp(argv[i], "-applicationId") && !regexec(&id_regex, argv[i+1], 0, NULL, 0))
					g_hash_table_replace(table[test],argv[i],(gchar *) argv[++i]);
				else if (!strcmp(argv[i], "-applicationId")){
					char help_text[1024] = "";
					/*strcat(help_text, "usage: ./program [-h] [-V]\n");
					strcat(help_text, "                        {GetCertificate,gc,CCMovelSign,ms,CCMovelMultipleSign,mms,ValidateOtp,otp,TestAll,test}\n");
					strcat(help_text, "                        ...\n");*/
					printf("%s%s: error: unrecognized arguments: %s\n", help_text, argv[0], argv[i]);
					exit(EXIT_FAILURE);
				}
				else
					g_hash_table_insert(table[test],argv[i],argv[i]);
			}
			else if(fopen(argv[i], "r")){
					g_hash_table_insert(table[test],"file",argv[i]);
					required_args--;
			}
			else{
				char help_text[1024] = "";
				strcat(help_text, "usage: ./program [-h] [-V]\n");
				strcat(help_text, "                        {GetCertificate,gc,CCMovelSign,ms,CCMovelMultipleSign,mms,ValidateOtp,otp,TestAll,test}\n");
				strcat(help_text, "                        ...\n");
				printf("%s%s: error: unrecognized arguments: %s\n", help_text, argv[0], argv[i]);
				exit(EXIT_FAILURE);
			}


		if(required_args != 0){
			printf("Error: wrong arguments. \n");
			exit(EXIT_FAILURE);
		}

		testall();
	}
	else{
		printf("Use -h for usage:\n  %s -h for all operations\n  %s <oper1> -h for usage of operation <oper1>\n", argv[0], argv[0]);
		exit(EXIT_FAILURE);
	}



		

}








/**
 * @brief Função main do programa..
 * @return Valor comum de retorno.
 */
int main(int argc, char **argv) {
	args_parse(argc, argv);

	return 0;
}

























































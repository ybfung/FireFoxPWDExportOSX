#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include "base64.h" 

#define NOMINMAX
#define PRBool   int
#define PRUint32 unsigned int
#define PR_TRUE  1
#define PR_FALSE 0
#define SQLITE_OK 0
#define SQLITE_ROW 100
#define SQLITE_API

char g_ver[20];


typedef enum SECItemType {
	siBuffer = 0,
	siClearDataBuffer = 1,
	siCipherDataBuffer,
	siDERCertBuffer,
	siEncodedCertBuffer,
	siDERNameBuffer,
	siEncodedNameBuffer,
	siAsciiNameString,
	siAsciiString,
	siDEROID,
	siUnsignedInteger,
	siUTCTime,
	siGeneralizedTime
};

struct SECItem {
	SECItemType type;
	unsigned char *data;
	size_t len;
};

typedef enum SECStatus {
	SECWouldBlock = -2,
	SECFailure = -1,
	SECSuccess = 0
};


typedef struct PK11SlotInfoStr PK11SlotInfo;
typedef SECStatus(*NSS_Init) (const char *);
typedef SECStatus(*NSS_Shutdown) (void);
typedef PK11SlotInfo * (*PK11_GetInternalKeySlot) (void);
typedef void(*PK11_FreeSlot) (PK11SlotInfo *);
typedef SECStatus(*PK11_Authenticate) (PK11SlotInfo *, PRBool, void *);
typedef SECStatus(*PK11SDR_Decrypt) (SECItem *, SECItem *, void *);
typedef int (*PK11_NeedLogin)(PK11SlotInfo *);

PK11_GetInternalKeySlot PK11GetInternalKeySlot;
PK11_FreeSlot           PK11FreeSlot;
PK11_Authenticate       PK11Authenticate;
PK11_NeedLogin		PK11NeedLogin; 
PK11SDR_Decrypt         PK11SDRDecrypt;
NSS_Init                fpNSS_INIT;
NSS_Shutdown            fpNSS_Shutdown;
void * hNSS;


bool loadFunctions(){

	//char path[] = "libnss3.dylib\0"; 
	hNSS = dlopen("libnss3.dylib", RTLD_LOCAL);
	if( !hNSS) printf("NSS is not opened\n");

	if (hNSS){
		fpNSS_INIT = (NSS_Init)dlsym(hNSS, "NSS_Init");
		fpNSS_Shutdown = (NSS_Shutdown)dlsym(hNSS, "NSS_Shutdown");
		PK11GetInternalKeySlot = (PK11_GetInternalKeySlot)dlsym(hNSS, "PK11_GetInternalKeySlot");
		PK11FreeSlot = (PK11_FreeSlot)dlsym(hNSS, "PK11_FreeSlot");
		PK11Authenticate = (PK11_Authenticate)dlsym(hNSS, "PK11_Authenticate");
		PK11NeedLogin = (PK11_NeedLogin)dlsym(hNSS, "PK11_NeedLogin");
		PK11SDRDecrypt = (PK11SDR_Decrypt)dlsym(hNSS, "PK11SDR_Decrypt");
	}
	return !(!fpNSS_INIT || !fpNSS_Shutdown 
			|| !PK11GetInternalKeySlot || !PK11Authenticate || !PK11SDRDecrypt || !PK11FreeSlot);
}

char *decrypt(const char *s){
	unsigned char byteData[8096];
	int dwLength = 8096;
	PK11SlotInfo *slot = 0;
	SECStatus status;
	SECItem in, out;
	char *result = "";

	typedef struct {
		enum {
			PW_NONE = 0,
			PW_FROMFILE = 1,
			PW_PLAINTEXT = 2,
			PW_EXTERNAL = 3
		} source;
		char *data;
	} secuPWData;

	//char pw_str[5] = "1234";
	//pw_str[4] = '\0';
	//secuPWData pw = { secuPWData::PW_PLAINTEXT, "1234" };
	//pw.source = secuPWData::PW_PLAINTEXT;
	//pw.data = pw_str;

	memset(byteData, 0, sizeof (byteData));

	//if (CryptStringToBinary(s, strlen(s), CRYPT_STRING_BASE64, byteData, &dwLength, 0, 0)){
	
	//if (Base64decode((char *)byteData, s)){
	dwLength = Base64decode((char *)byteData, s);
	if (dwLength ) {
		slot = (*PK11GetInternalKeySlot) ();
		//if (PK11NeedLogin(slot)) {
		if (slot != NULL){
			status = PK11Authenticate(slot, PR_TRUE, NULL);
			//status = PK11Authenticate(slot, PR_TRUE, &pw);
			if (status == SECSuccess){
				in.data = byteData;
				in.len = dwLength;
				out.data = 0;
				out.len = 0;
				status = (*PK11SDRDecrypt) (&in, &out, NULL);
				if (status == SECSuccess){
					memcpy(byteData, out.data, out.len);
					byteData[out.len] = 0;
					result = ((char*)byteData);
				}
				else
					result = "Error on decryption!";
			}
			else
				result = "Error on authenticate!";
			(*PK11FreeSlot) (slot);
		}
		else{
			result = "Get Internal Slot error!";

		}
	}
	return result;
}



int main(int argc, char* argv[]) {

	hNSS = NULL;

	if( loadFunctions()) {
		printf("NSS functions are loaded successfully!\n");
	}
       	else {
		printf("Not working\n");
		return 0;
	}

	// locate the logins.json file
	char logins[] = "/Users/michellecheung/Library/Application Support/Firefox/Profiles/poclmi5z.default"; 

	//if( !(*fpNSS_INIT)(logins))
	if(fpNSS_INIT(logins) != SECSuccess )
	{
		printf("NSS_INIT failed\n");
	       	dlclose(hNSS); 
		return -1;
	}
	printf("NSS_INIT succeeded.\n");

	// read the logins.json file
	char jsonfile[] = "/Users/michellecheung/Library/Application Support/Firefox/Profiles/poclmi5z.default/logins.json"; 
	FILE *loginJson;
       	int JsonFileSize = 0;
       	char *p, *q, *qu;

	int entries = 0;

	loginJson = fopen(jsonfile, "r");
       	if (loginJson)
       	{
	       	fseek(loginJson, 0, SEEK_END);
	       	JsonFileSize = ftell(loginJson);
	       	fseek(loginJson, 0, SEEK_SET);

		p = new char[JsonFileSize + 1];
	       	fread(p, 1, JsonFileSize, loginJson);

		printf("Mozilla Firefox exporting passwords:\n");
	       	while ((q = strstr(p, "formSubmitURL")) != NULL) {
		       	printf("---------------------\n");
		       	printf("Entry: %d\n", entries++);
			q += strlen("formSubmitURL") + 3;
		       	qu = strstr(q, "usernameField") - 3;
		       	*qu = '\0';

			printf("URL: %s\n", q);
		       	q = strstr(qu + 1, "encryptedUsername") + strlen("encryptedUsername") + 3;
		       	qu = strstr(q, "encryptedPassword") - 3;
		       	*qu = '\0';
		       	printf("Username: %s\n", decrypt(q));
		       	q = strstr(qu + 1, "encryptedPassword") + strlen("encryptedPassword") + 3;
		       	qu = strstr(q, "guid") - 3;
		       	*qu = '\0';
		       	printf("Password: %s\n", decrypt(q));
		       	p = qu + 1;
		       	printf("---------------------\n");
	       	}

	       	fclose(loginJson);
       	}
       	if (entries == 0)
	       	printf("No entries found!\n");

       	(*fpNSS_Shutdown)();

	//if(hNSS) dlclose(hNSS);

       	printf("\nExport passwords are done.\n");

	return 0;
}

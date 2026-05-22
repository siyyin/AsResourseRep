#include "cypher.h"
#include "cpbf.h"
#include "version.h"


int CypherInit(CypherCtx* cypher, int key, int salt)
{
	int user_data[2] = { 0 };

	if (NULL == cypher) {
		return PCE_ENULLARG;
	}

	*cypher = malloc(sizeof(BLOWFISH_KEY));

	if (NULL == *cypher) {
		return PCE_EMEM;
	}

	user_data[0] = key;
	user_data[1] = salt | 0x1011101;
	cpbf_setup((char*)user_data, *cypher, BLOWFISH_BLOCK_SIZE);
	return PCE_SUCCESS;
}

int CypherEncrypt(CypherCtx cypher, PCE_UCHAR in[], PCE_UCHAR out[], int length)
{
	int i = 0;
	BLOWFISH_KEY* key = NULL;
	if (NULL == cypher) {
		return PCE_ENULLARG;
	}
	key = (BLOWFISH_KEY*)cypher;

	for (i = 0; i < length - BLOWFISH_BLOCK_SIZE; i += BLOWFISH_BLOCK_SIZE) {
		cpbf_encrypt(in + i, out + i, key);
	}
	for (; i < length; ++i) {
		out[i] = in[i];
	}
	return PCE_SUCCESS;
}


int CypherDecrypt(CypherCtx cypher, PCE_UCHAR in[], PCE_UCHAR out[], int length)
{
	int i = 0;
	BLOWFISH_KEY* key = NULL;
	if (NULL == cypher) {
		return PCE_ENULLARG;
	}
	key = (BLOWFISH_KEY*)cypher;

	for (i = 0; i < length - BLOWFISH_BLOCK_SIZE; i += BLOWFISH_BLOCK_SIZE) {
		cpbf_decrypt(in + i, out + i, key);
	}
	for (; i < length; ++i) {
		out[i] = in[i];
	}
	return PCE_SUCCESS;
}

int CypherCleanup(CypherCtx cypher)
{
	if (NULL == cypher) {
		return PCE_ENULLARG;
	}

	free(cypher);
	return PCE_SUCCESS;
}

const char *CypherGetVersion(void)
{
	return PCE_VERSION_SZ "." PCE_REVISION_SZ "." PCE_BUILD_SZ;
}
#include <time.h>
#include <string.h>
#include <stdio.h>
#include "../include/zlib/zlib.h"
#include "../md5/md5.h"

#ifdef _WIN32
#include <windows.h>
#include <strsafe.h>
#include <string.h>
#include "../cypher/cypher.h"
#endif

#define FILE_PATH_LEN 1024
#define MAX_LEN_64 64
const char* PATTERN_MAGIC = "VA magic";
typedef struct _PATTERN_HEADER
{
	char ptnMagic[MAX_LEN_64];       //pattern识别标识
	char ptnVersion[MAX_LEN_64];     //pattern 版本号
	char ptnBuildTime[MAX_LEN_64]; //pattern build时间
	unsigned int ptnOriginalSize;	      //pattern原始文件大小
	unsigned int ptnCompressSize;     //pattern压缩和加密之后大小
}PATTERN_HEADER;

bool GetBuildTime(char* strBuildTime, int iLen)
{
	if (!strBuildTime || iLen <= 0)
		return false;
#ifdef _WIN32
	time_t rawtime;
	struct tm  timeinfo;
	time(&rawtime);
	localtime_s(&timeinfo, &rawtime);
	_snprintf_s(strBuildTime, iLen, iLen, "%d/%d/%d %d:%d:%d", 1900 + timeinfo.tm_year, 1 + timeinfo.tm_mon,  
					timeinfo.tm_mday, timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
#else
	time_t rawtime;
	struct tm* timeinfo;
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	_snprintf(strBuildTime, iLen, "%d/%d/%d %d:%d:%d", 1900 + timeinfo->tm_year, 1 + timeinfo->tm_mon,   
		           timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
#endif // _WIN32
	return  true;
}

bool parser_command_line(int argc, char ** argv, char* strOriginalFile, char* strEncryptFile, bool &bIsEncrypt)
{
	if (argc < 2 || !argv || !strOriginalFile || !strEncryptFile)
		return false;

#ifdef _WIN32
	if (_stricmp(argv[1], "-e") ==0)
		bIsEncrypt = true;
	else if (_stricmp(argv[1], "-d") ==0)
		bIsEncrypt = false;
#else
	if (strcasecmp(argv[1], "-e") ==0)
		bIsEncrypt = true;
	else if (strcasecmp(argv[1], "-d") ==0)
		bIsEncrypt = false;
#endif
	else
		return false;

	if (bIsEncrypt && argc == 3) {
		strncpy_s(strOriginalFile, FILE_PATH_LEN -1 , argv[2], FILE_PATH_LEN - 1);
	}
	else if (!bIsEncrypt && argc == 4) {
		strncpy_s(strEncryptFile, FILE_PATH_LEN - 1, argv[2], FILE_PATH_LEN - 1);
		strncpy_s(strOriginalFile, FILE_PATH_LEN - 1, argv[3], FILE_PATH_LEN - 1);
	}
	else 
		return false;
	return true;
}

int main(int argc, char ** argv)
{
	bool bEncrypt = false;
	char strOriginalFile[FILE_PATH_LEN] = {0};
	char strEncryptFile[FILE_PATH_LEN] = {0};
	char strPatternVer[MAX_LEN_64] = {0};
	FILE* fOriginal = NULL, *fEncrypt = NULL;
	char* pOriginalBuf = NULL, *pCompressBuf = NULL, *pEncryptBuf = NULL;
	unsigned long ulOriginalSize = 0, ulCompressSize = 0, ulEncryptSize = 0;
	PATTERN_HEADER pthHeader = {0};
	char* pTemp = NULL;

	//解析命令行
	if (!parser_command_line(argc, argv, strOriginalFile, strEncryptFile, bEncrypt)) {
		printf("command line error, the command is:\n");
		printf("encrypt.exe -e original_file\n");
        printf("encrypt.exe -d encrypted_file original_file\n");
		goto finish;
	}
	//处理pattern加密命令
	if (bEncrypt) {
		//获取pattern版本号
#ifdef _WIN32
		 fopen_s(&fOriginal, strOriginalFile, "rb");
#else 
		 fOriginal = fopen(strOriginalFile, "rb");
#endif // _WIN32
		if (!fOriginal) {
			printf("open file %s failed\n", strOriginalFile);
			goto finish;
		}
		fgets(strPatternVer, sizeof(strPatternVer) - 1, fOriginal);
		if (strlen(strPatternVer) == 0 || !strstr(strPatternVer, "patternver=")) {
			printf("pattern version format in %s error!\n", strOriginalFile);
			goto finish;
		}
		pTemp = strstr(strPatternVer, "patternver=");
		pTemp += strlen("patternver=");
		if (strlen(pTemp) <= 11) {
			printf("pattern version format in %s error!\n", strOriginalFile);
			goto finish;
		}
		if (pTemp[0] == '\"' &&
			(pTemp[1] >= '0' && pTemp[1] <= '9') &&
			(pTemp[2] >= '0' && pTemp[2] <= '9') &&
			(pTemp[3] >= '0' && pTemp[3] <= '9') &&
			(pTemp[4] >= '0' && pTemp[4] <= '9') &&
			pTemp[5] == '.' &&
			(pTemp[6] >= '0' && pTemp[6] <= '9') &&
			(pTemp[7] >= '0' && pTemp[7] <= '9') &&
			(pTemp[8] >= '0' && pTemp[8] <= '9') &&
			(pTemp[9] >= '0' && pTemp[9] <= '9') &&
			pTemp[10] == '\"' ) {
			strncpy_s(strPatternVer, sizeof(strPatternVer), pTemp + 1, 9);
		}
		else {
			printf("pattern version number in %s error!\n", strOriginalFile);
			goto finish;
		}
		//生成加密之后的目标文件名
		strncpy_s(strEncryptFile, FILE_PATH_LEN - 1, strOriginalFile, FILE_PATH_LEN - 1);
		pTemp = strstr(strEncryptFile, ".lua");
		if (!pTemp) {
			printf("source pattern file name %s is not ended with .lua\n", strOriginalFile);
			goto finish;		
		}
		*pTemp = 0;
		strncat_s(strEncryptFile, "$", sizeof(strEncryptFile) - strlen("$") - 1);
		strncat_s(strEncryptFile, strPatternVer, sizeof(strEncryptFile) - strlen(strPatternVer) - 1);

		//产生pattern header
		strncpy_s(pthHeader.ptnMagic,  sizeof(pthHeader.ptnMagic) - 1, PATTERN_MAGIC, sizeof(pthHeader.ptnMagic) - 1);
	    strncpy_s(pthHeader.ptnVersion, sizeof(pthHeader.ptnVersion) - 1,  strPatternVer, sizeof(pthHeader.ptnVersion) - 1);
		if (!GetBuildTime(pthHeader.ptnBuildTime, sizeof(pthHeader.ptnBuildTime) - 1))
			goto finish;
	    
#ifdef _WIN32
		 fopen_s(&fEncrypt, strEncryptFile, "wb");
#else 
		 fEncrypt = fopen(strEncryptFile, "wb");
#endif // _WIN32
		if (!fEncrypt) {
			printf("open file %s failed\n", strEncryptFile);
			goto finish;
		}
		fseek(fOriginal, 0, SEEK_END);
		ulOriginalSize = ftell(fOriginal);
		ulCompressSize = compressBound(ulOriginalSize);
		pOriginalBuf = new  char[ulOriginalSize];
		pCompressBuf  = new char[ulCompressSize];
		if (!pOriginalBuf || !pCompressBuf) {
			printf("new compress memory failed\n");
			goto finish;
		}
		memset(pOriginalBuf, 0, ulOriginalSize);
		memset(pCompressBuf, 0, ulCompressSize);
		fseek(fOriginal, 0, SEEK_SET);
		fread(pOriginalBuf, ulOriginalSize, 1, fOriginal);

		//压缩原始数据
		if(compress((Bytef*)pCompressBuf, &ulCompressSize, (const Bytef*)pOriginalBuf, ulOriginalSize) != Z_OK)  {
			printf("compress failed!\n");  
			goto finish;
		} 
		pthHeader.ptnOriginalSize = ulOriginalSize;
		pthHeader.ptnCompressSize = ulCompressSize;

		//加密压缩数据并计算MD5
		ulEncryptSize = sizeof(pthHeader) + ulCompressSize + MD5LEN;
		pEncryptBuf = new char[ulEncryptSize];
		if (!pEncryptBuf) {
			printf("new encrypt memory failed\n");
			goto finish;
		}
		memset(pEncryptBuf, 0, ulEncryptSize);
		memcpy(pEncryptBuf, &pthHeader, sizeof(pthHeader));
		CypherCtx en_ctx;
		if (CypherInit(&en_ctx, ~pthHeader.ptnOriginalSize, ~pthHeader.ptnCompressSize) != PCE_SUCCESS) {
			printf("encrypt init failed\n");
			goto finish;
		}
		if (CypherEncrypt(en_ctx, (PCE_UCHAR*)pCompressBuf, (PCE_UCHAR*)(pEncryptBuf + sizeof(pthHeader)), ulCompressSize) != PCE_SUCCESS) {
			printf("encrypt failed\n");
			goto finish;
		}
		MD5_CTX ctx;
        __VSMD5Init(&ctx);
        __VSMD5Update(&ctx, (unsigned char*)pEncryptBuf, sizeof(pthHeader) + ulCompressSize);  // 数据部分md5校验
        __VSMD5Final(&ctx);
		memcpy(pEncryptBuf + sizeof(pthHeader) + ulCompressSize, ctx.digest, sizeof(ctx.digest)/sizeof(byte));

		//加密数据写入目标文件
		fwrite(pEncryptBuf, ulEncryptSize, 1, fEncrypt);
		printf("encrypt pattern %s to %s successfully\n", strOriginalFile, strEncryptFile);
    }
	//处理pattern解密命令
	else {
#ifdef _WIN32
		fopen_s(&fOriginal, strOriginalFile, "wb");
		fopen_s(&fEncrypt, strEncryptFile, "rb");
#else 
		fOriginal = fopen(strOriginalFile, "wb");
		fEncrypt = fopen(strEncryptFile, "rb");
#endif // _WIN32
		if (!fOriginal || !fEncrypt) {
			printf("open file failed\n");
			goto finish;
		}
		//读入加密pattern内容，校验MD5, 解析pattern header
		fseek(fEncrypt, 0, SEEK_END);
		ulEncryptSize = ftell(fEncrypt);
		if (ulEncryptSize <= sizeof(pthHeader) + MD5LEN) {
			printf("pattern file is destroyed\n");
			goto finish;
		}
		pEncryptBuf = new char[ulEncryptSize];
		if (!pEncryptBuf) {
			printf("new encrypt memory failed\n");
			goto finish;
		}
		memset(pEncryptBuf, 0, ulEncryptSize);
		fseek(fEncrypt, 0, SEEK_SET);
		fread(pEncryptBuf, ulEncryptSize, 1, fEncrypt);
		MD5_CTX ctx;
        __VSMD5Init(&ctx);
        __VSMD5Update(&ctx, (unsigned char*)pEncryptBuf, ulEncryptSize - MD5LEN);  // 数据部分md5校验
        __VSMD5Final(&ctx);
		if (memcmp(pEncryptBuf + ulEncryptSize - MD5LEN, ctx.digest, MD5LEN) != 0) {
			printf("pattern md5 check is failed\n");
			goto finish;
		}
		memcpy(&pthHeader, pEncryptBuf, sizeof(pthHeader));
		ulOriginalSize = pthHeader.ptnOriginalSize;
		ulCompressSize = pthHeader.ptnCompressSize;
		//解密数据
		pCompressBuf = new char[ulCompressSize];
		if (!pCompressBuf) {
			printf("new compress memory failed\n");
			goto finish;
		}
		memset(pCompressBuf, 0, ulCompressSize);
		CypherCtx en_ctx;
		if (CypherInit(&en_ctx, ~pthHeader.ptnOriginalSize, ~pthHeader.ptnCompressSize) != PCE_SUCCESS) {
			printf("decrypt init failed\n");
			goto finish;	
		}
		if (CypherDecrypt(en_ctx, (PCE_UCHAR*)(pEncryptBuf + sizeof(pthHeader)), (PCE_UCHAR*)pCompressBuf, ulCompressSize)
			!= PCE_SUCCESS) {
			printf("decrypt failed\n");
			goto finish;	
		}
		//解压数据
		pOriginalBuf = new char[ulOriginalSize];
		if (!pOriginalBuf) {
			printf("new original memory failed\n");
			goto finish;
		}
		memset(pOriginalBuf, 0, ulOriginalSize);
		if(uncompress((Bytef*)pOriginalBuf, &ulOriginalSize, (const Bytef*)pCompressBuf, ulCompressSize) != Z_OK)  
		{  
			printf("uncompress failed!\n");  
			goto finish; 
		} 
		//解密和解压后的数据写入目标文件
		fwrite(pOriginalBuf, ulOriginalSize, 1, fOriginal);
		printf("decrypt pattern %s to %s successfully\n", strEncryptFile, strOriginalFile);
	}
finish:
	if (pOriginalBuf)
		delete[] pOriginalBuf;
	if (pCompressBuf)
		delete[] pCompressBuf;
	if (pEncryptBuf)
		delete[] pEncryptBuf;
	if (fOriginal)
		fclose(fOriginal);
	if (fEncrypt)
		fclose(fEncrypt);
	return 0;
}

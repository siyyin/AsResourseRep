#include "lua_file_crypt.h"
#include "Libs/LibPatternCypher/md5.h"
#include "Libs/LibPatternCypher/PatternCypher.h"
#include <stdio.h>
#include <windows.h>

/// <summary>
/// 加密单个文件
/// </summary>
/// <param name="strPath"></param>
/// <param name="nVersion"></param>
/// <returns></returns>
bool encode_lua_file(const std::string& strPath, int nVersion)
{
    size_t iCount   = 0;
    bool bRet       = false;
    FILE *fOriginal = NULL, *fEncrypt = NULL;
    char *pOriginalBuf = NULL, *pEncryptBuf = NULL;
    unsigned long ulOriginalSize = 0, ulEncryptSize = 0;

    size_t nPos = strPath.rfind("\\");
    if (nPos == std::string::npos)
    {
        printf("[Error] Can not find \\! %s", strPath.c_str());
        return false;
    }
    //文件夹路径
    std::string strFilePath = strPath.substr(0, nPos);
    //文件名，去掉后缀名
    std::string strFileName = strPath.substr(nPos + 1, strPath.length() - nPos - 1);
    strFileName             = strFileName.substr(0, strFileName.rfind("."));
    //加密后文件全路径
    char szEncodeFilePath[MAX_PATH];
    _snprintf_s(szEncodeFilePath, sizeof(szEncodeFilePath), "%s\\%s$%d", strFilePath.c_str(), strFileName.c_str(),
                nVersion);

    //读取文件
    fopen_s(&fOriginal, strPath.c_str(), "rb");
    if (!fOriginal)
    {
        printf("[Error] Open file failed! %s\n", strPath.c_str());
        goto _exit;
    }

    fseek(fOriginal, 0, SEEK_END);
    ulOriginalSize = ftell(fOriginal);
    pOriginalBuf   = (char*)malloc(ulOriginalSize);
    if (!pOriginalBuf)
    {
        printf("[Error] malloc failed!\n");
        goto _exit;
    }
    memset(pOriginalBuf, 0, ulOriginalSize);

    //读取整个文件
    fseek(fOriginal, 0, SEEK_SET);
    fread(pOriginalBuf, ulOriginalSize, 1, fOriginal);
    if (0 != LuaBuffEncode((const unsigned char*)pOriginalBuf, ulOriginalSize, nVersion, (unsigned char**)&pEncryptBuf,
                           ulEncryptSize))
    {
        printf("[Error] LuaBuffEncode failed!\n");
        goto _exit;
    }

    //加密数据写入目标文件
    fopen_s(&fEncrypt, szEncodeFilePath, "wb");
    if (!fEncrypt)
    {
        printf("open file %s failed\n", szEncodeFilePath);
        goto _exit;
    }
    fwrite(pEncryptBuf, ulEncryptSize, 1, fEncrypt);
    printf("[Info]encrypt pattern %s to %s successfully\n", strPath.c_str(), szEncodeFilePath);
    bRet = true;

_exit:
    if (pOriginalBuf)
    {
        free(pOriginalBuf);
        pOriginalBuf = NULL;
    }

    if (pEncryptBuf)
    {
        FreeCypherBuff((unsigned char**)&pEncryptBuf);
        pEncryptBuf = NULL;
    }

    if (fOriginal)
    {
        fclose(fOriginal);
        fOriginal = NULL;
    }

    if (fEncrypt)
    {
        fclose(fEncrypt);
        fEncrypt = NULL;
    }

    return bRet;
}


/// <summary>
/// 解密文件
/// </summary>
/// <param name="strPath"></param>
/// <param name="strSuffix"></param>
/// <returns></returns>
bool decode_lua_file(const std::string& strPath)
{
    bool bRet       = false;
    FILE *fOriginal = NULL, *fEncrypt = NULL;
    char *pOriginalBuf = NULL, *pEncryptBuf = NULL;
    unsigned long ulOriginalSize = 0, ulEncryptSize = 0;
    int nVersion = 0;
    int ret      = 0;

    size_t nPos = strPath.rfind("\\");
    if (nPos == std::string::npos)
    {
        printf("[Error] Can not find \\! %s", strPath.c_str());
        return false;
    }
    //文件夹路径
    std::string strFilePath = strPath.substr(0, nPos);
    //文件名，去掉后缀名
    std::string strFileName = strPath.substr(nPos + 1, strPath.length() - nPos - 1);
    strFileName             = strFileName.substr(0, strFileName.rfind("$"));
    //解密后文件全路径
    char szDecodeFilePath[MAX_PATH];
    _snprintf_s(szDecodeFilePath, sizeof(szDecodeFilePath), "%s\\%s.%s", strFilePath.c_str(), strFileName.c_str(),
                SUFFIX_LUA);

    //读取文件
    fopen_s(&fOriginal, szDecodeFilePath, "wb");
    fopen_s(&fEncrypt, strPath.c_str(), "rb");
    if (!fEncrypt)
    {
        printf("[Error] Open file failed! %s\n", strPath.c_str());
        goto _exit;
    }
    if (!fOriginal)
    {
        printf("[Error] Open file failed! %s\n", szDecodeFilePath);
        goto _exit;
    }

    //读入加密pattern内容，校验MD5, 解析pattern header
    fseek(fEncrypt, 0, SEEK_END);
    ulEncryptSize = ftell(fEncrypt);
    if (ulEncryptSize <= sizeof(PATTERN_HEADER) + MD5LEN)
    {
        printf("[Error] pattern file is destroyed! %s\n", strPath.c_str());
        goto _exit;
    }
    pEncryptBuf = (char*)malloc(ulEncryptSize);
    if (!pEncryptBuf)
    {
        printf("[Error] malloc encrypt memory failed\n");
        goto _exit;
    }
    memset(pEncryptBuf, 0, ulEncryptSize);
    fseek(fEncrypt, 0, SEEK_SET);
    fread(pEncryptBuf, ulEncryptSize, 1, fEncrypt);

    if (0 != LuaBuffDecode((const unsigned char*)pEncryptBuf, ulEncryptSize, nVersion, (unsigned char**)&pOriginalBuf,
                           ulOriginalSize))
    {
        printf("[Error] LuaBuffDecode failed! %s\n", szDecodeFilePath);
        goto _exit;
    }

    //解密和解压后的数据写入目标文件
    fwrite(pOriginalBuf, ulOriginalSize, 1, fOriginal);
    printf("[Info] decrypt file %s successfully\n", strPath.c_str());
    bRet = true;

_exit:
    if (pOriginalBuf)
    {
        FreeCypherBuff((unsigned char**)&pOriginalBuf);
        pOriginalBuf = NULL;
    }

    if (pEncryptBuf)
    {
        free(pEncryptBuf);
        pEncryptBuf = NULL;
    }

    if (fOriginal)
    {
        fclose(fOriginal);
        fOriginal = NULL;
    }

    if (fEncrypt)
    {
        fclose(fEncrypt);
        fEncrypt = NULL;
    }

    return bRet;
}
#include "json_file_crypt.h"
#include "utility/HraUtils.h"

/// <summary>
/// 加密单个json文件
/// </summary>
/// <param name="strPath"></param>
/// <param name="nVersion"></param>
/// <returns></returns>
bool encode_json_file(const std::string& strPath, int nVersion)
{
    size_t iCount   = 0;
    bool bRet       = false;
    FILE *fEncrypt = NULL;
    unsigned char *pEncryptBuf = NULL;
    uint64_t ulEncryptSize = 0;

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

    if (UtilsFileEncryption((unsigned char**)&pEncryptBuf, ulEncryptSize, strPath.c_str()) != 0)
    {
        printf("open file %s failed\n", szEncodeFilePath);
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
    if (pEncryptBuf)
    {
        free(pEncryptBuf);
        pEncryptBuf = NULL;
    }

    if (fEncrypt)
    {
        fclose(fEncrypt);
        fEncrypt = NULL;
    }

    return bRet;
}

/// <summary>
/// 解密的那个json文件
/// </summary>
/// <param name="strPath"></param>
/// <returns></returns>
bool decode_json_file(const std::string& strPath)
{
    bool bRet       = false;
    FILE *fOriginal = NULL;
    //char *pOriginalBuf = NULL;
    //unsigned long ulOriginalSize = 0;
    //int nVersion = 0;
    //int ret      = 0;
    std::string strOriginal;

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
                SUFFIX_JSON);
    strOriginal = UtilsFileDecryption(strPath.c_str());
    if (strOriginal.empty())
    {
        printf("[Error] File decrypt failed! %s\n", strPath.c_str());
        goto _exit;
    }

    //读取文件
    fopen_s(&fOriginal, szDecodeFilePath, "wb");
    if (!fOriginal)
    {
        printf("[Error] Open file failed! %s\n", szDecodeFilePath);
        goto _exit;
    }
    //解密和解压后的数据写入目标文件
    fwrite(strOriginal.c_str(), strOriginal.length(), 1, fOriginal);
    printf("[Info] decrypt file %s successfully\n", strPath.c_str());
    bRet = true;

_exit:
    if (fOriginal)
    {
        fclose(fOriginal);
        fOriginal = NULL;
    }

    return bRet;
}
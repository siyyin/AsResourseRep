#include "InstallUtility.h"
#include <wchar.h>
#include <securitybaseapi.h>
#include <ShlObj.h>
#include <algorithm>
#include <fstream>
#include <regex>
#include "zlib/unzip.h"
#include "zlib/zconf.h"
#include "zlib/zlib.h"
#include "zlib/zip.h"

#include "utility/HraAppDef.h"

#define BUFFER_SIZE 1024

/// <summary>
/// 删除目录，包括目录下的所有文件
/// </summary>
/// <param name="DirName"></param>
/// <returns></returns>
DWORD HraInst_RemoveDirectory(const wchar_t* DirName)
{
    WIN32_FIND_DATA FindFileData;
    ZeroMemory(&FindFileData, sizeof(WIN32_FIND_DATA));
    wchar_t szFileFilter[MAX_PATH];
    ZeroMemory(szFileFilter, sizeof(szFileFilter));
    wchar_t szFileName[MAX_PATH];
    ZeroMemory(szFileName, sizeof(szFileName));
    HANDLE hFind = NULL;
    DWORD dwError = ERROR_SUCCESS;

    if (DirName == NULL || wcslen(DirName) <= 0)
    {
        dwError = ERROR_BAD_ARGUMENTS;
        goto _exit;
    }

    //文件夹不存在直接返回成功
    if (!HraInst_IsDirExists(DirName))
    {
        dwError = ERROR_SUCCESS;
        goto _exit;
    }

    _snwprintf_s(szFileFilter, MAX_PATH, MAX_PATH - 1, L"%ls\\*", DirName);
    hFind = FindFirstFile(szFileFilter, &FindFileData);
    if (INVALID_HANDLE_VALUE == hFind)
    {
        dwError = GetLastError();
        dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
        goto _exit;
    }

    do
    {
        _snwprintf_s(szFileName, MAX_PATH, MAX_PATH - 1, L"%ls\\%ls", DirName, FindFileData.cFileName);
        if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if ((wcscmp(FindFileData.cFileName, L".") != 0) &&
                (wcscmp(FindFileData.cFileName, L"..") != 0)) //如果不是"." ".."目录
            {
                dwError = HraInst_RemoveDirectory(szFileName);
                if (dwError != ERROR_SUCCESS)
                {
                    goto _exit;
                }
            }
        }
        else
        {
            if (!DeleteFile(szFileName))
            {
                dwError = GetLastError();
                dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
                goto _exit;
            }
        }
    } while (FindNextFile(hFind, &FindFileData) != 0);

    if (!RemoveDirectory(DirName)) //删除目录
    {
        dwError = GetLastError();
        dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
        goto _exit;
    }

_exit:
    if (hFind != NULL && hFind != INVALID_HANDLE_VALUE)
    {
        FindClose(hFind);
        hFind = NULL;
    }

    return dwError;
}

/// <summary>
/// 删除目录，包括目录下的所有文件，包含例外文件或目录，例外的不删除，例外通过名称正则匹配
/// </summary>
/// <param name="bHasException"></param>
/// <param name="szExceptionRegex"></param>
/// <param name="pszDir"></param>
/// <returns></returns>
DWORD HraInst_RemoveDirectory_WithException(BOOL& bSubHasException, const wchar_t* pszExceptionRegex,
                                            const wchar_t* pszDirName)
{
    WIN32_FIND_DATA FindFileData;
    ZeroMemory(&FindFileData, sizeof(WIN32_FIND_DATA));
    wchar_t szFileFilter[MAX_PATH];
    ZeroMemory(szFileFilter, sizeof(szFileFilter));
    wchar_t szFileName[MAX_PATH];
    ZeroMemory(szFileName, sizeof(szFileName));
    HANDLE hFind  = NULL;
    DWORD dwError = ERROR_SUCCESS;
    char szRegFileName[MAX_PATH];
    memset(szRegFileName, 0, sizeof(szRegFileName));
    char szRegStr[MAX_PATH];
    memset(szRegStr, 0, sizeof(szRegStr));
    std::regex regExp;
    BOOL bCurrHasExp = FALSE;
    BOOL bSubHasExp = FALSE;

    if (pszDirName == NULL || wcslen(pszDirName) <= 0)
    {
        dwError = ERROR_BAD_ARGUMENTS;
        goto _exit;
    }

    // 文件夹不存在直接返回成功
    if (!HraInst_IsDirExists(pszDirName))
    {
        dwError = ERROR_SUCCESS;
        goto _exit;
    }

    if (pszExceptionRegex != NULL && wcslen(pszExceptionRegex) > 0)
    {
        dwError = HraInst_UnicodeToString(szRegStr, sizeof(szRegStr), pszExceptionRegex);
        if (dwError != ERROR_SUCCESS)
        {
            goto _exit;
        }
        regExp.assign(szRegStr);
    }
    
    _snwprintf_s(szFileFilter, MAX_PATH, MAX_PATH - 1, L"%ls\\*", pszDirName);
    hFind = FindFirstFile(szFileFilter, &FindFileData);
    if (INVALID_HANDLE_VALUE == hFind)
    {
        dwError = GetLastError();
        dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
        goto _exit;
    }

    do
    {
        //例外的跳过
        if (strlen(szRegStr) > 0)
        {
            dwError = HraInst_UnicodeToString(szRegFileName, sizeof(szRegFileName), FindFileData.cFileName);
            if (dwError != ERROR_SUCCESS)
            {
                goto _exit;
            }
            if (std::regex_match(szRegFileName, regExp))
            {
                bCurrHasExp = TRUE;
                continue;
            }
        }

        //不是例外的删除
        _snwprintf_s(szFileName, MAX_PATH, MAX_PATH - 1, L"%ls\\%ls", pszDirName, FindFileData.cFileName);
        if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if ((wcscmp(FindFileData.cFileName, L".") != 0) &&
                (wcscmp(FindFileData.cFileName, L"..") != 0)) // 如果不是"." ".."目录
            {
                bSubHasExp = FALSE;
                dwError = HraInst_RemoveDirectory_WithException(bSubHasExp, pszExceptionRegex, szFileName);
                if (dwError != ERROR_SUCCESS)
                {
                    goto _exit;
                }
                if (bSubHasExp)
                {
                    bCurrHasExp = TRUE;
                }
            }
        }
        else
        {
            if (!DeleteFile(szFileName))
            {
                dwError = GetLastError();
                dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
                goto _exit;
            }
        }
    } while (FindNextFile(hFind, &FindFileData) != 0);

    //目录下没有例外的才能删除
    if (!bCurrHasExp)
    {
        if (!RemoveDirectory(pszDirName)) // 删除目录
        {
            dwError = GetLastError();
            dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
            goto _exit;
        }
    }
    bSubHasException = bCurrHasExp;

_exit:
    if (hFind != NULL && hFind != INVALID_HANDLE_VALUE)
    {
        FindClose(hFind);
        hFind = NULL;
    }

    return dwError;
}

/// <summary>
/// 拷贝文件夹下的所有文件，目标目录不存在会自动创建
/// </summary>
/// <param name="pszSrcDir"></param>
/// <param name="pszDesDir"></param>
/// <returns></returns>
DWORD HraInst_CopyDirectory(const wchar_t* pszSrcDir, const wchar_t* pszDesDir)
{
    WIN32_FIND_DATA FindFileData;
    ZeroMemory(&FindFileData, sizeof(WIN32_FIND_DATA));
    wchar_t szFileFilter[MAX_PATH];
    ZeroMemory(szFileFilter, sizeof(szFileFilter));
    wchar_t szSrcSub[MAX_PATH];
    ZeroMemory(szSrcSub, sizeof(szSrcSub));
    wchar_t szDesSub[MAX_PATH];
    ZeroMemory(szDesSub, sizeof(szDesSub));
    HANDLE hFind  = NULL;
    DWORD dwError = ERROR_SUCCESS;

    if (pszSrcDir == NULL || pszDesDir == NULL || wcslen(pszSrcDir) <= 0 || wcslen(pszDesDir) <= 0)
    {
        dwError = ERROR_BAD_ARGUMENTS;
        goto _exit;
    }

    if (!HraInst_IsDirExists(pszDesDir))
    {
        if (!CreateDirectory(pszDesDir, NULL))
        {
            dwError = GetLastError();
            dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
            goto _exit;
        }
    }

    _snwprintf_s(szFileFilter, MAX_PATH, MAX_PATH - 1, L"%ls\\*", pszSrcDir);
    hFind = FindFirstFile(szFileFilter, &FindFileData);
    if (INVALID_HANDLE_VALUE == hFind)
    {
        dwError = GetLastError();
        dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
        goto _exit;
    }

    do
    {
        _snwprintf_s(szSrcSub, sizeof(szSrcSub) / sizeof(wchar_t), L"%ls\\%ls", pszSrcDir, FindFileData.cFileName);
        _snwprintf_s(szDesSub, sizeof(szDesSub) / sizeof(wchar_t), L"%ls\\%ls", pszDesDir, FindFileData.cFileName);

        if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if ((wcscmp(FindFileData.cFileName, L".") != 0) &&
                (wcscmp(FindFileData.cFileName, L"..") != 0)) //如果不是"." ".."目录
            {
                dwError = HraInst_CopyDirectory(szSrcSub, szDesSub);
                if (dwError != ERROR_SUCCESS)
                {
                    goto _exit;
                }
            }
        }
        else
        {
            if (!CopyFile(szSrcSub, szDesSub, FALSE))
            {
                dwError = GetLastError();
                goto _exit;
            }
        }
    } while (FindNextFile(hFind, &FindFileData) != 0);

_exit:
    if (hFind != NULL && hFind != INVALID_HANDLE_VALUE)
    {
        FindClose(hFind);
        hFind = NULL;
    }

    return dwError;
}

/// <summary>
/// 判断文件夹是否存在
/// </summary>
/// <param name="pszDirectory"></param>
/// <returns></returns>
BOOL HraInst_IsDirExists(const wchar_t* pszDirectory)
{
    if (pszDirectory == NULL || wcslen(pszDirectory) <= 0)
    {
        return FALSE;
    }
    DWORD dwAttributes = ::GetFileAttributes(pszDirectory);
    BOOL f             = (0xffffffff != dwAttributes) && (FILE_ATTRIBUTE_DIRECTORY & dwAttributes);
    return f;
}

/// <summary>
/// 去除首字符串
/// </summary>
/// <param name="strString"></param>
/// <param name="pszTrim"></param>
/// <returns></returns>
DWORD HraInst_LTrim(wchar_t* pszString, size_t nSizeCount, const wchar_t* pszTrim)
{
    if (!pszString || nSizeCount <= 0)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    std::wstring strString = pszString;
    if (pszTrim == NULL || wcslen(pszTrim) <= 0)
    {
        while (!strString.empty())
        {
            if (!iswspace(strString.at(0)))
            {
                break;
            }
            strString = strString.erase(0, 1);
        }
    }
    else
    {
        while (!strString.empty())
        {
            size_t nPos = strString.find(pszTrim);
            if (nPos != 0 || nPos == std::wstring::npos)
            {
                break;
            }
            strString = strString.erase(nPos, wcslen(pszTrim));
        }
    }

    _snwprintf_s(pszString, nSizeCount, nSizeCount - 1, L"%ls", strString.c_str());
    return ERROR_SUCCESS;
}

/// <summary>
/// 去除尾字符串
/// </summary>
/// <param name="strString"></param>
/// <param name="pszTrim"></param>
/// <returns></returns>
DWORD HraInst_RTrim(wchar_t* pszString, size_t nSizeCount, const wchar_t* pszTrim)
{
    if (!pszString || nSizeCount <= 0)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    std::wstring strString = pszString;
    if (pszTrim == NULL || wcslen(pszTrim) <= 0)
    {
        while (!strString.empty())
        {
            if (!iswspace(strString.at(strString.length() - 1)))
            {
                break;
            }
            strString = strString.erase(strString.length() - 1, 1);
        }
    }
    else
    {
        while (!strString.empty())
        {
            size_t nPos = strString.rfind(pszTrim);
            if (nPos != (strString.length() - wcslen(pszTrim)) || nPos == std::wstring::npos)
            {
                break;
            }
            strString = strString.erase(nPos, wcslen(pszTrim));
        }
    }

    _snwprintf_s(pszString, nSizeCount, nSizeCount - 1, L"%ls", strString.c_str());
    return ERROR_SUCCESS;
}

/// <summary>
/// 去除首尾字符串
/// </summary>
/// <param name="pszString"></param>
/// <param name="pszTrim"></param>
/// <returns></returns>
DWORD HraInst_Trim(wchar_t* pszString, size_t nBuffSize, const wchar_t* pszTrim)
{
    DWORD dwError = ERROR_SUCCESS;
    dwError       = HraInst_LTrim(pszString, nBuffSize, pszTrim);
    if (dwError != ERROR_SUCCESS)
    {
        return dwError;
    }
    return HraInst_RTrim(pszString, nBuffSize, pszTrim);
}

HRA_INSTALL_API DWORD HraInst_GetProgramDataDir(wchar_t* pszDirBuff, size_t nBuffSize)
{
    if (!pszDirBuff || nBuffSize <= 0)
    {
        return ERROR_BAD_ARGUMENTS;
    }
    wchar_t wszDirTmp[MAX_PATH] = {0};
    HRESULT hr                  = SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, wszDirTmp);
    if (hr != S_OK)
    {
        return ERROR_INVALID_FUNCTION;
    }
    _snwprintf_s(pszDirBuff, nBuffSize, nBuffSize - 1, L"%s", wszDirTmp);
    return ERROR_SUCCESS;
}

/// <summary>
/// 权限判断
/// </summary>
/// <param name="_bIsTokenMembership"></param>
/// <param name="_enumWellKnownSidType"></param>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
DWORD HraInst_CheckTokenMembership(BOOL& IsTokenMembership, const WELL_KNOWN_SID_TYPE emWellKnownSidType)
{
    DWORD dwError     = ERROR_SUCCESS;
    IsTokenMembership = FALSE;
    
    DWORD cbSidSize = SECURITY_MAX_SID_SIZE;
    PSID pSid       = ::LocalAlloc(LMEM_FIXED, cbSidSize);
    if (NULL == pSid)
    {
        dwError = ERROR_INVALID_HANDLE;
        return dwError;
    }

    if (!CreateWellKnownSid(emWellKnownSidType, NULL, pSid, &cbSidSize))
    {
        dwError = ::GetLastError();
        dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
        ::LocalFree(pSid);
        return dwError;
    }

    BOOL bIsMember = FALSE;
    if (!CheckTokenMembership(NULL, pSid, &bIsMember))
    {
        dwError = ::GetLastError();
        dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
        ::LocalFree(pSid);
        return dwError;
    }

    ::LocalFree(pSid);
    if (TRUE == bIsMember)
    {
        IsTokenMembership = TRUE;
    }

    return dwError;
}

/// <summary>
/// 判断是否admin权限
/// </summary>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
BOOL HraInst_IsAdmin()
{
    BOOL bIsAdmin = FALSE;
    if (HraInst_CheckTokenMembership(bIsAdmin, WinBuiltinAdministratorsSid) != ERROR_SUCCESS)
    {
        return FALSE;
    }
    return bIsAdmin;
}

/// <summary>
/// Unicode转String
/// </summary>
/// <param name="src"></param>
/// <param name="iCodePage"></param>
/// <returns></returns>
DWORD HraInst_UnicodeToString(char* pszDest, size_t nSizeCount, const wchar_t* src, unsigned int iCodePage)
{
    if (!pszDest)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    int iTextLen = WideCharToMultiByte(iCodePage, 0, src, -1, NULL, 0, NULL, NULL);
    if (nSizeCount <= iTextLen)
    {
        return ERROR_OUTOFMEMORY;
    }

    memset(pszDest, 0, nSizeCount);
    ::WideCharToMultiByte(iCodePage, 0, src, -1, pszDest, iTextLen, NULL, NULL);
    return ERROR_SUCCESS;
}

/// <summary>
/// String转Unicode
/// </summary>
/// <param name="src"></param>
/// <param name="iCodePage"></param>
/// <returns></returns>
DWORD HraInst_StringToUnicode(wchar_t* pszDest, size_t nSizeCount, const char* src, unsigned int iCodePage)
{
    if (!pszDest)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    int unicodeLen    = ::MultiByteToWideChar(iCodePage, 0, src, -1, NULL, 0);
    if (nSizeCount <= unicodeLen)
    {
        return ERROR_OUTOFMEMORY;
    }

    memset(pszDest, 0, nSizeCount * sizeof(wchar_t));
    ::MultiByteToWideChar(iCodePage, 0, src, -1, (LPWSTR)pszDest, unicodeLen);
    return ERROR_SUCCESS;
}

/// <summary>
/// 解压zip包
/// </summary>
/// <param name="pszZipPath"></param>
/// <param name="pszUnzipPath"></param>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
DWORD HraInst_Unzip(const wchar_t* pszZipPath, const wchar_t* pszUnzipPath)
{
    unzFile pvZipFile = NULL;
    unz_global_info zGlobalInfo;
    memset(&zGlobalInfo, 0, sizeof(zGlobalInfo));
    unz_file_info zFileInfo;
    char szSubFileName[MAX_PATH];
    memset(szSubFileName, 0, sizeof(szSubFileName));
    char szZipPath[MAX_PATH];
    memset(szZipPath, 0, sizeof(szZipPath));
    char szUnzipPath[MAX_PATH];
    memset(szUnzipPath, 0, sizeof(szUnzipPath));

    DWORD dwError = ERROR_SUCCESS;

    if (!pszZipPath || wcslen(pszZipPath) <= 0 || !pszUnzipPath || wcslen(pszUnzipPath) <= 0)
    {
        dwError = ERROR_BAD_ARGUMENTS; 
        goto _exit;
    }

    dwError = HraInst_UnicodeToString(szZipPath, sizeof(szZipPath), pszZipPath);
    if (dwError != ERROR_SUCCESS)
    {
        goto _exit;
    }
    dwError = HraInst_UnicodeToString(szUnzipPath, sizeof(szUnzipPath), pszUnzipPath);
    if (dwError != ERROR_SUCCESS)
    {
        goto _exit;
    }

    if (szUnzipPath[strlen(szUnzipPath) - 1] != '\\')
    {
        szUnzipPath[strlen(szUnzipPath)] = '\\';
    }

    //打开zip文件
    pvZipFile = unzOpen(szZipPath);
    if (NULL == pvZipFile)
    {
        dwError = errno;
        dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
        goto _exit;
    }

    //获取压缩文件的全局信息
    if (unzGetGlobalInfo(pvZipFile, &zGlobalInfo) != UNZ_OK)
    {
        dwError = errno;
        dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
        goto _exit;
    }

    //解压路径不存在则创建
    if (!HraInst_IsDirExists(pszUnzipPath))
    {
        if (!CreateDirectory(pszUnzipPath, NULL))
        {
            dwError = GetLastError();
            dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
            goto _exit;
        }
    }

    for (size_t i = 0; i < zGlobalInfo.number_entry; ++i)
    {
        //从压缩包循环获得子文件信息：文件名， 文件大小
        if (UNZ_OK !=
            unzGetCurrentFileInfo(pvZipFile, &zFileInfo, szSubFileName, sizeof(szSubFileName), NULL, 0, NULL, 0))
        {
            dwError = errno;
            dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
            goto _exit;
        }

        std::string strSubFileName = szSubFileName;
        replace(strSubFileName.begin(), strSubFileName.end(), '/', '\\');
        std::string strSubFilePath = szUnzipPath + strSubFileName; // 拼接子文件路径与解压路径
        if (strSubFileName.empty())
        {
            dwError = errno;
            dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
            goto _exit;
        }

        if (strSubFileName == "." || strSubFileName == ".\\" || strSubFileName == ".." || strSubFileName == "..\\")
        {
            unzGoToNextFile(pvZipFile);
            continue;
        }

        // 是个文件夹
        if (strSubFileName.rfind("\\") == strSubFileName.size() - 1)
        {
            std::string strPathTmp = strSubFilePath.substr(0, strSubFilePath.rfind("\\"));
            wchar_t szPathTmp[MAX_PATH];
            ZeroMemory(szPathTmp, sizeof(szPathTmp));
            dwError = HraInst_StringToUnicode(szPathTmp, MAX_PATH, strPathTmp.c_str());
            if (dwError != ERROR_SUCCESS)
            {
                goto _exit;
            }
            //判断路径是否存在，不存在则创建
            if (HraInst_IsDirExists(szPathTmp))
            {
                unzGoToNextFile(pvZipFile);
                continue;
            }

            if (!CreateDirectory(szPathTmp, NULL))
            {
                dwError = GetLastError();
                dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
                goto _exit;
            }

            unzGoToNextFile(pvZipFile);
            continue;
        }
        //是个文件
        else
        {
            std::string strPathTmp = strSubFilePath.substr(0, strSubFilePath.rfind("\\"));
            wchar_t szPathTmp[MAX_PATH];
            ZeroMemory(szPathTmp, sizeof(szPathTmp));
            dwError = HraInst_StringToUnicode(szPathTmp, MAX_PATH, strPathTmp.c_str());
            if (dwError != ERROR_SUCCESS)
            {
                goto _exit;
            }
            //判断父路径是否存在，不存在则创建
            if (!HraInst_IsDirExists(szPathTmp))
            {
                if (!CreateDirectory(szPathTmp, NULL))
                {
                    dwError = errno;
                    dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
                    goto _exit;
                }
            }
        }

        if (UNZ_OK != unzOpenCurrentFile(pvZipFile))
        {
            dwError = errno;
            dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
            goto _exit;
        }

        //申请内存
        size_t lFileLength   = zFileInfo.uncompressed_size; // 子文件长度
        char* pscFileData = (char*)malloc(lFileLength + 1);
        memset(pscFileData, 0, lFileLength + 1);

        //解压子文件
        int lUnzSubfileLen          = unzReadCurrentFile(pvZipFile, (voidp)pscFileData, (unsigned int)lFileLength);
        if (pscFileData != NULL)
        {
            pscFileData[lUnzSubfileLen] = '\0';
        }

        //写入文件
        std::ofstream file(strSubFilePath.c_str(), std::ios::out | std::ios::binary);
        if (!file.good())
        {
            dwError = errno;
            dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);

            unzCloseCurrentFile(pvZipFile);
            if (pscFileData)
            {
                free(pscFileData);
                pscFileData = NULL;
            }
            goto _exit;
        }
        file.seekp(0, std::ios::beg);
        if (pscFileData != NULL)
        {
            file.write(pscFileData, lUnzSubfileLen);
        }
        size_t nFileSize = file.tellp();
        file.close();
        unzCloseCurrentFile(pvZipFile);
        unzGoToNextFile(pvZipFile);
        if (pscFileData)
        {
            free(pscFileData);
            pscFileData = NULL;
        }
    }

_exit:
    if (pvZipFile)
    {
        unzClose(pvZipFile);
    }
    return dwError;
}

/// <summary>
/// 获得字符串中的指定参数
/// </summary>
/// <param name="pszValue"></param>
/// <param name="nSizeCount"></param>
/// <param name="strKey"></param>
/// <param name="strCmd"></param>
/// <returns></returns>
DWORD HraInst_GetParam(wchar_t* pszValue, size_t nSizeCount, const wchar_t* pszKey, const wchar_t* pszCmd)
{
    if (pszValue == NULL || nSizeCount <= 0 || pszKey == NULL || wcslen(pszKey) <= 0 || pszCmd == NULL || wcslen(pszCmd) <= 0)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    std::wstring strCmdTmp = pszCmd;
    std::wstring strFind   = std::wstring(HRA_INSTALL_PARAM_START) + pszKey + L" ";
    size_t nPos            = strCmdTmp.find(strFind);
    if (nPos == std::wstring::npos)
    {
        return ERROR_NOT_FOUND;
    }

    std::wstring strValue;
    strCmdTmp = strCmdTmp.erase(0, nPos + strFind.length());
    nPos      = strCmdTmp.find(HRA_INSTALL_PARAM_START);
    if (nPos != std::wstring::npos)
    {
        strValue = strCmdTmp.substr(0, nPos);
    }
    else
    {
        strValue = strCmdTmp;
    }

    _snwprintf_s(pszValue, nSizeCount, nSizeCount - 1, L"%ls", strValue.c_str());
    return HraInst_Trim(pszValue, nSizeCount);
}

/// <summary>
/// 从指定的注册表路径获取数据
/// </summary>
/// <param name="pszValue">结果</param>
/// <param name="pszSubKey">注册表项</param>
/// <param name="pszValueName">键名称</param>
/// <param name="hRoot">注册表Root</param>
/// <returns></returns>
DWORD HraInst_GetRegValue(wchar_t* pszValue, const wchar_t* pszSubKey, const wchar_t* pszValueName,
                                          HKEY hRoot)
{
    DWORD dwError = ERROR_SUCCESS;
    HKEY hKey;
    if ((dwError = RegOpenKeyExW(hRoot, pszSubKey, 0, KEY_READ, &hKey)) != ERROR_SUCCESS)
    {
        return dwError;
    }
    wchar_t wszValue[MAX_PATH] = {0};
    DWORD dwType               = 2;
    DWORD dwLen                = MAX_PATH;
    if ((dwError = RegQueryValueExW(hKey, pszValueName, NULL, &dwType, (LPBYTE)wszValue, &dwLen)) !=
        ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return dwError;
    }
    wcsncpy_s(pszValue, MAX_PATH, wszValue, MAX_PATH - 1);
    return ERROR_SUCCESS;
}

DWORD HraInst_JsontoWString(wchar_t* pwszValue, size_t nSizeCount, const Json::Value& jsObj)
{
    DWORD dwError = ERROR_SUCCESS;
    Json::FastWriter writer;
    std::string strValue;
    if (jsObj.size() == 0)
    {
        strValue = "";
    }
    strValue = writer.write(jsObj);
    dwError  = HraInst_StringToUnicode(pwszValue, nSizeCount, strValue.c_str());
    return dwError;
}

DWORD HraInst_WStringtoJson(Json::Value& jsObj, const wchar_t* wszValue)
{
    DWORD dwError = ERROR_SUCCESS;
    Json::Reader jsReader;
    char szBuffer[BUFFER_SIZE] = {0};
    if (wszValue == NULL || wcslen(wszValue) <= 0)
    {
        jsObj.clear();
        goto _end;
    }

    dwError = HraInst_UnicodeToString(szBuffer, BUFFER_SIZE, wszValue);
    if (dwError != ERROR_SUCCESS)
    {
        goto _end;
    }
    if (!jsReader.parse(szBuffer, jsObj))
    {
        jsObj.clear();
        dwError = ERROR_FUNCTION_FAILED;
    }

_end:
    return dwError;
}

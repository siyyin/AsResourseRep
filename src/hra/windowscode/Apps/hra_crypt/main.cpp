#include <windows.h>
#include <string>
#include <vector>
#include <regex>
#include <sys/stat.h>
#include <time.h>
#include "json_file_crypt.h"
#include "lua_file_crypt.h"
//#include "utility/HraUtils.h"
//#include "Libs/LibPatternCypher/md5.h"
//#include "Libs/LibPatternCypher/PatternCypher.h"

const char* USAGE_STRING = "[encode]:\n"
                           "hra_crypt.exe --encode --path ${path} --version ${version} [--suffix ${suffix}]\n"
                           "[decode]:\n"
                           "hra_crypt.exe --decode --path ${path} --suffix ${suffix} [--version ${version}]\n"
                           "Notice:\n"
                           "1:if ${path} can be file or directory;\n"
                           "2:${version} must be integer;\n";

const char* CMD_START   = "--"; //命令起始符，不用-是为了防止有些路径中带-号
const char* CMD_ENCODE  = "encode";  //加密
const char* CMD_DECODE  = "decode";  //解密
const char* CMD_PATH    = "path";  //路径（目录：则是扫描目录下所有文件；文件：指定文件）
const char* CMD_SUFFIX  = "suffix";  //文件后缀名
const char* CMD_VERSION = "version";  //版本

typedef struct _CMD_PARAM
{
    char cmd_type[MAX_PATH];
    char cmd_path[MAX_PATH];
    char cmd_suffix[MAX_PATH];
    int  cmd_version;
} CMD_PARAM;

/// <summary>
/// 判断是否文件夹
/// </summary>
/// <param name="pszPath"></param>
/// <returns></returns>
bool is_dir(const char* pszPath)
{
    DWORD dwAttributes = ::GetFileAttributesA(pszPath);
    bool bDir          = (0xffffffff != dwAttributes) && (FILE_ATTRIBUTE_DIRECTORY & dwAttributes);
    return bDir;
}

/// <summary>
/// 去首位空格
/// </summary>
/// <param name="strTrim"></param>
void trim(std::string& strTrim)
{
    //left trim
    while (!strTrim.empty() && isspace(strTrim.at(0)))
    {
        strTrim = strTrim.erase(0, 1);
    }

    //rignt trim
    while (!strTrim.empty() && isspace(strTrim.at(strTrim.length() - 1)))
    {
        strTrim = strTrim.erase(strTrim.length() - 1, 1);
    }
}

/// <summary>
/// 从参数字符串中获取指定key的参数
/// </summary>
/// <param name="strValue"></param>
/// <param name="strKey"></param>
/// <param name="strCmd"></param>
/// <returns></returns>
bool get_param(std::string& strValue, const std::string& strKey, const std::string& strCmd)
{
    std::string strCmdTmp = strCmd;
    std::string strFind = CMD_START + strKey;
    size_t nPos = strCmdTmp.find(strFind);
    if (nPos == std::string::npos)
    {
        return false;
    }

    strValue.clear();
    strCmdTmp = strCmdTmp.erase(0, nPos + strFind.length());
    nPos = strCmdTmp.find(CMD_START);
    if (nPos != std::string::npos)
    {
        strValue = strCmdTmp.substr(0, nPos);
    }
    else
    {
        strValue = strCmdTmp;
    }
    trim(strValue);

    return true;
}

std::string get_file_name_from_path(const std::string& strFileFullName)
{
    size_t nPos = 0;
    nPos        = strFileFullName.rfind("\\");
    if (nPos == std::string::npos)
    {
        return "";
    }
    return strFileFullName.substr(nPos + 1, strFileFullName.length() - nPos - 1);
}

/// <summary>
/// 解析传参
/// </summary>
/// <param name="sParam"></param>
/// <param name="argc"></param>
/// <param name="argv"></param>
/// <returns></returns>
bool parse_cmd(CMD_PARAM& sParam, int argc, char** argv)
{
    std::string strParam;
    for (int i = 0; i < argc; ++i)
    {
        strParam += argv[i];
        strParam += " ";
    }

    memset(&sParam, 0, sizeof(sParam));
    //处理加密还是解密
    std::string strValue;
    if (get_param(strValue, CMD_ENCODE, strParam) && !get_param(strValue, CMD_DECODE, strParam))
    {
        _snprintf_s(sParam.cmd_type, sizeof(sParam.cmd_type), "%s", CMD_ENCODE);
    }
    else if (!get_param(strValue, CMD_ENCODE, strParam) && get_param(strValue, CMD_DECODE, strParam))
    {
        _snprintf_s(sParam.cmd_type, sizeof(sParam.cmd_type), "%s", CMD_DECODE);
    }
    else
    {
        printf("[Error] Param error! Unable to determine whether it is encryption or decryption!\n");
        return false;
    }

    //路径
    if (!get_param(strValue, CMD_PATH, strParam))
    {
        printf("[Error] Param error! Unable to get path!\n");
        return false;
    }
    if (strValue.empty())
    {
        printf("[Error] Path empty!\n");
        return false;
    }
    _snprintf_s(sParam.cmd_path, sizeof(sParam.cmd_path), "%s", strValue.c_str());

    //加密、解密路径，必须要有版本号
    if ((strcmp(sParam.cmd_type, CMD_ENCODE) == 0) ||
        (strcmp(sParam.cmd_type, CMD_DECODE) == 0 && is_dir(sParam.cmd_path)))
    {
        if (!get_param(strValue, CMD_VERSION, strParam))
        {
            printf("[Error] Param error! Unable to get verion!\n");
            return false;
        }
        if (strValue.empty())
        {
            printf("[Error] Version empty!\n");
            return false;
        }
        sParam.cmd_version = std::atoi(strValue.c_str());
        if (sParam.cmd_version <= 0)
        {
            printf("[Error] Verion error! %d\n", sParam.cmd_version);
            return false;
        }
    }
    //解密文件，版本号通过文件名获取
    else
    {
        strValue           = sParam.cmd_path;
        strValue           = strValue.erase(0, strValue.rfind("$") + 1);
        sParam.cmd_version = std::atoi(strValue.c_str());
        if (sParam.cmd_version <= 0)
        {
            printf("[Error] Verion error! %d\n", sParam.cmd_version);
            return false;
        }
    }

    //解密、加密路径，必须要有后缀
    if ((strcmp(sParam.cmd_type, CMD_DECODE) == 0) ||
        (strcmp(sParam.cmd_type, CMD_ENCODE) == 0 && is_dir(sParam.cmd_path)))
    {
        //文件后缀
        if (!get_param(strValue, CMD_SUFFIX, strParam))
        {
            printf("[Error] Param error! Unable to get suffix!\n");
            return false;
        }
        if (strValue.empty())
        {
            printf("[Error] Suffix empty!\n");
            return false;
        }
        _snprintf_s(sParam.cmd_suffix, sizeof(sParam.cmd_suffix), "%s", strValue.c_str());
    }
    else
    {
        strValue = sParam.cmd_path;
        strValue = strValue.erase(0, strValue.rfind(".") + 1);
        if (strValue.empty())
        {
            printf("[Error] Suffix empty!\n");
            return false;
        }
        _snprintf_s(sParam.cmd_suffix, sizeof(sParam.cmd_suffix), "%s", strValue.c_str());
    }

    return true;
}

bool find_file(std::vector<std::string>& vctFiles, const std::string& strPath, const std::string& strFilter)
{
    //扫描目录下所有符合条件的文件
    WIN32_FIND_DATAA FindFileData;
    ZeroMemory(&FindFileData, sizeof(WIN32_FIND_DATAA));
    HANDLE hFind = NULL;
    bool bret    = false;
    //std::regex rexFileName(strRex);
    std::string strFullPath;

    std::string strFileString;
    if (strFilter.empty())
    {
        strFileString = strPath + "\\*";
    }
    else
    {
        strFileString = strPath + "\\" + strFilter;
    }

    hFind = FindFirstFileA(strFileString.c_str(), &FindFileData);
    if (INVALID_HANDLE_VALUE == hFind)
    {
        printf("[Error] hFind INVALID! Path:%s\n", strFileString.c_str());
        goto _exit;
    }

    do
    {
        strFullPath = strPath + "\\" + FindFileData.cFileName;
        if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if ((strcmp(FindFileData.cFileName, ".") == 0) ||
                (strcmp(FindFileData.cFileName, "..") == 0)) //如果不是"." ".."目录
            {
                continue;
            }

            if (!find_file(vctFiles, strFullPath.c_str(), strFilter))
            {
                bret = false;
                goto _exit;
            }
            continue;
        }
        else
        {
            vctFiles.push_back(strFullPath);
        }
    } while (FindNextFileA(hFind, &FindFileData) != 0);

    bret = true;

_exit:
    if (hFind)
    {
        FindClose(hFind);
        hFind = NULL;
    }

    return bret;
}



/// <summary>
/// 加密
/// </summary>
/// <param name="sParam"></param>
/// <returns></returns>
bool encode_dir(const std::string& strPath, const std::string& strSuffix, const int nVersion)
{
    std::string strPathTmp = strPath;
    if (strPathTmp.empty())
    {
        printf("[Error] Path empty!\n");
        return false;
    }

    //去掉末尾的"\"
    if (strPathTmp.at(strPathTmp.length() - 1) == '\\')
    {
        strPathTmp = strPathTmp.erase(strPathTmp.length() - 1, 1);
    }

    struct stat stFileStat;
    if (stat(strPathTmp.c_str(), &stFileStat) < 0)
    {
        printf("[Error] Path not exists! %s\n", strPathTmp.c_str());
        return false;
    }

    if (strSuffix.empty())
    {
        printf("[Error] Suffix empty!\n");
        return false;
    }

    std::vector<std::string> vctFiles;
    if (!find_file(vctFiles, strPathTmp, "*"))
    {
        printf("[Error] Find file error! %s\n", strPathTmp.c_str());
        return false;
    }

    std::string strFileRex = "^.*[.]";
    for (size_t i = 0; i < strSuffix.length(); ++i)
    {
        strFileRex += "[";
        strFileRex += tolower(strSuffix.at(i));
        strFileRex += toupper(strSuffix.at(i));
        strFileRex += "]";
    }
    strFileRex += "$";
    std::regex regFileName(strFileRex);
    int nCount = 0;
    for (std::vector<std::string>::const_iterator it = vctFiles.begin(); vctFiles.end() != it; ++it)
    {
        std::string strFileName = get_file_name_from_path(*it);
        if (!std::regex_match(strFileName, regFileName))
        {
            continue;
        }

        if (strSuffix == SUFFIX_JSON)
        {
            if (!encode_json_file(*it, nVersion))
            {
                printf("[Error] encode_file error! %s\n", it->c_str());
                return false;
            }
            printf("[Info] encode_file succeed! %s\n", it->c_str());
            ++nCount;
        }
        else if (strSuffix == SUFFIX_LUA)
        {
            if (!encode_lua_file(*it, nVersion))
            {
                printf("[Error] encode_file error! %s\n", it->c_str());
                return false;
            }
            printf("[Info] encode_file succeed! %s\n", it->c_str());
            ++nCount;
        }
        else
        {
            printf("[Error] cmd_suffix:%s error!\n", strSuffix.c_str());
            return false;
        }
    }

    printf("[Info] encode %d files succeed!\n", nCount);
    return true;
}


/// <summary>
/// 解密
/// </summary>
/// <param name="sParam"></param>
/// <returns></returns>
bool decode_dir(const std::string& strPath, const std::string& strSuffix, const int nVersion)
{
    std::string strPathTmp = strPath;
    if (strPathTmp.empty())
    {
        printf("[Error] Path empty!\n");
        return false;
    }

    //去掉末尾的"\"
    if (strPathTmp.at(strPathTmp.length() - 1) == '\\')
    {
        strPathTmp = strPathTmp.erase(strPathTmp.length() - 1, 1);
    }

    struct stat stFileStat;
    if (stat(strPathTmp.c_str(), &stFileStat) < 0)
    {
        printf("[Error] Path not exists! %s\n", strPathTmp.c_str());
        return false;
    }

    std::vector<std::string> vctFiles;
    if (!find_file(vctFiles, strPathTmp, "*"))
    {
        printf("[Error] Find file error! %s\n", strPathTmp.c_str());
        return false;
    }

    char szFileRex[MAX_PATH];
    memset(szFileRex, 0, sizeof(szFileRex));
    if (nVersion <= 0)
    {
        _snprintf_s(szFileRex, sizeof(szFileRex), "^.*[\\$][0-9]{n}$");
    }
    else
    {
        _snprintf_s(szFileRex, sizeof(szFileRex), "^.*\\$%d$", nVersion);
    }
    
    std::regex regFileName(szFileRex);
    int nCount = 0;
    for (std::vector<std::string>::const_iterator it = vctFiles.begin(); vctFiles.end() != it; ++it)
    {
        std::string strFileName = get_file_name_from_path(*it);
        if (!std::regex_match(strFileName, regFileName))
        {
            continue;
        }

        if (strSuffix == SUFFIX_JSON)
        {
            if (!decode_json_file(*it))
            {
                printf("[Error] decode_file error! %s\n", it->c_str());
                return false;
            }
            printf("[Info] decode_file succeed! %s\n", it->c_str());
            ++nCount;
        }
        else if (strSuffix == SUFFIX_LUA)
        {
            if (!decode_lua_file(*it))
            {
                printf("[Error] decode_file error! %s\n", it->c_str());
                return false;
            }
            printf("[Info] decode_file succeed! %s\n", it->c_str());
            ++nCount;
        }
        else
        {
            printf("[Error] cmd_suffix:%s error!\n", strSuffix.c_str());
            return false;
        }
    }

    printf("[Info] decode %d files succeed!\n", nCount);
    return true;
}


int main(int argc, char** argv)
{
    //解析参数
    CMD_PARAM sParam;
    memset(&sParam, 0, sizeof(sParam));
    if (!parse_cmd(sParam, argc, argv))
    {
        printf("[Error] parse_cmd error!\n");
        printf(USAGE_STRING);
        return -1;
    }

    if (strcmp(sParam.cmd_type, CMD_ENCODE) == 0)
    {
        if (is_dir(sParam.cmd_path))
        {
            if (!encode_dir(sParam.cmd_path, sParam.cmd_suffix, sParam.cmd_version))
            {
                printf("[Error] encode_dir error!\n");
                return -1;
            }
        }
        else
        {
            if (_stricmp(sParam.cmd_suffix, SUFFIX_JSON) == 0)
            {
                if (!encode_json_file(sParam.cmd_path, sParam.cmd_version))
                {
                    printf("[Error] encode_file error!\n");
                    return -1;
                }
            }
            else if (_stricmp(sParam.cmd_suffix, SUFFIX_LUA) == 0)
            {
                if (!encode_lua_file(sParam.cmd_path, sParam.cmd_version))
                {
                    printf("[Error] encode_file error!\n");
                    return -1;
                }
            }
            else
            {
                printf("[Error] cmd_suffix:%s error!\n", sParam.cmd_suffix);
                return -1;
            }
        }
    }
    else if (strcmp(sParam.cmd_type, CMD_DECODE) == 0)
    {
        if (is_dir(sParam.cmd_path))
        {
            if (!decode_dir(sParam.cmd_path, sParam.cmd_suffix, sParam.cmd_version))
            {
                printf("[Error] decode_dir error!\n");
                return -1;
            }
        }
        else
        {
            if (_stricmp(sParam.cmd_suffix, SUFFIX_JSON) == 0)
            {
                if (!decode_json_file(sParam.cmd_path))
                {
                    printf("[Error] decode_file error!\n");
                    return -1;
                }
            }
            else if (_stricmp(sParam.cmd_suffix, SUFFIX_LUA) == 0)
            {
                if (!decode_lua_file(sParam.cmd_path))
                {
                    printf("[Error] decode_file error!\n");
                    return -1;
                }
            }
            else
            {
                printf("[Error] cmd_suffix:%s error!\n", sParam.cmd_suffix);
                return -1;
            }
        }
    }

    return 0;
}
#include "DolphinNTLMCode.h"
#include <string>
#include <fstream>
#include <Windows.h>

int main()
{
    char  path[MAX_PATH + 1];
    DWORD length = GetModuleFileNameA(NULL, path, MAX_PATH + 1);
    std::string pathString(path);
    if (length > 0)
    {
        std::string::size_type pos = pathString.rfind('\\');
        pathString                 = pathString.substr(0, pos + 1);
        SetCurrentDirectoryA(pathString.c_str());
    }

    std::string   strOutPath  = pathString + "..\\..\\compare_ret.txt";
    std::string   strFilePath = pathString  + "..\\..\\wpp.txt";
    std::ifstream ifs;
    ifs.open(strFilePath.c_str(), std::ios::in);
    if (!ifs.is_open())
    {
        printf("Open file:%s error!\n", strFilePath.c_str());
        return -1;
    }

    std::ofstream ofs;
    ofs.open(strOutPath.c_str(), std::ios::out);
    if (!ofs.is_open())
    {
        printf("Open file:%s error!\n", strOutPath.c_str());
        ifs.close();
        return -1;
    }

    int         iFileLine = 0;
    std::string strLine;
    while (std::getline(ifs, strLine))
    {
        ++iFileLine;

        //新算法
        char szNewHash[33];
        memset(szNewHash, 0, sizeof(szNewHash));
        if (dolphin_hash(strLine.c_str(), szNewHash, 33) != 0)
        {
            printf("dolphin_hash error! line:%d\n", iFileLine);
            // return -1;
        }

        //老算法
        char szOldHash[33];
        memset(szOldHash, 0, sizeof(szOldHash));
        if (dolphin_hash_code(strLine.c_str(), szOldHash) != 0)
        {
            printf("dolphin_hash_code error! line:%d\n", iFileLine);
            // return -1;
        }

        //比较
        int nCompRet = strcmp(szNewHash, szOldHash);

        //输出
        char szRet[2048];
        memset(szRet, 0, sizeof(szRet));
        _snprintf_s(szRet, sizeof(szRet), "pwd:%s, line:%d, ret:%d, new:%s, old:%s\n", strLine.c_str(), iFileLine,
                 nCompRet, szNewHash, szOldHash);
        printf(szRet);
        ofs.write(szRet, strlen(szRet));
        ofs.flush();
    }

    ifs.close();
    ofs.close();

    return 0;
}
// hra.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include "utility/MiniDumper.h"
#include "HRAMain.h"
#include "hra_cmd.h"

CMiniDumper g_miniDumper;


int wmain(int argc, wchar_t* argv[])
{
    int iRet = 0;
    //测试指令
    if (argc > 1)
    {
        iRet = hra_cmd_run(argc, argv);
    }
    //默认运行hra主程序，无参数传入
    else
    {
        iRet = HraAppInit();
        if (HRA_OK == iRet)
        {
            iRet = HraAppRun();
        }
        HraAppEnd();
    }
    
    return iRet;
}


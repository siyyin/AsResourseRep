#include "DolphinCore.h"
#include "DolphinCoreWorker.h"
#include "utility/comm.h"
#include "utility/Logger.h"

const USER_PWD_RESULT* DolphinCore_GetResult()
{
    return DolphinCoreWorker_GetResult();
}

void DolphinCore_FreeResult()
{
    return DolphinCoreWorker_FreeResult();
}

int DolphinCore_DoWorker(const wchar_t* szSystemFile, const wchar_t* szSamFile)
{
    //int ret = HRA_OK;
    //ret = ai_s_wpdump_init();
    //if (ret != HRA_OK)
    //{
    //    ai_s_wpdump_uninit();
    //    return ret;
    //}
    //ret = ai_s_wpdump_sam();
    //ai_s_wpdump_uninit();
    //return ret;
    
    return ai_s_wpdump_sam(szSystemFile, szSamFile);
}

int DolphinCore_Elevate()
{
    NTSTATUS status = ai_s_privilege_debug();
    if (!NT_SUCCESS(status))
    {
        return HRA_FAILED;
    }

    status = ai_s_token_elevate_system();
    if (!NT_SUCCESS(status))
    {
        return HRA_FAILED;
    }

    return HRA_OK;
}
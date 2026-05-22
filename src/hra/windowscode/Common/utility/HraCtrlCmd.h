#pragma once
#include "comm.h"
#include <map>
#include <mutex>

class HRA_UTILITY_EXPORT HraCtrlCmd
{
public:
    enum CmdDef
    {
        cmd_init = 0,
        cmd_cancel = 1
    };

    //struct CtrlCmd
    //{
    //    //std::string strTaskId;
    //    //int iWorkType;
    //    //int iRqType;
    //    uint64_t nThreadID;
    //    int iCmd;
    //    

    //    void clear()
    //    {
    //        //strTaskId.clear();
    //        //iWorkType = 0;
    //        //iRqType = 0;
    //        nThreadID = 0;
    //        iCmd = 0;
    //        
    //    }

    //    CtrlCmd()
    //    {
    //        clear();
    //    }
    //};

public:
    static HraCtrlCmd* getInstance();
    //bool pushCmd(const std::string& strTaskId, int iWorkType, int iRqType, int iCmd, uint64_t nThreadID);
    //int popCmd(const std::string& strTaskId, int iWorkType, int iRqType);
    //int getCmd(const std::string& strTaskId, int iWorkType, int iRqType);
    bool pushCmd(uint64_t nThreadID, int iCmd);
    int popCmd(uint64_t nThreadID);
    int getCmd(uint64_t nThreadID);
    void clear();

private:
    HraCtrlCmd();
    virtual ~HraCtrlCmd();
private:
    static HraCtrlCmd* m_pInstance;
    std::mutex m_mutex;
    //std::list<CtrlCmd> m_lstCmd;
    std::map<uint64_t, int> m_mapCmd;
};

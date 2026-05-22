#pragma once
#include "comm.h"
#include <list>
#include <mutex>
#include <string>

class HRA_UTILITY_EXPORT HraKbDataMgr
{
public:
    struct KbData
    {
        unsigned long long nSeq;
        std::string strData;

        void clear()
        {
            nSeq = 0;
            strData.clear();
        }

        KbData()
        {
            clear();
        }
    };

public:
    static HraKbDataMgr& getInstance();
    bool pushData(const KbData& data);
    bool popData(KbData& data, unsigned long long nSeq);
    bool getData(KbData& data, unsigned long long nSeq);
    void clear();

private:
    HraKbDataMgr();
    virtual ~HraKbDataMgr();

private:
    std::mutex m_mutex;
    std::list<KbData> m_lstData;
};

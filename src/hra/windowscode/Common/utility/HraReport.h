/*****************************************************************
* Copyright (C) 2021 Asia info security Technology Co.,Ltd.*
******************************************************************
* HraReport.h
*
* DESCRIPTION:
*     
* AUTHOR:
*     qinyong
* CREATED DATE:
*     2021-8-15
* REVISION:
*     1.0
*
* MODIFICATION HISTORY
* --------------------
* $Log:$
*
*****************************************************************/
#ifndef __HRA_REPORT_H__
#define __HRA_REPORT_H__
#include <iostream>
#include "comm.h"
//#include "include\AsiEsmIpcCommonDefine.h"
#include "HraIpcInterface/HraIpcCommDef.h"

#define MAX_BUFFER_LEN (1024)

class HRA_UTILITY_EXPORT CReportInfo 
{
public:
    CReportInfo();
    ~CReportInfo();
public:
    int Request(const HraMsgHead::MsgType& emMsgType, unsigned char ucMsgType, const char* pscContent,
                unsigned int ulContentLen);
    void SetCompress(enum CompressionMode enCompressionMode);
    void ShowRspHdr();

    int KbRequest(unsigned long long nSeq);

private:
    int SetPkgHdr(unsigned char* pucData, unsigned int ulDataLen, const HraMsgHead::MsgType& emMsgType);

private:
    unsigned char m_ucCompress;
};

#endif /* __HRA_REPORT_H__ */

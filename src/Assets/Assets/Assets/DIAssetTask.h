#pragma once
#include <string>
#include <iostream>
#include <map>
#include <vector>
#include <comdef.h>
#include <taskschd.h>
#include <mstask.h>

namespace di_rest_client
{

	class DIAssetTaskItem
	{
	public:
		// 关键字段
		std::string strTaskName;             // 计划名称
		std::string strTaskState;            // 任务状态，0："TASK_STATE_UNKNOWN(未知)"，1："TASK_STATE_DISABLED(已禁用)"，2："TASK_STATE_QUEUED(已排队)"，3："TASK_STATE_READY(就绪)"，4："TASK_STATE_RUNNING(正在运行)"
		
    // 触发器字段
    std::string strEnabled;                    // 触发器是否可用
		std::string strType;                       // 触发器的类型
		std::string strStartBoundary;              // 任务被触发的时间和日期
		std::string strID;                         // 触发器的ID
		std::string strEndBoundary;                // 任务被停止的时间和日期
		std::string strExecutionTimeLimit;         // 触发器允许任务运行的最大时间
		std::string strDetailMsg;                  // 详细信息

		std::string strTaskCreator;          // 用户
		std::string strExcuteCycle;          // 执行周期
		std::string strTaskStartProcessCmd;  // 执行命令或者脚本

		// 扩展字段
		std::string strTaskNextRunTime;      // 下一次运行时间
		std::string strTaskLastRunTime;      // 上一次运行时间
		std::string strTaskLastRunResult;    // 上一次运行结果
		std::string strTaskCreateTime;       // 创建时间
	};

	class DIAssetTask
	{
	public:
		DIAssetTask(void);
		~DIAssetTask(void);

		bool InitTasksList(void);
		bool InitTasksListXP(void);
    bool InitInstance(void);
    void UnInitInstance(void);
		void GetTaskItemByFolder(ITaskFolder *pTaskFolder);
		void EnumSubFolders(ITaskFolder *pTaskFolder);
		std::map<std::string, DIAssetTaskItem>& GetTasksList(void);

	private:
	};
}
patternver="0100.0007"
-- 定义漏洞匹配找到的信息类型
BaseType = {
    linux_kernel = 8,
    kernel_running = 9,
    kernel_boot = 10
}


VulType = {
    OS = 1,
    App = 2,
    Web = 3,
    db = 4
}

-- 定义漏洞匹配查找的匹配动作
BaseOper = {
    lessthan = 1,
    equalto = 2,
    greaterthan = 3,
    notinstalled = 4,
    boot_next = 6
}

BaseOS = {
    Rhel5 = 1,
    Rhel6 = 2,
    Rhel7 = 3,
    Rhel8 = 4,
    Rhel9 = 5,
}


local ruleList = {}
local File_Version = {}
local OS_Type = nil
local Linux_Product = nil
local Linux_Version = nil
local Linux_Kernel_Runing = nil
local Linux_Kernel_Boot = nil

-- 所有的模块都通过这个函数来实现添加
function AddModule(module_id)
    ruleList[#ruleList + 1] = module_id
end

function GetModule() 
    return ruleList 
end

function GetOsType() 
    return OS_Type 
end


function GetFileVersion(filename)
    --print(filename)
    if File_Version[filename] == nil then
        File_Version[filename] = extendFunc.GetFileVersion(filename)
        --File_Version[filename] = "0"
    end
    --print(File_Version[filename])
    return File_Version[filename]
end

function FileVersionCompare(Version1, Version2)
    if Version1==nil or Version2==nil then
        return BaseOper.lessthan
    end
    local V1 = {}
    local V2 = {}
    local len
    -- lua的string.match()是个伪正则匹配, 所以需要调C函数实现
    local PackVersion = extendFunc.VersionMatch(Version1)
    local PattVersion = extendFunc.VersionMatch(Version2)

    for w in string.gmatch(PackVersion, '[%w]+') do
        V1[#V1+1] = w
    end

    for w in string.gmatch(PattVersion, '[%w]+') do
        V2[#V2+1] = w
    end
    len = #V1
    if len>#V2 then
        len = #V2
    end

    -- print("version1:"..PackVersion)
    -- print("version2:"..PattVersion)
    for i=1,len do
        if #V1[i]>#V2[i] then
            -- print("BaseOper.greaterthan")
            return BaseOper.greaterthan
        elseif #V1[i]<#V2[i] then
            -- print("BaseOper.lessthan")
            return BaseOper.lessthan
        end
        if V1[i]>V2[i] then
            -- print("BaseOper.greaterthan")
            return BaseOper.greaterthan
        elseif V1[i]<V2[i] then
            -- print("BaseOper.lessthan")
            return BaseOper.lessthan
        end
    end

    if #V1 == #V2 then
        -- print("BaseOper.equalto")
        return BaseOper.equalto
    elseif #V1 > #V2 then
        -- print("BaseOper.greaterthan")
        return BaseOper.greaterthan
    else
        -- print("BaseOper.lessthan")
        return BaseOper.lessthan
    end
end


function GetKernelRuning()
    return Linux_Kernel_Runing
end

function GetKernelBoot()
    return Linux_Kernel_Boot
end

function InitGetInfo()
    -- 初始化一次
    --Linux_Product = "Red Hat Enterprise Linux"
    --Linux_Version = "7.1"
    --Linux_Kernel_Runing = "2.10.0-693.21.1.el7.x86_64"
    --Linux_Kernel_Boot = "2.10.0-693.21.1.el7.x86_64"

    Linux_Product = extendFunc.GetLinuxBuild()
    Linux_Version = extendFunc.LinuxVersion()
    Linux_Kernel_Runing = extendFunc.GetKernelRuning()
    Linux_Kernel_Boot = extendFunc.GetKernelBoot()

    --print(Linux_Product);
    --print(Linux_Version);
    --print(Linux_Kernel_Runing);
    --print(Linux_Kernel_Boot);

    ---获取Linux系统类型
    Linux_Version = string.sub(Linux_Version, 1, 1)
    if string.find(string.lower(Linux_Product),string.lower("BigCloud")) ~= nil or string.find(string.lower(Linux_Product),string.lower("Red Hat")) ~= nil or string.find(string.lower(Linux_Product),string.lower("centos")) ~= nil then
        if Linux_Version=="5" then
            OS_Type = BaseOS.Rhel5
        elseif Linux_Version=="6" then
            OS_Type = BaseOS.Rhel6
        elseif Linux_Version=="7" then
            OS_Type = BaseOS.Rhel7
        elseif Linux_Version=="8" then
            OS_Type = BaseOS.Rhel8
        elseif Linux_Version=="9" then
            OS_Type = BaseOS.Rhel9
        end
    end


	--print(OS_Type)
    return
end



InitGetInfo()

----------------------------------------------------------------------------------------
--              所有的pattern 都必须继承自该类。并实现其中的Scan                 --
----------------------------------------------------------------------------------------
--- the base class of VulRule

VulRule = {
    PatchId = "",
    PatchUrl = "https://access.redhat.com/errata/",
    PatchFull = "",
    CVEId = "",
    CVEUrl = "https://access.redhat.com/security/cve/",
    CVEUrlFull = "",
    description = "",
    CVEType = VulType.OS,
    criteria = {
        OS = nil,
        logic = {Type = nil, filename = nil, Version = nil, Oper = nil}
    }

}

function VulRule:new(r)
    r = r or {}
    self.__index = self
    setmetatable(r, self)
    return r
end

function VulRule:Scan()
    local Bfind = false
    ---print(self.CVEId)
    for _, tab in ipairs(self.criteria) do
        ---print(tab.OS)
        if tab.OS == GetOsType() then
            Bfind = true
            Binstall = false
            for _, value in pairs(tab.logic) do
                local Oper = value["Oper"]
                local Type = value["Type"]
                local filename = value["filename"]
                local Version = value["Version"]
                if Type == BaseType.kernel_running then
                    Binstall = true
                    if FileVersionCompare(GetKernelRuning(), Version) ~= Oper then
                        Bfind = false
                        break
                    elseif string.find(string.lower(filename),string.lower("rt")) ~= nil and string.find(string.lower(GetKernelRuning()),string.lower("rt")) == nil then
                        Bfind = false
                        break
                    elseif string.find(string.lower(filename),string.lower("rt")) == nil and string.find(string.lower(GetKernelRuning()),string.lower("rt")) ~= nil then
                        Bfind = false
                        break
                    end
                elseif Type == BaseType.kernel_boot then
                    Binstall = true
                    if FileVersionCompare(GetKernelBoot(), Version) ~= Oper then
                        Bfind = false
                        break
                    elseif string.find(string.lower(filename),string.lower("rt")) ~= nil and string.find(string.lower(GetKernelBoot()),string.lower("rt")) == nil then
                        Bfind = false
                        break
                    elseif string.find(string.lower(filename),string.lower("rt")) == nil and string.find(string.lower(GetKernelBoot()),string.lower("rt")) ~= nil then
                        Bfind = false
                        break
                    end
                elseif Type == BaseType.linux_kernel then
                    local filever = GetFileVersion(filename)
                    if not Binstall and FileVersionCompare(filever, "0") == BaseOper.greaterthan then
                        Binstall = true
                    end
                    if FileVersionCompare(filever, Version) ~= Oper then
                        Bfind = false
                        break
                    end
                end

                ---for key0, value0 in pairs(value) do
                ---	print("\t", key0, "===>", value0)
                ---end
            end

            if Bfind and Binstall then
                ---print(self.CVEId)
                ---print(tab.OS)
                return true
            end
        end
    end
    return false
end

function VulRule:createScanResult() return self.PatchId,self.PatchUrl,self.PatchFull,self.CVEId,self.CVEUrl,self.CVEUrlFull,self.description,self.CVEType end

RHBA_2021_0623_Rule = VulRule:new()

RHBA_2021_0623 = RHBA_2021_0623_Rule:new{
PatchId = "RHBA-2021:0623",
CVEId = "CVE-2020-8696",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "microcode_ctl",Version = "2.1-73.8.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHBA_2021_0623)

RHSA_2020_0027_Rule = VulRule:new()

RHSA_2020_0027 = RHSA_2020_0027_Rule:new{
PatchId = "RHSA-2020:0027",
CVEId = "CVE-2019-15239",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1062.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1062.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1062.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1062",Version = "1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.4.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1062.4.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1062.4.1.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.4.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1062.4.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1062_4_1",Version = "1-6.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.1.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1062.1.2.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1062.1.2.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.1.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1062.1.2.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1062_1_2",Version = "1-9.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.1.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1062.1.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1062.1.1.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.1.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1062.1.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1062_1_1",Version = "1-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.4.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1062.4.2.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1062.4.2.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.4.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1062.4.2.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1062_4_2",Version = "1-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.4.3.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1062.4.3.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1062.4.3.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.4.3.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1062.4.3.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1062_4_3",Version = "1-3.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0027)

RHSA_2020_0028_Rule = VulRule:new()

RHSA_2020_0028 = RHSA_2020_0028_Rule:new{
PatchId = "RHSA-2020:0028",
CVEId = "CVE-2019-11135",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.4.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1062.4.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1062.4.1.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.4.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1062.4.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1062_4_1",Version = "1-4.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.1.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1062.1.2.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1062.1.2.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.1.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1062.1.2.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1062_1_2",Version = "1-7.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.1.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1062.1.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1062.1.1.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.1.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1062.1.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1062_1_1",Version = "1-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1062.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1062.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1062.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1062",Version = "1-9.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0028)

RHSA_2020_0085_Rule = VulRule:new()

RHSA_2020_0085 = RHSA_2020_0085_Rule:new{
PatchId = "RHSA-2020:0085",
CVEId = "CVE-2019-17026",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "68.4.1-1.el7_7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0085)

RHSA_2020_0120_Rule = VulRule:new()

RHSA_2020_0120 = RHSA_2020_0120_Rule:new{
PatchId = "RHSA-2020:0120",
CVEId = "CVE-2019-17024",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "68.4.1-2.el7_7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0120)

RHSA_2020_0122_Rule = VulRule:new()

RHSA_2020_0122 = RHSA_2020_0122_Rule:new{
PatchId = "RHSA-2020:0122",
CVEId = "CVE-2020-2655",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk",Version = "11.0.6.10-1.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-debug",Version = "11.0.6.10-1.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-demo",Version = "11.0.6.10-1.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-demo-debug",Version = "11.0.6.10-1.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-devel",Version = "11.0.6.10-1.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-devel-debug",Version = "11.0.6.10-1.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-headless",Version = "11.0.6.10-1.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-headless-debug",Version = "11.0.6.10-1.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-javadoc",Version = "11.0.6.10-1.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-javadoc-debug",Version = "11.0.6.10-1.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-javadoc-zip",Version = "11.0.6.10-1.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-javadoc-zip-debug",Version = "11.0.6.10-1.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-jmods",Version = "11.0.6.10-1.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-jmods-debug",Version = "11.0.6.10-1.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-src",Version = "11.0.6.10-1.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-src-debug",Version = "11.0.6.10-1.el7_7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0122)

RHSA_2020_0124_Rule = VulRule:new()

RHSA_2020_0124 = RHSA_2020_0124_Rule:new{
PatchId = "RHSA-2020:0124",
CVEId = "CVE-2019-1387",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "emacs-git",Version = "1.8.3.1-21.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "emacs-git-el",Version = "1.8.3.1-21.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git",Version = "1.8.3.1-21.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-all",Version = "1.8.3.1-21.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-bzr",Version = "1.8.3.1-21.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-cvs",Version = "1.8.3.1-21.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-daemon",Version = "1.8.3.1-21.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-email",Version = "1.8.3.1-21.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-gnome-keyring",Version = "1.8.3.1-21.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-gui",Version = "1.8.3.1-21.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-hg",Version = "1.8.3.1-21.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-instaweb",Version = "1.8.3.1-21.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-p4",Version = "1.8.3.1-21.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-svn",Version = "1.8.3.1-21.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gitk",Version = "1.8.3.1-21.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gitweb",Version = "1.8.3.1-21.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Git",Version = "1.8.3.1-21.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Git-SVN",Version = "1.8.3.1-21.el7_7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0124)

RHSA_2020_0194_Rule = VulRule:new()

RHSA_2020_0194 = RHSA_2020_0194_Rule:new{
PatchId = "RHSA-2020:0194",
CVEId = "CVE-2019-10086",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "apache-commons-beanutils",Version = "1.8.3-15.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "apache-commons-beanutils-javadoc",Version = "1.8.3-15.el7_7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0194)

RHSA_2020_0195_Rule = VulRule:new()

RHSA_2020_0195 = RHSA_2020_0195_Rule:new{
PatchId = "RHSA-2020:0195",
CVEId = "CVE-2019-17626",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-reportlab",Version = "2.5-9.el7_7.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-reportlab-docs",Version = "2.5-9.el7_7.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0195)

RHSA_2020_0196_Rule = VulRule:new()

RHSA_2020_0196 = RHSA_2020_0196_Rule:new{
PatchId = "RHSA-2020:0196",
CVEId = "CVE-2020-2659",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk",Version = "1.8.0.242.b08-0.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-accessibility",Version = "1.8.0.242.b08-0.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-accessibility-debug",Version = "1.8.0.242.b08-0.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-debug",Version = "1.8.0.242.b08-0.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-demo",Version = "1.8.0.242.b08-0.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-demo-debug",Version = "1.8.0.242.b08-0.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-devel",Version = "1.8.0.242.b08-0.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-devel-debug",Version = "1.8.0.242.b08-0.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-headless",Version = "1.8.0.242.b08-0.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-headless-debug",Version = "1.8.0.242.b08-0.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-javadoc",Version = "1.8.0.242.b08-0.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-javadoc-debug",Version = "1.8.0.242.b08-0.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-javadoc-zip",Version = "1.8.0.242.b08-0.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-javadoc-zip-debug",Version = "1.8.0.242.b08-0.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-src",Version = "1.8.0.242.b08-0.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-src-debug",Version = "1.8.0.242.b08-0.el7_7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0196)

RHSA_2020_0203_Rule = VulRule:new()

RHSA_2020_0203 = RHSA_2020_0203_Rule:new{
PatchId = "RHSA-2020:0203",
CVEId = "CVE-2019-18408",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bsdcpio",Version = "3.1.2-14.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bsdtar",Version = "3.1.2-14.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libarchive",Version = "3.1.2-14.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libarchive-devel",Version = "3.1.2-14.el7_7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0203)

RHSA_2020_0227_Rule = VulRule:new()

RHSA_2020_0227 = RHSA_2020_0227_Rule:new{
PatchId = "RHSA-2020:0227",
CVEId = "CVE-2019-13734",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "lemon",Version = "3.7.17-8.el7_7.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "sqlite",Version = "3.7.17-8.el7_7.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "sqlite-devel",Version = "3.7.17-8.el7_7.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "sqlite-doc",Version = "3.7.17-8.el7_7.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "sqlite-tcl",Version = "3.7.17-8.el7_7.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0227)

RHSA_2020_0262_Rule = VulRule:new()

RHSA_2020_0262 = RHSA_2020_0262_Rule:new{
PatchId = "RHSA-2020:0262",
CVEId = "CVE-2020-6851",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openjpeg2",Version = "2.3.1-2.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openjpeg2-devel",Version = "2.3.1-2.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openjpeg2-devel-docs",Version = "2.3.1-2.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openjpeg2-tools",Version = "2.3.1-2.el7_7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0262)

RHSA_2020_0366_Rule = VulRule:new()

RHSA_2020_0366 = RHSA_2020_0366_Rule:new{
PatchId = "RHSA-2020:0366",
CVEId = "CVE-2019-14378",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-img",Version = "1.5.3-167.el7_7.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm",Version = "1.5.3-167.el7_7.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-common",Version = "1.5.3-167.el7_7.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-tools",Version = "1.5.3-167.el7_7.4",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0366)

RHSA_2020_0374_Rule = VulRule:new()

RHSA_2020_0374 = RHSA_2020_0374_Rule:new{
PatchId = "RHSA-2020:0374",
CVEId = "CVE-2019-17133",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-bootwrapper",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump-devel",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python-perf",Version = "3.10.0-1062.12.1.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0374)

RHSA_2020_0378_Rule = VulRule:new()

RHSA_2020_0378 = RHSA_2020_0378_Rule:new{
PatchId = "RHSA-2020:0378",
CVEId = "CVE-2019-14867",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipa-client",Version = "4.6.5-11.el7_7.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipa-client-common",Version = "4.6.5-11.el7_7.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipa-common",Version = "4.6.5-11.el7_7.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipa-python-compat",Version = "4.6.5-11.el7_7.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipa-server",Version = "4.6.5-11.el7_7.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipa-server-common",Version = "4.6.5-11.el7_7.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipa-server-dns",Version = "4.6.5-11.el7_7.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipa-server-trust-ad",Version = "4.6.5-11.el7_7.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python2-ipaclient",Version = "4.6.5-11.el7_7.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python2-ipalib",Version = "4.6.5-11.el7_7.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python2-ipaserver",Version = "4.6.5-11.el7_7.4",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0378)

RHSA_2020_0468_Rule = VulRule:new()

RHSA_2020_0468 = RHSA_2020_0468_Rule:new{
PatchId = "RHSA-2020:0468",
CVEId = "CVE-2020-2604",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm",Version = "1.7.1.4.60-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-demo",Version = "1.7.1.4.60-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-devel",Version = "1.7.1.4.60-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-jdbc",Version = "1.7.1.4.60-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-plugin",Version = "1.7.1.4.60-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-src",Version = "1.7.1.4.60-1jpp.1.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0468)

RHSA_2020_0470_Rule = VulRule:new()

RHSA_2020_0470 = RHSA_2020_0470_Rule:new{
PatchId = "RHSA-2020:0470",
CVEId = "CVE-2020-2593",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-ibm",Version = "1.8.0.6.5-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-ibm-demo",Version = "1.8.0.6.5-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-ibm-devel",Version = "1.8.0.6.5-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-ibm-jdbc",Version = "1.8.0.6.5-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-ibm-plugin",Version = "1.8.0.6.5-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-ibm-src",Version = "1.8.0.6.5-1jpp.1.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0470)

RHSA_2020_0520_Rule = VulRule:new()

RHSA_2020_0520 = RHSA_2020_0520_Rule:new{
PatchId = "RHSA-2020:0520",
CVEId = "CVE-2020-6800",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "68.5.0-2.el7_7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0520)

RHSA_2020_0540_Rule = VulRule:new()

RHSA_2020_0540 = RHSA_2020_0540_Rule:new{
PatchId = "RHSA-2020:0540",
CVEId = "CVE-2019-18634",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "sudo",Version = "1.8.23-4.el7_7.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "sudo-devel",Version = "1.8.23-4.el7_7.2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0540)

RHSA_2020_0541_Rule = VulRule:new()

RHSA_2020_0541 = RHSA_2020_0541_Rule:new{
PatchId = "RHSA-2020:0541",
CVEId = "CVE-2020-2654",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.0-openjdk",Version = "1.7.0.251-2.6.21.0.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.0-openjdk-accessibility",Version = "1.7.0.251-2.6.21.0.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.0-openjdk-demo",Version = "1.7.0.251-2.6.21.0.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.0-openjdk-devel",Version = "1.7.0.251-2.6.21.0.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.0-openjdk-headless",Version = "1.7.0.251-2.6.21.0.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.0-openjdk-javadoc",Version = "1.7.0.251-2.6.21.0.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.0-openjdk-src",Version = "1.7.0.251-2.6.21.0.el7_7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0541)

RHSA_2020_0550_Rule = VulRule:new()

RHSA_2020_0550 = RHSA_2020_0550_Rule:new{
PatchId = "RHSA-2020:0550",
CVEId = "CVE-2020-8112",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openjpeg2",Version = "2.3.1-3.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openjpeg2-devel",Version = "2.3.1-3.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openjpeg2-devel-docs",Version = "2.3.1-3.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openjpeg2-tools",Version = "2.3.1-3.el7_7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0550)

RHSA_2020_0568_Rule = VulRule:new()

RHSA_2020_0568 = RHSA_2020_0568_Rule:new{
PatchId = "RHSA-2020:0568",
CVEId = "CVE-2019-14868",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ksh",Version = "20120801-140.el7_7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0568)

RHSA_2020_0576_Rule = VulRule:new()

RHSA_2020_0576 = RHSA_2020_0576_Rule:new{
PatchId = "RHSA-2020:0576",
CVEId = "CVE-2020-6798",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "68.5.0-1.el7_7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0576)

RHSA_2020_0578_Rule = VulRule:new()

RHSA_2020_0578 = RHSA_2020_0578_Rule:new{
PatchId = "RHSA-2020:0578",
CVEId = "CVE-2020-5312",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-pillow",Version = "2.0.0-20.gitd1c6db8.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-pillow-devel",Version = "2.0.0-20.gitd1c6db8.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-pillow-doc",Version = "2.0.0-20.gitd1c6db8.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-pillow-qt",Version = "2.0.0-20.gitd1c6db8.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-pillow-sane",Version = "2.0.0-20.gitd1c6db8.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-pillow-tk",Version = "2.0.0-20.gitd1c6db8.el7_7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0578)

RHSA_2020_0630_Rule = VulRule:new()

RHSA_2020_0630 = RHSA_2020_0630_Rule:new{
PatchId = "RHSA-2020:0630",
CVEId = "CVE-2020-8597",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ppp",Version = "2.4.5-34.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ppp-devel",Version = "2.4.5-34.el7_7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0630)

RHSA_2020_0703_Rule = VulRule:new()

RHSA_2020_0703 = RHSA_2020_0703_Rule:new{
PatchId = "RHSA-2020:0703",
CVEId = "CVE-2019-15605",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "http-parser",Version = "2.7.1-8.el7_7.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "http-parser-devel",Version = "2.7.1-8.el7_7.2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0703)

RHSA_2020_0704_Rule = VulRule:new()

RHSA_2020_0704 = RHSA_2020_0704_Rule:new{
PatchId = "RHSA-2020:0704",
CVEId = "CVE-2018-1311",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xerces-c",Version = "3.1.1-10.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xerces-c-devel",Version = "3.1.1-10.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xerces-c-doc",Version = "3.1.1-10.el7_7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0704)

RHSA_2020_0815_Rule = VulRule:new()

RHSA_2020_0815 = RHSA_2020_0815_Rule:new{
PatchId = "RHSA-2020:0815",
CVEId = "CVE-2020-6814",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "68.6.0-1.el7_7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0815)

RHSA_2020_0834_Rule = VulRule:new()

RHSA_2020_0834 = RHSA_2020_0834_Rule:new{
PatchId = "RHSA-2020:0834",
CVEId = "CVE-2019-19338",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-bootwrapper",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump-devel",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python-perf",Version = "3.10.0-1062.18.1.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0834)

RHSA_2020_0850_Rule = VulRule:new()

RHSA_2020_0850 = RHSA_2020_0850_Rule:new{
PatchId = "RHSA-2020:0850",
CVEId = "CVE-2019-11324",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-pip",Version = "9.0.3-7.el7_7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0850)

RHSA_2020_0851_Rule = VulRule:new()

RHSA_2020_0851 = RHSA_2020_0851_Rule:new{
PatchId = "RHSA-2020:0851",
CVEId = "CVE-2019-11236",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-virtualenv",Version = "15.1.0-4.el7_7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0851)

RHSA_2020_0853_Rule = VulRule:new()

RHSA_2020_0853 = RHSA_2020_0853_Rule:new{
PatchId = "RHSA-2020:0853",
CVEId = "CVE-2019-20044",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "zsh",Version = "5.0.2-34.el7_7.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "zsh-html",Version = "5.0.2-34.el7_7.2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0853)

RHSA_2020_0855_Rule = VulRule:new()

RHSA_2020_0855 = RHSA_2020_0855_Rule:new{
PatchId = "RHSA-2020:0855",
CVEId = "CVE-2020-1938",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat",Version = "7.0.76-11.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-admin-webapps",Version = "7.0.76-11.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-docs-webapp",Version = "7.0.76-11.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-el-2.2-api",Version = "7.0.76-11.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-javadoc",Version = "7.0.76-11.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-jsp-2.2-api",Version = "7.0.76-11.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-jsvc",Version = "7.0.76-11.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-lib",Version = "7.0.76-11.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-servlet-3.0-api",Version = "7.0.76-11.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-webapps",Version = "7.0.76-11.el7_7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0855)

RHSA_2020_0897_Rule = VulRule:new()

RHSA_2020_0897 = RHSA_2020_0897_Rule:new{
PatchId = "RHSA-2020:0897",
CVEId = "CVE-2020-10531",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "icu",Version = "50.2-4.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libicu",Version = "50.2-4.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libicu-devel",Version = "50.2-4.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libicu-doc",Version = "50.2-4.el7_7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0897)

RHSA_2020_0905_Rule = VulRule:new()

RHSA_2020_0905 = RHSA_2020_0905_Rule:new{
PatchId = "RHSA-2020:0905",
CVEId = "CVE-2020-6812",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "68.6.0-1.el7_7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0905)

RHSA_2020_0913_Rule = VulRule:new()

RHSA_2020_0913 = RHSA_2020_0913_Rule:new{
PatchId = "RHSA-2020:0913",
CVEId = "CVE-2019-20788",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvncserver",Version = "0.9.9-14.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvncserver-devel",Version = "0.9.9-14.el7_7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0913)

RHSA_2020_0984_Rule = VulRule:new()

RHSA_2020_0984 = RHSA_2020_0984_Rule:new{
PatchId = "RHSA-2020:0984",
CVEId = "CVE-2020-5208",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bmc-snmp-proxy",Version = "1.8.18-9.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "exchange-bmc-os-info",Version = "1.8.18-9.el7_7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipmitool",Version = "1.8.18-9.el7_7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0984)

RHSA_2020_1000_Rule = VulRule:new()

RHSA_2020_1000 = RHSA_2020_1000_Rule:new{
PatchId = "RHSA-2020:1000",
CVEId = "CVE-2019-17042",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "rsyslog",Version = "8.24.0-52.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "rsyslog-crypto",Version = "8.24.0-52.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "rsyslog-doc",Version = "8.24.0-52.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "rsyslog-elasticsearch",Version = "8.24.0-52.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "rsyslog-gnutls",Version = "8.24.0-52.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "rsyslog-gssapi",Version = "8.24.0-52.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "rsyslog-kafka",Version = "8.24.0-52.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "rsyslog-libdbi",Version = "8.24.0-52.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "rsyslog-mmaudit",Version = "8.24.0-52.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "rsyslog-mmjsonparse",Version = "8.24.0-52.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "rsyslog-mmkubernetes",Version = "8.24.0-52.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "rsyslog-mmnormalize",Version = "8.24.0-52.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "rsyslog-mmsnmptrapd",Version = "8.24.0-52.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "rsyslog-mysql",Version = "8.24.0-52.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "rsyslog-pgsql",Version = "8.24.0-52.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "rsyslog-relp",Version = "8.24.0-52.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "rsyslog-snmp",Version = "8.24.0-52.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "rsyslog-udpspoof",Version = "8.24.0-52.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1000)

RHSA_2020_1003_Rule = VulRule:new()

RHSA_2020_1003 = RHSA_2020_1003_Rule:new{
PatchId = "RHSA-2020:1003",
CVEId = "CVE-2019-13038",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mod_auth_mellon",Version = "0.14.0-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mod_auth_mellon-diagnostics",Version = "0.14.0-8.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1003)

RHSA_2020_1011_Rule = VulRule:new()

RHSA_2020_1011 = RHSA_2020_1011_Rule:new{
PatchId = "RHSA-2020:1011",
CVEId = "CVE-2015-2716",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "expat",Version = "2.1.0-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "expat-devel",Version = "2.1.0-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "expat-static",Version = "2.1.0-11.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1011)

RHSA_2020_1016_Rule = VulRule:new()

RHSA_2020_1016 = RHSA_2020_1016_Rule:new{
PatchId = "RHSA-2020:1016",
CVEId = "CVE-2019-9503",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-bootwrapper",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump-devel",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python-perf",Version = "3.10.0-1127.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1016)

RHSA_2020_1020_Rule = VulRule:new()

RHSA_2020_1020 = RHSA_2020_1020_Rule:new{
PatchId = "RHSA-2020:1020",
CVEId = "CVE-2019-5436",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "curl",Version = "7.29.0-57.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libcurl",Version = "7.29.0-57.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libcurl-devel",Version = "7.29.0-57.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1020)

RHSA_2020_1021_Rule = VulRule:new()

RHSA_2020_1021 = RHSA_2020_1021_Rule:new{
PatchId = "RHSA-2020:1021",
CVEId = "CVE-2019-3820",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gtk-update-icon-cache",Version = "3.22.30-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gtk3",Version = "3.22.30-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gtk3-devel",Version = "3.22.30-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gtk3-devel-docs",Version = "3.22.30-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gtk3-immodule-xim",Version = "3.22.30-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gtk3-immodules",Version = "3.22.30-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gtk3-tests",Version = "3.22.30-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tracker",Version = "1.10.5-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tracker-devel",Version = "1.10.5-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tracker-docs",Version = "1.10.5-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tracker-needle",Version = "1.10.5-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tracker-preferences",Version = "1.10.5-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "control-center",Version = "3.28.1-6.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "control-center-filesystem",Version = "3.28.1-6.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-online-accounts",Version = "3.28.2-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-online-accounts-devel",Version = "3.28.2-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "LibRaw",Version = "0.19.4-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "LibRaw-devel",Version = "0.19.4-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "LibRaw-static",Version = "0.19.4-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xchat",Version = "2.8.8-25.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xchat-tcl",Version = "2.8.8-25.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nautilus",Version = "3.26.3.1-7.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nautilus-devel",Version = "3.26.3.1-7.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nautilus-extensions",Version = "3.26.3.1-7.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gsettings-desktop-schemas",Version = "3.28.0-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gsettings-desktop-schemas-devel",Version = "3.28.0-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "shared-mime-info",Version = "1.8-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "colord",Version = "1.3.4-2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "colord-devel",Version = "1.3.4-2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "colord-devel-docs",Version = "1.3.4-2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "colord-extra-profiles",Version = "1.3.4-2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "colord-libs",Version = "1.3.4-2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libgweather",Version = "3.28.2-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libgweather-devel",Version = "3.28.2-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-settings-daemon",Version = "3.28.1-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-settings-daemon-devel",Version = "3.28.1-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "osinfo-db",Version = "20190805-2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libcanberra",Version = "0.30-9.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libcanberra-devel",Version = "0.30-9.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libcanberra-gtk2",Version = "0.30-9.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libcanberra-gtk3",Version = "0.30-9.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "accountsservice",Version = "0.6.50-7.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "accountsservice-devel",Version = "0.6.50-7.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "accountsservice-libs",Version = "0.6.50-7.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gdm",Version = "3.28.2-22.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gdm-devel",Version = "3.28.2-22.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gdm-pam-extensions-devel",Version = "3.28.2-22.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mutter",Version = "3.28.3-20.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mutter-devel",Version = "3.28.3-20.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell",Version = "3.28.3-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-classic-session",Version = "3.28.1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell-extension-alternate-tab",Version = "3.28.1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell-extension-apps-menu",Version = "3.28.1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell-extension-auto-move-windows",Version = "3.28.1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell-extension-common",Version = "3.28.1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell-extension-dash-to-dock",Version = "3.28.1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell-extension-disable-screenshield",Version = "3.28.1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell-extension-drive-menu",Version = "3.28.1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell-extension-extra-osk-keys",Version = "3.28.1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell-extension-horizontal-workspaces",Version = "3.28.1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell-extension-launch-new-instance",Version = "3.28.1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell-extension-native-window-placement",Version = "3.28.1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell-extension-no-hot-corner",Version = "3.28.1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell-extension-panel-favorites",Version = "3.28.1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell-extension-places-menu",Version = "3.28.1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell-extension-screenshot-window-sizer",Version = "3.28.1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell-extension-systemMonitor",Version = "3.28.1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell-extension-top-icons",Version = "3.28.1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell-extension-updates-dialog",Version = "3.28.1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell-extension-user-theme",Version = "3.28.1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell-extension-window-grouper",Version = "3.28.1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell-extension-window-list",Version = "3.28.1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell-extension-windowsNavigator",Version = "3.28.1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell-extension-workspace-indicator",Version = "3.28.1-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-tweak-tool",Version = "3.28.1-7.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1021)

RHSA_2020_1022_Rule = VulRule:new()

RHSA_2020_1022 = RHSA_2020_1022_Rule:new{
PatchId = "RHSA-2020:1022",
CVEId = "CVE-2018-10360",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "file",Version = "5.11-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "file-devel",Version = "5.11-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "file-libs",Version = "5.11-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "file-static",Version = "5.11-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-magic",Version = "5.11-36.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1022)

RHSA_2020_1034_Rule = VulRule:new()

RHSA_2020_1034 = RHSA_2020_1034_Rule:new{
PatchId = "RHSA-2020:1034",
CVEId = "CVE-2016-10245",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "doxygen",Version = "1.8.5-4.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "doxygen-doxywizard",Version = "1.8.5-4.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "doxygen-latex",Version = "1.8.5-4.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1034)

RHSA_2020_1036_Rule = VulRule:new()

RHSA_2020_1036 = RHSA_2020_1036_Rule:new{
PatchId = "RHSA-2020:1036",
CVEId = "CVE-2018-17407",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive",Version = "2012-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-adjustbox",Version = "svn26555.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-adjustbox-doc",Version = "svn26555.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ae",Version = "svn15878.1.4-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ae-doc",Version = "svn15878.1.4-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-algorithms",Version = "svn15878.0.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-algorithms-doc",Version = "svn15878.0.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-amscls",Version = "svn29207.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-amscls-doc",Version = "svn29207.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-amsfonts",Version = "svn29208.3.04-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-amsfonts-doc",Version = "svn29208.3.04-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-amsmath",Version = "svn29327.2.14-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-amsmath-doc",Version = "svn29327.2.14-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-anysize",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-anysize-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-appendix",Version = "svn15878.1.2b-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-appendix-doc",Version = "svn15878.1.2b-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-arabxetex",Version = "svn17470.v1.1.4-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-arabxetex-doc",Version = "svn17470.v1.1.4-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-arphic",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-arphic-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-attachfile",Version = "svn21866.v1.5b-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-attachfile-doc",Version = "svn21866.v1.5b-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-avantgar",Version = "svn28614.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-babel",Version = "svn24756.3.8m-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-babel-doc",Version = "svn24756.3.8m-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-babelbib",Version = "svn25245.1.31-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-babelbib-doc",Version = "svn25245.1.31-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-base",Version = "2012-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-beamer",Version = "svn29349.3.26-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-beamer-doc",Version = "svn29349.3.26-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-bera",Version = "svn20031.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-bera-doc",Version = "svn20031.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-beton",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-beton-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-bibtex",Version = "svn26689.0.99d-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-bibtex-bin",Version = "svn26509.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-bibtex-doc",Version = "svn26689.0.99d-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-bibtopic",Version = "svn15878.1.1a-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-bibtopic-doc",Version = "svn15878.1.1a-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-bidi",Version = "svn29650.12.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-bidi-doc",Version = "svn29650.12.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-bigfoot",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-bigfoot-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-bookman",Version = "svn28614.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-booktabs",Version = "svn15878.1.61803-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-booktabs-doc",Version = "svn15878.1.61803-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-breakurl",Version = "svn15878.1.30-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-breakurl-doc",Version = "svn15878.1.30-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-caption",Version = "svn29026.3.3__2013_02_03_-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-caption-doc",Version = "svn29026.3.3__2013_02_03_-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-carlisle",Version = "svn18258.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-carlisle-doc",Version = "svn18258.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-changebar",Version = "svn29349.3.5c-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-changebar-doc",Version = "svn29349.3.5c-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-changepage",Version = "svn15878.1.0c-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-changepage-doc",Version = "svn15878.1.0c-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-charter",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-charter-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-chngcntr",Version = "svn17157.1.0a-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-chngcntr-doc",Version = "svn17157.1.0a-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-cite",Version = "svn19955.5.3-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-cite-doc",Version = "svn19955.5.3-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-cjk",Version = "svn26296.4.8.3-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-cjk-doc",Version = "svn26296.4.8.3-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-cm",Version = "svn29581.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-cm-doc",Version = "svn29581.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-cm-lgc",Version = "svn28250.0.5-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-cm-lgc-doc",Version = "svn28250.0.5-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-cm-super",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-cm-super-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-cmap",Version = "svn26568.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-cmap-doc",Version = "svn26568.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-cmextra",Version = "svn14075.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-cns",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-cns-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-collectbox",Version = "svn26557.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-collectbox-doc",Version = "svn26557.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-collection-basic",Version = "svn26314.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-collection-documentation-base",Version = "svn17091.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-collection-fontsrecommended",Version = "svn28082.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-collection-htmlxml",Version = "svn28251.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-collection-latex",Version = "svn25030.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-collection-latexrecommended",Version = "svn25795.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-collection-xetex",Version = "svn29634.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-colortbl",Version = "svn25394.v1.0a-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-colortbl-doc",Version = "svn25394.v1.0a-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-courier",Version = "svn28614.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-crop",Version = "svn15878.1.5-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-crop-doc",Version = "svn15878.1.5-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-csquotes",Version = "svn24393.5.1d-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-csquotes-doc",Version = "svn24393.5.1d-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ctable",Version = "svn26694.1.23-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ctable-doc",Version = "svn26694.1.23-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-currfile",Version = "svn29012.0.7b-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-currfile-doc",Version = "svn29012.0.7b-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-datetime",Version = "svn19834.2.58-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-datetime-doc",Version = "svn19834.2.58-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-dvipdfm",Version = "svn26689.0.13.2d-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-dvipdfm-bin",Version = "svn13663.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-dvipdfm-doc",Version = "svn26689.0.13.2d-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-dvipdfmx",Version = "svn26765.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-dvipdfmx-bin",Version = "svn26509.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-dvipdfmx-def",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-dvipdfmx-doc",Version = "svn26765.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-dvipng",Version = "svn26689.1.14-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-dvipng-bin",Version = "svn26509.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-dvipng-doc",Version = "svn26689.1.14-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-dvips",Version = "svn29585.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-dvips-bin",Version = "svn26509.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-dvips-doc",Version = "svn29585.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ec",Version = "svn25033.1.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ec-doc",Version = "svn25033.1.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-eepic",Version = "svn15878.1.1e-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-eepic-doc",Version = "svn15878.1.1e-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-enctex",Version = "svn28602.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-enctex-doc",Version = "svn28602.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-enumitem",Version = "svn24146.3.5.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-enumitem-doc",Version = "svn24146.3.5.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-epsf",Version = "svn21461.2.7.4-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-epsf-doc",Version = "svn21461.2.7.4-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-epstopdf",Version = "svn26577.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-epstopdf-bin",Version = "svn18336.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-epstopdf-doc",Version = "svn26577.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-eso-pic",Version = "svn21515.2.0c-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-eso-pic-doc",Version = "svn21515.2.0c-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-etex",Version = "svn22198.2.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-etex-doc",Version = "svn22198.2.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-etex-pkg",Version = "svn15878.2.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-etex-pkg-doc",Version = "svn15878.2.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-etoolbox",Version = "svn20922.2.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-etoolbox-doc",Version = "svn20922.2.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-euenc",Version = "svn19795.0.1h-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-euenc-doc",Version = "svn19795.0.1h-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-euler",Version = "svn17261.2.5-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-euler-doc",Version = "svn17261.2.5-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-euro",Version = "svn22191.1.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-euro-doc",Version = "svn22191.1.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-eurosym",Version = "svn17265.1.4_subrfix-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-eurosym-doc",Version = "svn17265.1.4_subrfix-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-extsizes",Version = "svn17263.1.4a-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-extsizes-doc",Version = "svn17263.1.4a-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fancybox",Version = "svn18304.1.4-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fancybox-doc",Version = "svn18304.1.4-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fancyhdr",Version = "svn15878.3.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fancyhdr-doc",Version = "svn15878.3.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fancyref",Version = "svn15878.0.9c-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fancyref-doc",Version = "svn15878.0.9c-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fancyvrb",Version = "svn18492.2.8-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fancyvrb-doc",Version = "svn18492.2.8-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-filecontents",Version = "svn24250.1.3-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-filecontents-doc",Version = "svn24250.1.3-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-filehook",Version = "svn24280.0.5d-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-filehook-doc",Version = "svn24280.0.5d-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fix2col",Version = "svn17133.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fix2col-doc",Version = "svn17133.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fixlatvian",Version = "svn21631.1a-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fixlatvian-doc",Version = "svn21631.1a-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-float",Version = "svn15878.1.3d-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-float-doc",Version = "svn15878.1.3d-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fmtcount",Version = "svn28068.2.02-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fmtcount-doc",Version = "svn28068.2.02-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fncychap",Version = "svn20710.v1.34-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fncychap-doc",Version = "svn20710.v1.34-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fontbook",Version = "svn23608.0.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fontbook-doc",Version = "svn23608.0.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fontspec",Version = "svn29412.v2.3a-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fontspec-doc",Version = "svn29412.v2.3a-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fontware",Version = "svn26689.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fontware-bin",Version = "svn26509.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fontwrap",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fontwrap-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-footmisc",Version = "svn23330.5.5b-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-footmisc-doc",Version = "svn23330.5.5b-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fp",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fp-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fpl",Version = "svn15878.1.002-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-fpl-doc",Version = "svn15878.1.002-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-framed",Version = "svn26789.0.96-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-framed-doc",Version = "svn26789.0.96-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-garuda-c90",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-geometry",Version = "svn19716.5.6-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-geometry-doc",Version = "svn19716.5.6-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-glyphlist",Version = "svn28576.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-graphics",Version = "svn25405.1.0o-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-graphics-doc",Version = "svn25405.1.0o-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-gsftopk",Version = "svn26689.1.19.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-gsftopk-bin",Version = "svn26509.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-helvetic",Version = "svn28614.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-hyperref",Version = "svn28213.6.83m-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-hyperref-doc",Version = "svn28213.6.83m-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-hyph-utf8",Version = "svn29641.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-hyph-utf8-doc",Version = "svn29641.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-hyphen-base",Version = "svn29197.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-hyphenat",Version = "svn15878.2.3c-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-hyphenat-doc",Version = "svn15878.2.3c-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ifetex",Version = "svn24853.1.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ifetex-doc",Version = "svn24853.1.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ifluatex",Version = "svn26725.1.3-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ifluatex-doc",Version = "svn26725.1.3-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ifmtarg",Version = "svn19363.1.2a-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ifmtarg-doc",Version = "svn19363.1.2a-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ifoddpage",Version = "svn23979.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ifoddpage-doc",Version = "svn23979.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-iftex",Version = "svn29654.0.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-iftex-doc",Version = "svn29654.0.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ifxetex",Version = "svn19685.0.5-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ifxetex-doc",Version = "svn19685.0.5-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-index",Version = "svn24099.4.1beta-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-index-doc",Version = "svn24099.4.1beta-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-jadetex",Version = "svn23409.3.13-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-jadetex-bin",Version = "svn3006.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-jadetex-doc",Version = "svn23409.3.13-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-jknapltx",Version = "svn19440.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-jknapltx-doc",Version = "svn19440.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-kastrup",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-kastrup-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-kerkis",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-kerkis-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-koma-script",Version = "svn27255.3.11b-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-kpathsea",Version = "svn28792.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-kpathsea-bin",Version = "svn27347.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-kpathsea-doc",Version = "svn28792.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-kpathsea-lib",Version = "2012-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-kpathsea-lib-devel",Version = "2012-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-l3experimental",Version = "svn29361.SVN_4467-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-l3experimental-doc",Version = "svn29361.SVN_4467-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-l3kernel",Version = "svn29409.SVN_4469-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-l3kernel-doc",Version = "svn29409.SVN_4469-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-l3packages",Version = "svn29361.SVN_4467-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-l3packages-doc",Version = "svn29361.SVN_4467-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-lastpage",Version = "svn28985.1.2l-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-lastpage-doc",Version = "svn28985.1.2l-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-latex",Version = "svn27907.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-latex-bin",Version = "svn26689.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-latex-bin-bin",Version = "svn14050.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-latex-doc",Version = "svn27907.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-latex-fonts",Version = "svn28888.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-latex-fonts-doc",Version = "svn28888.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-latexconfig",Version = "svn28991.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-lettrine",Version = "svn29391.1.64-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-lettrine-doc",Version = "svn29391.1.64-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-listings",Version = "svn15878.1.4-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-listings-doc",Version = "svn15878.1.4-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-lm",Version = "svn28119.2.004-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-lm-doc",Version = "svn28119.2.004-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-lm-math",Version = "svn29044.1.958-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-lm-math-doc",Version = "svn29044.1.958-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ltxmisc",Version = "svn21927.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-lua-alt-getopt",Version = "svn29349.0.7.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-lua-alt-getopt-doc",Version = "svn29349.0.7.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-lualatex-math",Version = "svn29346.1.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-lualatex-math-doc",Version = "svn29346.1.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-luaotfload",Version = "svn26718.1.26-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-luaotfload-bin",Version = "svn18579.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-luaotfload-doc",Version = "svn26718.1.26-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-luatex",Version = "svn26689.0.70.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-luatex-bin",Version = "svn26912.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-luatex-doc",Version = "svn26689.0.70.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-luatexbase",Version = "svn22560.0.31-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-luatexbase-doc",Version = "svn22560.0.31-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-makecmds",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-makecmds-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-makeindex",Version = "svn26689.2.12-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-makeindex-bin",Version = "svn26509.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-makeindex-doc",Version = "svn26689.2.12-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-marginnote",Version = "svn25880.v1.1i-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-marginnote-doc",Version = "svn25880.v1.1i-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-marvosym",Version = "svn29349.2.2a-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-marvosym-doc",Version = "svn29349.2.2a-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-mathpazo",Version = "svn15878.1.003-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-mathpazo-doc",Version = "svn15878.1.003-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-mathspec",Version = "svn15878.0.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-mathspec-doc",Version = "svn15878.0.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-mdwtools",Version = "svn15878.1.05.4-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-mdwtools-doc",Version = "svn15878.1.05.4-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-memoir",Version = "svn21638.3.6j_patch_6.0g-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-memoir-doc",Version = "svn21638.3.6j_patch_6.0g-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-metafont",Version = "svn26689.2.718281-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-metafont-bin",Version = "svn26912.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-metalogo",Version = "svn18611.0.12-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-metalogo-doc",Version = "svn18611.0.12-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-metapost",Version = "svn26689.1.212-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-metapost-bin",Version = "svn26509.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-metapost-doc",Version = "svn26689.1.212-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-metapost-examples-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-mflogo",Version = "svn17487.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-mflogo-doc",Version = "svn17487.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-mfnfss",Version = "svn19410.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-mfnfss-doc",Version = "svn19410.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-mfware",Version = "svn26689.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-mfware-bin",Version = "svn26509.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-mh",Version = "svn29420.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-mh-doc",Version = "svn29420.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-microtype",Version = "svn29392.2.5-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-microtype-doc",Version = "svn29392.2.5-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-misc",Version = "svn24955.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-mnsymbol",Version = "svn18651.1.4-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-mnsymbol-doc",Version = "svn18651.1.4-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-mparhack",Version = "svn15878.1.4-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-mparhack-doc",Version = "svn15878.1.4-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-mptopdf",Version = "svn26689.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-mptopdf-bin",Version = "svn18674.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ms",Version = "svn24467.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ms-doc",Version = "svn24467.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-multido",Version = "svn18302.1.42-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-multido-doc",Version = "svn18302.1.42-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-multirow",Version = "svn17256.1.6-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-multirow-doc",Version = "svn17256.1.6-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-natbib",Version = "svn20668.8.31b-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-natbib-doc",Version = "svn20668.8.31b-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ncctools",Version = "svn15878.3.5-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ncctools-doc",Version = "svn15878.3.5-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ncntrsbk",Version = "svn28614.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-norasi-c90",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ntgclass",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ntgclass-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-oberdiek",Version = "svn26725.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-oberdiek-doc",Version = "svn26725.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-overpic",Version = "svn19712.0.53-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-overpic-doc",Version = "svn19712.0.53-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-palatino",Version = "svn28614.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-paralist",Version = "svn15878.2.3b-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-paralist-doc",Version = "svn15878.2.3b-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-parallel",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-parallel-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-parskip",Version = "svn19963.2.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-parskip-doc",Version = "svn19963.2.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-passivetex",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pdfpages",Version = "svn27574.0.4t-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pdfpages-doc",Version = "svn27574.0.4t-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pdftex",Version = "svn29585.1.40.11-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pdftex-bin",Version = "svn27321.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pdftex-def",Version = "svn22653.0.06d-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pdftex-doc",Version = "svn29585.1.40.11-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pgf",Version = "svn22614.2.10-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pgf-doc",Version = "svn22614.2.10-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-philokalia",Version = "svn18651.1.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-philokalia-doc",Version = "svn18651.1.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-placeins",Version = "svn19848.2.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-placeins-doc",Version = "svn19848.2.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-plain",Version = "svn26647.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-polyglossia",Version = "svn26163.v1.2.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-polyglossia-doc",Version = "svn26163.v1.2.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-powerdot",Version = "svn25656.1.4i-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-powerdot-doc",Version = "svn25656.1.4i-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-preprint",Version = "svn16085.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-preprint-doc",Version = "svn16085.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-psfrag",Version = "svn15878.3.04-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-psfrag-doc",Version = "svn15878.3.04-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pslatex",Version = "svn16416.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-psnfss",Version = "svn23394.9.2a-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-psnfss-doc",Version = "svn23394.9.2a-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pspicture",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pspicture-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pst-3d",Version = "svn17257.1.10-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pst-3d-doc",Version = "svn17257.1.10-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pst-blur",Version = "svn15878.2.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pst-blur-doc",Version = "svn15878.2.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pst-coil",Version = "svn24020.1.06-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pst-coil-doc",Version = "svn24020.1.06-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pst-eps",Version = "svn15878.1.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pst-eps-doc",Version = "svn15878.1.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pst-fill",Version = "svn15878.1.01-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pst-fill-doc",Version = "svn15878.1.01-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pst-grad",Version = "svn15878.1.06-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pst-grad-doc",Version = "svn15878.1.06-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pst-math",Version = "svn20176.0.61-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pst-math-doc",Version = "svn20176.0.61-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pst-node",Version = "svn27799.1.25-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pst-node-doc",Version = "svn27799.1.25-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pst-plot",Version = "svn28729.1.44-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pst-plot-doc",Version = "svn28729.1.44-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pst-slpe",Version = "svn24391.1.31-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pst-slpe-doc",Version = "svn24391.1.31-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pst-text",Version = "svn15878.1.00-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pst-text-doc",Version = "svn15878.1.00-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pst-tree",Version = "svn24142.1.12-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pst-tree-doc",Version = "svn24142.1.12-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pstricks",Version = "svn29678.2.39-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pstricks-add",Version = "svn28750.3.59-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pstricks-add-doc",Version = "svn28750.3.59-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pstricks-doc",Version = "svn29678.2.39-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ptext",Version = "svn28124.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ptext-doc",Version = "svn28124.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pxfonts",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-pxfonts-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-qstest",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-qstest-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-rcs",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-rcs-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-realscripts",Version = "svn29423.0.3b-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-realscripts-doc",Version = "svn29423.0.3b-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-rotating",Version = "svn16832.2.16b-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-rotating-doc",Version = "svn16832.2.16b-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-rsfs",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-rsfs-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-sansmath",Version = "svn17997.1.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-sansmath-doc",Version = "svn17997.1.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-sauerj",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-sauerj-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-scheme-basic",Version = "svn25923.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-section",Version = "svn20180.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-section-doc",Version = "svn20180.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-sectsty",Version = "svn15878.2.0.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-sectsty-doc",Version = "svn15878.2.0.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-seminar",Version = "svn18322.1.5-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-seminar-doc",Version = "svn18322.1.5-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-sepnum",Version = "svn20186.2.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-sepnum-doc",Version = "svn20186.2.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-setspace",Version = "svn24881.6.7a-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-setspace-doc",Version = "svn24881.6.7a-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-showexpl",Version = "svn27790.v0.3j-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-showexpl-doc",Version = "svn27790.v0.3j-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-soul",Version = "svn15878.2.4-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-soul-doc",Version = "svn15878.2.4-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-stmaryrd",Version = "svn22027.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-stmaryrd-doc",Version = "svn22027.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-subfig",Version = "svn15878.1.3-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-subfig-doc",Version = "svn15878.1.3-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-subfigure",Version = "svn15878.2.1.5-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-subfigure-doc",Version = "svn15878.2.1.5-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-svn-prov",Version = "svn18017.3.1862-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-svn-prov-doc",Version = "svn18017.3.1862-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-symbol",Version = "svn28614.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-t2",Version = "svn29349.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-t2-doc",Version = "svn29349.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-tetex",Version = "svn29585.3.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-tetex-bin",Version = "svn27344.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-tetex-doc",Version = "svn29585.3.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-tex",Version = "svn26689.3.1415926-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-tex-bin",Version = "svn26912.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-tex-gyre",Version = "svn18651.2.004-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-tex-gyre-doc",Version = "svn18651.2.004-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-tex-gyre-math",Version = "svn29045.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-tex-gyre-math-doc",Version = "svn29045.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-tex4ht",Version = "svn29474.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-tex4ht-bin",Version = "svn26509.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-tex4ht-doc",Version = "svn29474.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-texconfig",Version = "svn29349.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-texconfig-bin",Version = "svn27344.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-texlive.infra",Version = "svn28217.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-texlive.infra-bin",Version = "svn22566.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-texlive.infra-doc",Version = "svn28217.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-textcase",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-textcase-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-textpos",Version = "svn28261.1.7h-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-textpos-doc",Version = "svn28261.1.7h-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-thailatex",Version = "svn29349.0.5.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-thailatex-doc",Version = "svn29349.0.5.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-threeparttable",Version = "svn17383.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-threeparttable-doc",Version = "svn17383.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-thumbpdf",Version = "svn26689.3.15-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-thumbpdf-bin",Version = "svn6898.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-thumbpdf-doc",Version = "svn26689.3.15-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-times",Version = "svn28614.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-tipa",Version = "svn29349.1.3-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-tipa-doc",Version = "svn29349.1.3-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-titlesec",Version = "svn24852.2.10.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-titlesec-doc",Version = "svn24852.2.10.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-titling",Version = "svn15878.2.1d-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-titling-doc",Version = "svn15878.2.1d-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-tocloft",Version = "svn20084.2.3e-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-tocloft-doc",Version = "svn20084.2.3e-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-tools",Version = "svn26263.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-tools-doc",Version = "svn26263.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-txfonts",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-txfonts-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-type1cm",Version = "svn21820.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-type1cm-doc",Version = "svn21820.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-typehtml",Version = "svn17134.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-typehtml-doc",Version = "svn17134.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ucharclasses",Version = "svn27820.2.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ucharclasses-doc",Version = "svn27820.2.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ucs",Version = "svn27549.2.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ucs-doc",Version = "svn27549.2.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-uhc",Version = "svn16791.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-uhc-doc",Version = "svn16791.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ulem",Version = "svn26785.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-ulem-doc",Version = "svn26785.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-underscore",Version = "svn18261.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-underscore-doc",Version = "svn18261.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-unicode-math",Version = "svn29413.0.7d-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-unicode-math-doc",Version = "svn29413.0.7d-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-unisugar",Version = "svn22357.0.92-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-unisugar-doc",Version = "svn22357.0.92-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-url",Version = "svn16864.3.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-url-doc",Version = "svn16864.3.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-utopia",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-utopia-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-varwidth",Version = "svn24104.0.92-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-varwidth-doc",Version = "svn24104.0.92-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-wadalab",Version = "svn22576.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-wadalab-doc",Version = "svn22576.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-was",Version = "svn21439.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-was-doc",Version = "svn21439.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-wasy",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-wasy-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-wasysym",Version = "svn15878.2.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-wasysym-doc",Version = "svn15878.2.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-wrapfig",Version = "svn22048.3.6-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-wrapfig-doc",Version = "svn22048.3.6-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xcolor",Version = "svn15878.2.11-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xcolor-doc",Version = "svn15878.2.11-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xdvi",Version = "svn26689.22.85-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xdvi-bin",Version = "svn26509.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xecjk",Version = "svn28816.3.1.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xecjk-doc",Version = "svn28816.3.1.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xecolor",Version = "svn29660.0.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xecolor-doc",Version = "svn29660.0.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xecyr",Version = "svn20221.1.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xecyr-doc",Version = "svn20221.1.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xeindex",Version = "svn16760.0.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xeindex-doc",Version = "svn16760.0.2-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xepersian",Version = "svn29661.12.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xepersian-doc",Version = "svn29661.12.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xesearch",Version = "svn16041.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xesearch-doc",Version = "svn16041.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xetex",Version = "svn26330.0.9997.5-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xetex-bin",Version = "svn26912.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xetex-def",Version = "svn29154.0.95-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xetex-doc",Version = "svn26330.0.9997.5-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xetex-itrans",Version = "svn24105.4.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xetex-itrans-doc",Version = "svn24105.4.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xetex-pstricks",Version = "svn17055.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xetex-pstricks-doc",Version = "svn17055.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xetex-tibetan",Version = "svn28847.0.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xetex-tibetan-doc",Version = "svn28847.0.1-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xetexconfig",Version = "svn28819.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xetexfontinfo",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xetexfontinfo-doc",Version = "svn15878.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xifthen",Version = "svn15878.1.3-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xifthen-doc",Version = "svn15878.1.3-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xkeyval",Version = "svn27995.2.6a-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xkeyval-doc",Version = "svn27995.2.6a-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xltxtra",Version = "svn19809.0.5e-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xltxtra-doc",Version = "svn19809.0.5e-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xmltex",Version = "svn28273.0.8-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xmltex-bin",Version = "svn3006.0-45.20130427_r30134.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xmltex-doc",Version = "svn28273.0.8-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xstring",Version = "svn29258.1.7a-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xstring-doc",Version = "svn29258.1.7a-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xtab",Version = "svn23347.2.3f-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xtab-doc",Version = "svn23347.2.3f-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xunicode",Version = "svn23897.0.981-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-xunicode-doc",Version = "svn23897.0.981-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-zapfchan",Version = "svn28614.0-45.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "texlive-zapfding",Version = "svn28614.0-45.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1036)

RHSA_2020_1037_Rule = VulRule:new()

RHSA_2020_1037 = RHSA_2020_1037_Rule:new{
PatchId = "RHSA-2020:1037",
CVEId = "CVE-2019-9210",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "advancecomp",Version = "1.15-22.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1037)

RHSA_2020_1045_Rule = VulRule:new()

RHSA_2020_1045 = RHSA_2020_1045_Rule:new{
PatchId = "RHSA-2020:1045",
CVEId = "CVE-2018-10916",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "lftp",Version = "4.4.8-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "lftp-scripts",Version = "4.4.8-12.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1045)

RHSA_2020_1047_Rule = VulRule:new()

RHSA_2020_1047 = RHSA_2020_1047_Rule:new{
PatchId = "RHSA-2020:1047",
CVEId = "CVE-2018-7418",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "wireshark",Version = "1.10.14-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "wireshark-devel",Version = "1.10.14-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "wireshark-gnome",Version = "1.10.14-24.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1047)

RHSA_2020_1050_Rule = VulRule:new()

RHSA_2020_1050 = RHSA_2020_1050_Rule:new{
PatchId = "RHSA-2020:1050",
CVEId = "CVE-2018-4700",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "cups",Version = "1.6.3-43.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "cups-client",Version = "1.6.3-43.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "cups-devel",Version = "1.6.3-43.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "cups-filesystem",Version = "1.6.3-43.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "cups-ipptool",Version = "1.6.3-43.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "cups-libs",Version = "1.6.3-43.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "cups-lpd",Version = "1.6.3-43.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1050)

RHSA_2020_1051_Rule = VulRule:new()

RHSA_2020_1051 = RHSA_2020_1051_Rule:new{
PatchId = "RHSA-2020:1051",
CVEId = "CVE-2019-13313",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libosinfo",Version = "1.1.0-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libosinfo-devel",Version = "1.1.0-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libosinfo-vala",Version = "1.1.0-5.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1051)

RHSA_2020_1054_Rule = VulRule:new()

RHSA_2020_1054 = RHSA_2020_1054_Rule:new{
PatchId = "RHSA-2020:1054",
CVEId = "CVE-2018-13796",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mailman",Version = "2.1.15-30.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1054)

RHSA_2020_1061_Rule = VulRule:new()

RHSA_2020_1061 = RHSA_2020_1061_Rule:new{
PatchId = "RHSA-2020:1061",
CVEId = "CVE-2019-6477",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind",Version = "9.11.4-16.P2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-chroot",Version = "9.11.4-16.P2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-devel",Version = "9.11.4-16.P2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-export-devel",Version = "9.11.4-16.P2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-export-libs",Version = "9.11.4-16.P2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-libs",Version = "9.11.4-16.P2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-libs-lite",Version = "9.11.4-16.P2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-license",Version = "9.11.4-16.P2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-lite-devel",Version = "9.11.4-16.P2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11",Version = "9.11.4-16.P2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-devel",Version = "9.11.4-16.P2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-libs",Version = "9.11.4-16.P2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-utils",Version = "9.11.4-16.P2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-sdb",Version = "9.11.4-16.P2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-sdb-chroot",Version = "9.11.4-16.P2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-utils",Version = "9.11.4-16.P2.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1061)

RHSA_2020_1062_Rule = VulRule:new()

RHSA_2020_1062 = RHSA_2020_1062_Rule:new{
PatchId = "RHSA-2020:1062",
CVEId = "CVE-2019-7524",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dovecot",Version = "2.2.36-6.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dovecot-devel",Version = "2.2.36-6.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dovecot-mysql",Version = "2.2.36-6.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dovecot-pgsql",Version = "2.2.36-6.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dovecot-pigeonhole",Version = "2.2.36-6.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1062)

RHSA_2020_1068_Rule = VulRule:new()

RHSA_2020_1068 = RHSA_2020_1068_Rule:new{
PatchId = "RHSA-2020:1068",
CVEId = "CVE-2019-13345",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "squid",Version = "3.5.20-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "squid-migration-script",Version = "3.5.20-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "squid-sysvinit",Version = "3.5.20-15.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1068)

RHSA_2020_1074_Rule = VulRule:new()

RHSA_2020_1074 = RHSA_2020_1074_Rule:new{
PatchId = "RHSA-2020:1074",
CVEId = "CVE-2019-9959",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evince",Version = "3.28.2-9.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evince-browser-plugin",Version = "3.28.2-9.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evince-devel",Version = "3.28.2-9.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evince-dvi",Version = "3.28.2-9.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evince-libs",Version = "3.28.2-9.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evince-nautilus",Version = "3.28.2-9.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "poppler",Version = "0.26.5-42.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "poppler-cpp",Version = "0.26.5-42.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "poppler-cpp-devel",Version = "0.26.5-42.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "poppler-demos",Version = "0.26.5-42.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "poppler-devel",Version = "0.26.5-42.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "poppler-glib",Version = "0.26.5-42.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "poppler-glib-devel",Version = "0.26.5-42.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "poppler-qt",Version = "0.26.5-42.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "poppler-qt-devel",Version = "0.26.5-42.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "poppler-utils",Version = "0.26.5-42.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1074)

RHSA_2020_1080_Rule = VulRule:new()

RHSA_2020_1080 = RHSA_2020_1080_Rule:new{
PatchId = "RHSA-2020:1080",
CVEId = "CVE-2019-3890",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evolution-data-server",Version = "3.28.5-4.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evolution-data-server-devel",Version = "3.28.5-4.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evolution-data-server-doc",Version = "3.28.5-4.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evolution-data-server-langpacks",Version = "3.28.5-4.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evolution-data-server-perl",Version = "3.28.5-4.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evolution-data-server-tests",Version = "3.28.5-4.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "atk",Version = "2.28.1-2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "atk-devel",Version = "2.28.1-2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evolution",Version = "3.28.5-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evolution-bogofilter",Version = "3.28.5-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evolution-devel",Version = "3.28.5-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evolution-devel-docs",Version = "3.28.5-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evolution-help",Version = "3.28.5-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evolution-langpacks",Version = "3.28.5-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evolution-pst",Version = "3.28.5-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evolution-spamassassin",Version = "3.28.5-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evolution-ews",Version = "3.28.5-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evolution-ews-langpacks",Version = "3.28.5-5.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1080)

RHSA_2020_1081_Rule = VulRule:new()

RHSA_2020_1081 = RHSA_2020_1081_Rule:new{
PatchId = "RHSA-2020:1081",
CVEId = "CVE-2018-18066",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp",Version = "5.7.2-47.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-agent-libs",Version = "5.7.2-47.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-devel",Version = "5.7.2-47.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-gui",Version = "5.7.2-47.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-libs",Version = "5.7.2-47.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-perl",Version = "5.7.2-47.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-python",Version = "5.7.2-47.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-sysvinit",Version = "5.7.2-47.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-utils",Version = "5.7.2-47.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1081)

RHSA_2020_1084_Rule = VulRule:new()

RHSA_2020_1084 = RHSA_2020_1084_Rule:new{
PatchId = "RHSA-2020:1084",
CVEId = "CVE-2019-10218",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ctdb",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ctdb-tests",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libsmbclient",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libsmbclient-devel",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libwbclient",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libwbclient-devel",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-client",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-client-libs",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-common",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-common-libs",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-common-tools",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-dc",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-dc-libs",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-devel",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-krb5-printing",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-libs",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-pidl",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-python",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-python-test",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-test",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-test-libs",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-vfs-glusterfs",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winbind",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winbind-clients",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winbind-krb5-locator",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winbind-modules",Version = "4.10.4-10.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1084)

RHSA_2020_1091_Rule = VulRule:new()

RHSA_2020_1091 = RHSA_2020_1091_Rule:new{
PatchId = "RHSA-2020:1091",
CVEId = "CVE-2019-12387",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-twisted-web",Version = "12.1.0-6.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1091)

RHSA_2020_1100_Rule = VulRule:new()

RHSA_2020_1100 = RHSA_2020_1100_Rule:new{
PatchId = "RHSA-2020:1100",
CVEId = "CVE-2021-2007",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mariadb",Version = "5.5.65-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mariadb-bench",Version = "5.5.65-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mariadb-devel",Version = "5.5.65-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mariadb-embedded",Version = "5.5.65-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mariadb-embedded-devel",Version = "5.5.65-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mariadb-libs",Version = "5.5.65-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mariadb-server",Version = "5.5.65-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mariadb-test",Version = "5.5.65-1.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1100)

RHSA_2020_1101_Rule = VulRule:new()

RHSA_2020_1101 = RHSA_2020_1101_Rule:new{
PatchId = "RHSA-2020:1101",
CVEId = "CVE-2018-10910",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez",Version = "5.44-6.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez-cups",Version = "5.44-6.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez-hid2hci",Version = "5.44-6.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez-libs",Version = "5.44-6.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez-libs-devel",Version = "5.44-6.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1101)

RHSA_2020_1112_Rule = VulRule:new()

RHSA_2020_1112 = RHSA_2020_1112_Rule:new{
PatchId = "RHSA-2020:1112",
CVEId = "CVE-2019-9024",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php-bcmath",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php-cli",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php-common",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php-dba",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php-devel",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php-embedded",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php-enchant",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php-fpm",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php-gd",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php-intl",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php-ldap",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php-mbstring",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php-mysql",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php-mysqlnd",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php-odbc",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php-pdo",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php-pgsql",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php-process",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php-pspell",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php-recode",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php-snmp",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php-soap",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php-xml",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "php-xmlrpc",Version = "5.4.16-48.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1112)

RHSA_2020_1113_Rule = VulRule:new()

RHSA_2020_1113 = RHSA_2020_1113_Rule:new{
PatchId = "RHSA-2020:1113",
CVEId = "CVE-2019-9924",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bash",Version = "4.2.46-34.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bash-doc",Version = "4.2.46-34.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1113)

RHSA_2020_1116_Rule = VulRule:new()

RHSA_2020_1116 = RHSA_2020_1116_Rule:new{
PatchId = "RHSA-2020:1116",
CVEId = "CVE-2020-7039",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-img",Version = "1.5.3-173.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm",Version = "1.5.3-173.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-common",Version = "1.5.3-173.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-tools",Version = "1.5.3-173.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1116)

RHSA_2020_1121_Rule = VulRule:new()

RHSA_2020_1121 = RHSA_2020_1121_Rule:new{
PatchId = "RHSA-2020:1121",
CVEId = "CVE-2018-17199",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "httpd",Version = "2.4.6-93.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "httpd-devel",Version = "2.4.6-93.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "httpd-manual",Version = "2.4.6-93.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "httpd-tools",Version = "2.4.6-93.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mod_ldap",Version = "2.4.6-93.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mod_proxy_html",Version = "2.4.6-93.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mod_session",Version = "2.4.6-93.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mod_ssl",Version = "2.4.6-93.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1121)

RHSA_2020_1126_Rule = VulRule:new()

RHSA_2020_1126 = RHSA_2020_1126_Rule:new{
PatchId = "RHSA-2020:1126",
CVEId = "CVE-2018-14355",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mutt",Version = "1.5.21-29.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1126)

RHSA_2020_1131_Rule = VulRule:new()

RHSA_2020_1131 = RHSA_2020_1131_Rule:new{
PatchId = "RHSA-2020:1131",
CVEId = "CVE-2019-16056",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python",Version = "2.7.5-88.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-debug",Version = "2.7.5-88.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-devel",Version = "2.7.5-88.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-libs",Version = "2.7.5-88.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-test",Version = "2.7.5-88.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-tools",Version = "2.7.5-88.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tkinter",Version = "2.7.5-88.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1131)

RHSA_2020_1132_Rule = VulRule:new()

RHSA_2020_1132 = RHSA_2020_1132_Rule:new{
PatchId = "RHSA-2020:1132",
CVEId = "CVE-2018-20852",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python3",Version = "3.6.8-13.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-debug",Version = "3.6.8-13.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-devel",Version = "3.6.8-13.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-idle",Version = "3.6.8-13.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-libs",Version = "3.6.8-13.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-test",Version = "3.6.8-13.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-tkinter",Version = "3.6.8-13.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1132)

RHSA_2020_1135_Rule = VulRule:new()

RHSA_2020_1135 = RHSA_2020_1135_Rule:new{
PatchId = "RHSA-2020:1135",
CVEId = "CVE-2018-1116",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "polkit",Version = "0.112-26.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "polkit-devel",Version = "0.112-26.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "polkit-docs",Version = "0.112-26.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1135)

RHSA_2020_1138_Rule = VulRule:new()

RHSA_2020_1138 = RHSA_2020_1138_Rule:new{
PatchId = "RHSA-2020:1138",
CVEId = "CVE-2018-18751",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "emacs-gettext",Version = "0.19.8.1-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gettext",Version = "0.19.8.1-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gettext-common-devel",Version = "0.19.8.1-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gettext-devel",Version = "0.19.8.1-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gettext-libs",Version = "0.19.8.1-3.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1138)

RHSA_2020_1150_Rule = VulRule:new()

RHSA_2020_1150 = RHSA_2020_1150_Rule:new{
PatchId = "RHSA-2020:1150",
CVEId = "CVE-2020-1711",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-img-ma",Version = "2.12.0-44.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-common-ma",Version = "2.12.0-44.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-ma",Version = "2.12.0-44.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-tools-ma",Version = "2.12.0-44.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1150)

RHSA_2020_1151_Rule = VulRule:new()

RHSA_2020_1151 = RHSA_2020_1151_Rule:new{
PatchId = "RHSA-2020:1151",
CVEId = "CVE-2019-9854",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-af",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-bg",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-ca",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-cs",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-da",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-de",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-en",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-es",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-fa",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-fi",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-fr",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-ga",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-hr",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-hu",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-is",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-it",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-ja",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-ko",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-lb",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-lt",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-mn",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-nl",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-pl",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-pt",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-ro",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-ru",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-sk",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-sl",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-sr",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-sv",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-tr",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-vi",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autocorr-zh",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-base",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-bsh",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-calc",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-core",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-data",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-draw",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-emailmerge",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-filters",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-gdb-debug-support",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-glade",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-graphicfilter",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-gtk2",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-gtk3",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-ar",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-bg",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-bn",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-ca",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-cs",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-da",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-de",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-dz",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-el",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-es",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-et",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-eu",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-fi",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-fr",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-gl",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-gu",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-he",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-hi",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-hr",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-hu",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-id",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-it",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-ja",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-ko",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-lt",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-lv",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-nb",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-nl",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-nn",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-pl",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-pt-BR",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-pt-PT",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-ro",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-ru",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-si",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-sk",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-sl",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-sv",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-ta",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-tr",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-uk",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-zh-Hans",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-help-zh-Hant",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-impress",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-langpack-en",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-librelogo",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-math",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-nlpsolver",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-officebean",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-officebean-common",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-ogltrans",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-opensymbol-fonts",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-pdfimport",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-postgresql",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-pyuno",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-rhino",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-sdk",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-sdk-doc",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-ure",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-ure-common",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-wiki-publisher",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-writer",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-x11",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreoffice-xsltfilter",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreofficekit",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libreofficekit-devel",Version = "5.3.6.1-24.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1151)

RHSA_2020_1167_Rule = VulRule:new()

RHSA_2020_1167 = RHSA_2020_1167_Rule:new{
PatchId = "RHSA-2020:1167",
CVEId = "CVE-2019-14850",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nbdkit",Version = "1.8.0-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nbdkit-basic-plugins",Version = "1.8.0-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nbdkit-devel",Version = "1.8.0-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nbdkit-example-plugins",Version = "1.8.0-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nbdkit-plugin-python-common",Version = "1.8.0-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nbdkit-plugin-python2",Version = "1.8.0-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nbdkit-plugin-vddk",Version = "1.8.0-3.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1167)

RHSA_2020_1172_Rule = VulRule:new()

RHSA_2020_1172 = RHSA_2020_1172_Rule:new{
PatchId = "RHSA-2020:1172",
CVEId = "CVE-2018-19873",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt",Version = "4.8.7-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-assistant",Version = "4.8.7-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-config",Version = "4.8.7-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-demos",Version = "4.8.7-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-devel",Version = "4.8.7-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-devel-private",Version = "4.8.7-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-doc",Version = "4.8.7-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-examples",Version = "4.8.7-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-mysql",Version = "4.8.7-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-odbc",Version = "4.8.7-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-postgresql",Version = "4.8.7-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-qdbusviewer",Version = "4.8.7-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-qvfb",Version = "4.8.7-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-x11",Version = "4.8.7-8.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1172)

RHSA_2020_1173_Rule = VulRule:new()

RHSA_2020_1173 = RHSA_2020_1173_Rule:new{
PatchId = "RHSA-2020:1173",
CVEId = "CVE-2018-1000801",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "okular",Version = "4.10.5-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "okular-devel",Version = "4.10.5-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "okular-libs",Version = "4.10.5-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "okular-part",Version = "4.10.5-8.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1173)

RHSA_2020_1175_Rule = VulRule:new()

RHSA_2020_1175 = RHSA_2020_1175_Rule:new{
PatchId = "RHSA-2020:1175",
CVEId = "CVE-2018-11439",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "taglib",Version = "1.8-8.20130218git.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "taglib-devel",Version = "1.8-8.20130218git.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "taglib-doc",Version = "1.8-8.20130218git.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1175)

RHSA_2020_1176_Rule = VulRule:new()

RHSA_2020_1176 = RHSA_2020_1176_Rule:new{
PatchId = "RHSA-2020:1176",
CVEId = "CVE-2017-6519",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "avahi",Version = "0.6.31-20.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "avahi-autoipd",Version = "0.6.31-20.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "avahi-compat-howl",Version = "0.6.31-20.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "avahi-compat-howl-devel",Version = "0.6.31-20.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "avahi-compat-libdns_sd",Version = "0.6.31-20.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "avahi-compat-libdns_sd-devel",Version = "0.6.31-20.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "avahi-devel",Version = "0.6.31-20.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "avahi-dnsconfd",Version = "0.6.31-20.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "avahi-glib",Version = "0.6.31-20.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "avahi-glib-devel",Version = "0.6.31-20.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "avahi-gobject",Version = "0.6.31-20.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "avahi-gobject-devel",Version = "0.6.31-20.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "avahi-libs",Version = "0.6.31-20.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "avahi-qt3",Version = "0.6.31-20.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "avahi-qt3-devel",Version = "0.6.31-20.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "avahi-qt4",Version = "0.6.31-20.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "avahi-qt4-devel",Version = "0.6.31-20.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "avahi-tools",Version = "0.6.31-20.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "avahi-ui",Version = "0.6.31-20.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "avahi-ui-devel",Version = "0.6.31-20.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "avahi-ui-gtk3",Version = "0.6.31-20.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "avahi-ui-tools",Version = "0.6.31-20.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1176)

RHSA_2020_1178_Rule = VulRule:new()

RHSA_2020_1178 = RHSA_2020_1178_Rule:new{
PatchId = "RHSA-2020:1178",
CVEId = "CVE-2018-17828",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "zziplib",Version = "0.13.62-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "zziplib-devel",Version = "0.13.62-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "zziplib-utils",Version = "0.13.62-12.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1178)

RHSA_2020_1180_Rule = VulRule:new()

RHSA_2020_1180 = RHSA_2020_1180_Rule:new{
PatchId = "RHSA-2020:1180",
CVEId = "CVE-2019-9956",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "inkscape",Version = "0.92.2-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "inkscape-docs",Version = "0.92.2-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "inkscape-view",Version = "0.92.2-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autotrace",Version = "0.31.1-38.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "autotrace-devel",Version = "0.31.1-38.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "emacs",Version = "24.3-23.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "emacs-common",Version = "24.3-23.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "emacs-el",Version = "24.3-23.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "emacs-filesystem",Version = "24.3-23.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "emacs-nox",Version = "24.3-23.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "emacs-terminal",Version = "24.3-23.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ImageMagick",Version = "6.9.10.68-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ImageMagick-c++",Version = "6.9.10.68-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ImageMagick-c++-devel",Version = "6.9.10.68-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ImageMagick-devel",Version = "6.9.10.68-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ImageMagick-doc",Version = "6.9.10.68-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ImageMagick-perl",Version = "6.9.10.68-3.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1180)

RHSA_2020_1181_Rule = VulRule:new()

RHSA_2020_1181 = RHSA_2020_1181_Rule:new{
PatchId = "RHSA-2020:1181",
CVEId = "CVE-2019-13232",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "unzip",Version = "6.0-21.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1181)

RHSA_2020_1185_Rule = VulRule:new()

RHSA_2020_1185 = RHSA_2020_1185_Rule:new{
PatchId = "RHSA-2020:1185",
CVEId = "CVE-2018-13139",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libsndfile",Version = "1.0.25-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libsndfile-devel",Version = "1.0.25-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libsndfile-utils",Version = "1.0.25-11.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1185)

RHSA_2020_1189_Rule = VulRule:new()

RHSA_2020_1189 = RHSA_2020_1189_Rule:new{
PatchId = "RHSA-2020:1189",
CVEId = "CVE-2019-12779",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libqb",Version = "1.0.1-9.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libqb-devel",Version = "1.0.1-9.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1189)

RHSA_2020_1190_Rule = VulRule:new()

RHSA_2020_1190 = RHSA_2020_1190_Rule:new{
PatchId = "RHSA-2020:1190",
CVEId = "CVE-2018-14567",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libxml2",Version = "2.9.1-6.el7.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libxml2-devel",Version = "2.9.1-6.el7.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libxml2-python",Version = "2.9.1-6.el7.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libxml2-static",Version = "2.9.1-6.el7.4",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1190)

RHSA_2020_1208_Rule = VulRule:new()

RHSA_2020_1208 = RHSA_2020_1208_Rule:new{
PatchId = "RHSA-2020:1208",
CVEId = "CVE-2020-8608",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-img",Version = "1.5.3-173.el7_8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm",Version = "1.5.3-173.el7_8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-common",Version = "1.5.3-173.el7_8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-tools",Version = "1.5.3-173.el7_8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-img-ma",Version = "2.12.0-44.el7_8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-common-ma",Version = "2.12.0-44.el7_8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-ma",Version = "2.12.0-44.el7_8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-tools-ma",Version = "2.12.0-44.el7_8.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1208)

RHSA_2020_1334_Rule = VulRule:new()

RHSA_2020_1334 = RHSA_2020_1334_Rule:new{
PatchId = "RHSA-2020:1334",
CVEId = "CVE-2020-10188",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "telnet-server",Version = "0.17-65.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1334)

RHSA_2020_1338_Rule = VulRule:new()

RHSA_2020_1338 = RHSA_2020_1338_Rule:new{
PatchId = "RHSA-2020:1338",
CVEId = "CVE-2020-6820",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "68.6.1-1.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1338)

RHSA_2020_1420_Rule = VulRule:new()

RHSA_2020_1420 = RHSA_2020_1420_Rule:new{
PatchId = "RHSA-2020:1420",
CVEId = "CVE-2020-6825",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "68.7.0-2.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1420)

RHSA_2020_1489_Rule = VulRule:new()

RHSA_2020_1489 = RHSA_2020_1489_Rule:new{
PatchId = "RHSA-2020:1489",
CVEId = "CVE-2020-6822",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "68.7.0-1.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1489)

RHSA_2020_1507_Rule = VulRule:new()

RHSA_2020_1507 = RHSA_2020_1507_Rule:new{
PatchId = "RHSA-2020:1507",
CVEId = "CVE-2020-2830",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.0-openjdk",Version = "1.7.0.261-2.6.22.2.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.0-openjdk-accessibility",Version = "1.7.0.261-2.6.22.2.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.0-openjdk-demo",Version = "1.7.0.261-2.6.22.2.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.0-openjdk-devel",Version = "1.7.0.261-2.6.22.2.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.0-openjdk-headless",Version = "1.7.0.261-2.6.22.2.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.0-openjdk-javadoc",Version = "1.7.0.261-2.6.22.2.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.0-openjdk-src",Version = "1.7.0.261-2.6.22.2.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1507)

RHSA_2020_1509_Rule = VulRule:new()

RHSA_2020_1509 = RHSA_2020_1509_Rule:new{
PatchId = "RHSA-2020:1509",
CVEId = "CVE-2020-2816",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk",Version = "11.0.7.10-4.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-demo",Version = "11.0.7.10-4.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-devel",Version = "11.0.7.10-4.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-headless",Version = "11.0.7.10-4.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-javadoc",Version = "11.0.7.10-4.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-javadoc-zip",Version = "11.0.7.10-4.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-jmods",Version = "11.0.7.10-4.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-src",Version = "11.0.7.10-4.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1509)

RHSA_2020_1511_Rule = VulRule:new()

RHSA_2020_1511 = RHSA_2020_1511_Rule:new{
PatchId = "RHSA-2020:1511",
CVEId = "CVE-2020-5260",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "emacs-git",Version = "1.8.3.1-22.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "emacs-git-el",Version = "1.8.3.1-22.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git",Version = "1.8.3.1-22.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-all",Version = "1.8.3.1-22.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-bzr",Version = "1.8.3.1-22.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-cvs",Version = "1.8.3.1-22.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-daemon",Version = "1.8.3.1-22.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-email",Version = "1.8.3.1-22.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-gnome-keyring",Version = "1.8.3.1-22.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-gui",Version = "1.8.3.1-22.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-hg",Version = "1.8.3.1-22.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-instaweb",Version = "1.8.3.1-22.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-p4",Version = "1.8.3.1-22.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-svn",Version = "1.8.3.1-22.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gitk",Version = "1.8.3.1-22.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gitweb",Version = "1.8.3.1-22.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Git",Version = "1.8.3.1-22.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Git-SVN",Version = "1.8.3.1-22.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1511)

RHSA_2020_1512_Rule = VulRule:new()

RHSA_2020_1512 = RHSA_2020_1512_Rule:new{
PatchId = "RHSA-2020:1512",
CVEId = "CVE-2020-2805",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk",Version = "1.8.0.252.b09-2.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-accessibility",Version = "1.8.0.252.b09-2.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-demo",Version = "1.8.0.252.b09-2.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-devel",Version = "1.8.0.252.b09-2.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-headless",Version = "1.8.0.252.b09-2.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-javadoc",Version = "1.8.0.252.b09-2.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-javadoc-zip",Version = "1.8.0.252.b09-2.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-src",Version = "1.8.0.252.b09-2.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1512)

RHSA_2020_1561_Rule = VulRule:new()

RHSA_2020_1561 = RHSA_2020_1561_Rule:new{
PatchId = "RHSA-2020:1561",
CVEId = "CVE-2020-10109",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-twisted-web",Version = "12.1.0-7.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1561)

RHSA_2020_2037_Rule = VulRule:new()

RHSA_2020_2037 = RHSA_2020_2037_Rule:new{
PatchId = "RHSA-2020:2037",
CVEId = "CVE-2020-6831",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "68.8.0-1.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2037)

RHSA_2020_2040_Rule = VulRule:new()

RHSA_2020_2040 = RHSA_2020_2040_Rule:new{
PatchId = "RHSA-2020:2040",
CVEId = "CVE-2020-11945",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "squid",Version = "3.5.20-15.el7_8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "squid-migration-script",Version = "3.5.20-15.el7_8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "squid-sysvinit",Version = "3.5.20-15.el7_8.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2040)

RHSA_2020_2050_Rule = VulRule:new()

RHSA_2020_2050 = RHSA_2020_2050_Rule:new{
PatchId = "RHSA-2020:2050",
CVEId = "CVE-2020-12397",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "68.8.0-1.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2050)

RHSA_2020_2068_Rule = VulRule:new()

RHSA_2020_2068 = RHSA_2020_2068_Rule:new{
PatchId = "RHSA-2020:2068",
CVEId = "CVE-2018-20060",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-pip",Version = "9.0.3-7.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2068)

RHSA_2020_2081_Rule = VulRule:new()

RHSA_2020_2081 = RHSA_2020_2081_Rule:new{
PatchId = "RHSA-2020:2081",
CVEId = "CVE-2018-18074",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-virtualenv",Version = "15.1.0-4.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2081)

RHSA_2020_2082_Rule = VulRule:new()

RHSA_2020_2082 = RHSA_2020_2082_Rule:new{
PatchId = "RHSA-2020:2082",
CVEId = "CVE-2020-10711",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-bootwrapper",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump-devel",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python-perf",Version = "3.10.0-1127.8.2.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2082)

RHSA_2020_2237_Rule = VulRule:new()

RHSA_2020_2237 = RHSA_2020_2237_Rule:new{
PatchId = "RHSA-2020:2237",
CVEId = "CVE-2020-2803",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-ibm",Version = "1.8.0.6.10-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-ibm-demo",Version = "1.8.0.6.10-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-ibm-devel",Version = "1.8.0.6.10-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-ibm-jdbc",Version = "1.8.0.6.10-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-ibm-plugin",Version = "1.8.0.6.10-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-ibm-src",Version = "1.8.0.6.10-1jpp.1.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2237)

RHSA_2020_2238_Rule = VulRule:new()

RHSA_2020_2238 = RHSA_2020_2238_Rule:new{
PatchId = "RHSA-2020:2238",
CVEId = "CVE-2020-2800",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm",Version = "1.7.1.4.65-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-demo",Version = "1.7.1.4.65-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-devel",Version = "1.7.1.4.65-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-jdbc",Version = "1.7.1.4.65-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-plugin",Version = "1.7.1.4.65-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-src",Version = "1.7.1.4.65-1jpp.1.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2238)

RHSA_2020_2334_Rule = VulRule:new()

RHSA_2020_2334 = RHSA_2020_2334_Rule:new{
PatchId = "RHSA-2020:2334",
CVEId = "CVE-2020-11524",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "freerdp",Version = "2.0.0-4.rc4.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "freerdp-devel",Version = "2.0.0-4.rc4.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "freerdp-libs",Version = "2.0.0-4.rc4.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libwinpr",Version = "2.0.0-4.rc4.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libwinpr-devel",Version = "2.0.0-4.rc4.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2334)

RHSA_2020_2337_Rule = VulRule:new()

RHSA_2020_2337 = RHSA_2020_2337_Rule:new{
PatchId = "RHSA-2020:2337",
CVEId = "CVE-2020-11008",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "emacs-git",Version = "1.8.3.1-23.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "emacs-git-el",Version = "1.8.3.1-23.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git",Version = "1.8.3.1-23.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-all",Version = "1.8.3.1-23.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-bzr",Version = "1.8.3.1-23.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-cvs",Version = "1.8.3.1-23.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-daemon",Version = "1.8.3.1-23.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-email",Version = "1.8.3.1-23.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-gnome-keyring",Version = "1.8.3.1-23.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-gui",Version = "1.8.3.1-23.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-hg",Version = "1.8.3.1-23.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-instaweb",Version = "1.8.3.1-23.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-p4",Version = "1.8.3.1-23.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "git-svn",Version = "1.8.3.1-23.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gitk",Version = "1.8.3.1-23.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gitweb",Version = "1.8.3.1-23.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Git",Version = "1.8.3.1-23.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Git-SVN",Version = "1.8.3.1-23.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2337)

RHSA_2020_2344_Rule = VulRule:new()

RHSA_2020_2344 = RHSA_2020_2344_Rule:new{
PatchId = "RHSA-2020:2344",
CVEId = "CVE-2020-8617",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind",Version = "9.11.4-16.P2.el7_8.6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-chroot",Version = "9.11.4-16.P2.el7_8.6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-devel",Version = "9.11.4-16.P2.el7_8.6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-export-devel",Version = "9.11.4-16.P2.el7_8.6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-export-libs",Version = "9.11.4-16.P2.el7_8.6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-libs",Version = "9.11.4-16.P2.el7_8.6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-libs-lite",Version = "9.11.4-16.P2.el7_8.6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-license",Version = "9.11.4-16.P2.el7_8.6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-lite-devel",Version = "9.11.4-16.P2.el7_8.6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11",Version = "9.11.4-16.P2.el7_8.6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-devel",Version = "9.11.4-16.P2.el7_8.6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-libs",Version = "9.11.4-16.P2.el7_8.6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-utils",Version = "9.11.4-16.P2.el7_8.6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-sdb",Version = "9.11.4-16.P2.el7_8.6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-sdb-chroot",Version = "9.11.4-16.P2.el7_8.6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-utils",Version = "9.11.4-16.P2.el7_8.6",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2344)

RHSA_2020_2381_Rule = VulRule:new()

RHSA_2020_2381 = RHSA_2020_2381_Rule:new{
PatchId = "RHSA-2020:2381",
CVEId = "CVE-2020-12410",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "68.9.0-1.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2381)

RHSA_2020_2405_Rule = VulRule:new()

RHSA_2020_2405 = RHSA_2020_2405_Rule:new{
PatchId = "RHSA-2020:2405",
CVEId = "CVE-2020-13398",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "freerdp",Version = "2.0.0-4.rc4.el7_8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "freerdp-devel",Version = "2.0.0-4.rc4.el7_8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "freerdp-libs",Version = "2.0.0-4.rc4.el7_8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libwinpr",Version = "2.0.0-4.rc4.el7_8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libwinpr-devel",Version = "2.0.0-4.rc4.el7_8.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2405)

RHSA_2020_2414_Rule = VulRule:new()

RHSA_2020_2414 = RHSA_2020_2414_Rule:new{
PatchId = "RHSA-2020:2414",
CVEId = "CVE-2020-12663",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "unbound",Version = "1.6.6-4.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "unbound-devel",Version = "1.6.6-4.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "unbound-libs",Version = "1.6.6-4.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "unbound-python",Version = "1.6.6-4.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2414)

RHSA_2020_2432_Rule = VulRule:new()

RHSA_2020_2432 = RHSA_2020_2432_Rule:new{
PatchId = "RHSA-2020:2432",
CVEId = "CVE-2020-0549",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "microcode_ctl",Version = "2.1-61.6.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2432)

RHSA_2020_2530_Rule = VulRule:new()

RHSA_2020_2530 = RHSA_2020_2530_Rule:new{
PatchId = "RHSA-2020:2530",
CVEId = "CVE-2020-9484",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat",Version = "7.0.76-12.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-admin-webapps",Version = "7.0.76-12.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-docs-webapp",Version = "7.0.76-12.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-el-2.2-api",Version = "7.0.76-12.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-javadoc",Version = "7.0.76-12.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-jsp-2.2-api",Version = "7.0.76-12.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-jsvc",Version = "7.0.76-12.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-lib",Version = "7.0.76-12.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-servlet-3.0-api",Version = "7.0.76-12.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-webapps",Version = "7.0.76-12.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2530)

RHSA_2020_2549_Rule = VulRule:new()

RHSA_2020_2549 = RHSA_2020_2549_Rule:new{
PatchId = "RHSA-2020:2549",
CVEId = "CVE-2020-13112",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libexif",Version = "0.6.21-7.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libexif-devel",Version = "0.6.21-7.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libexif-doc",Version = "0.6.21-7.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2549)

RHSA_2020_2615_Rule = VulRule:new()

RHSA_2020_2615 = RHSA_2020_2615_Rule:new{
PatchId = "RHSA-2020:2615",
CVEId = "CVE-2020-12406",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "68.9.0-1.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2615)

RHSA_2020_2642_Rule = VulRule:new()

RHSA_2020_2642 = RHSA_2020_2642_Rule:new{
PatchId = "RHSA-2020:2642",
CVEId = "CVE-2020-10772",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "unbound",Version = "1.6.6-5.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "unbound-devel",Version = "1.6.6-5.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "unbound-libs",Version = "1.6.6-5.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "unbound-python",Version = "1.6.6-5.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2642)

RHSA_2020_2663_Rule = VulRule:new()

RHSA_2020_2663 = RHSA_2020_2663_Rule:new{
PatchId = "RHSA-2020:2663",
CVEId = "CVE-2020-13817",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ntp",Version = "4.2.6p5-29.el7_8.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ntp-doc",Version = "4.2.6p5-29.el7_8.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ntp-perl",Version = "4.2.6p5-29.el7_8.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ntpdate",Version = "4.2.6p5-29.el7_8.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "sntp",Version = "4.2.6p5-29.el7_8.2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2663)

RHSA_2020_2664_Rule = VulRule:new()

RHSA_2020_2664 = RHSA_2020_2664_Rule:new{
PatchId = "RHSA-2020:2664",
CVEId = "CVE-2020-12888",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-bootwrapper",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump-devel",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python-perf",Version = "3.10.0-1127.13.1.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2664)

RHSA_2020_2827_Rule = VulRule:new()

RHSA_2020_2827 = RHSA_2020_2827_Rule:new{
PatchId = "RHSA-2020:2827",
CVEId = "CVE-2020-12421",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "68.10.0-1.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2827)

RHSA_2020_2894_Rule = VulRule:new()

RHSA_2020_2894 = RHSA_2020_2894_Rule:new{
PatchId = "RHSA-2020:2894",
CVEId = "CVE-2020-12049",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dbus",Version = "1.10.24-14.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dbus-devel",Version = "1.10.24-14.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dbus-doc",Version = "1.10.24-14.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dbus-libs",Version = "1.10.24-14.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dbus-tests",Version = "1.10.24-14.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dbus-x11",Version = "1.10.24-14.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2894)

RHSA_2020_2906_Rule = VulRule:new()

RHSA_2020_2906 = RHSA_2020_2906_Rule:new{
PatchId = "RHSA-2020:2906",
CVEId = "CVE-2020-15646",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "68.10.0-1.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2906)

RHSA_2020_2968_Rule = VulRule:new()

RHSA_2020_2968 = RHSA_2020_2968_Rule:new{
PatchId = "RHSA-2020:2968",
CVEId = "CVE-2020-14621",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk",Version = "1.8.0.262.b10-0.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-accessibility",Version = "1.8.0.262.b10-0.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-demo",Version = "1.8.0.262.b10-0.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-devel",Version = "1.8.0.262.b10-0.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-headless",Version = "1.8.0.262.b10-0.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-javadoc",Version = "1.8.0.262.b10-0.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-javadoc-zip",Version = "1.8.0.262.b10-0.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-src",Version = "1.8.0.262.b10-0.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2968)

RHSA_2020_2969_Rule = VulRule:new()

RHSA_2020_2969 = RHSA_2020_2969_Rule:new{
PatchId = "RHSA-2020:2969",
CVEId = "CVE-2020-14593",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk",Version = "11.0.8.10-0.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-demo",Version = "11.0.8.10-0.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-devel",Version = "11.0.8.10-0.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-headless",Version = "11.0.8.10-0.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-javadoc",Version = "11.0.8.10-0.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-javadoc-zip",Version = "11.0.8.10-0.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-jmods",Version = "11.0.8.10-0.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-src",Version = "11.0.8.10-0.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2969)

RHSA_2020_3217_Rule = VulRule:new()

RHSA_2020_3217 = RHSA_2020_3217_Rule:new{
PatchId = "RHSA-2020:3217",
CVEId = "CVE-2020-15707",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "shim-unsigned-ia32",Version = "15-7.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "shim-unsigned-x64",Version = "15-7.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fwupdate",Version = "12-6.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fwupdate-devel",Version = "12-6.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fwupdate-efi",Version = "12-6.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fwupdate-libs",Version = "12-6.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2",Version = "2.02-0.86.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-common",Version = "2.02-0.86.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-aa64-modules",Version = "2.02-0.86.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-ia32",Version = "2.02-0.86.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-ia32-cdboot",Version = "2.02-0.86.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-ia32-modules",Version = "2.02-0.86.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-x64",Version = "2.02-0.86.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-x64-cdboot",Version = "2.02-0.86.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-x64-modules",Version = "2.02-0.86.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-pc",Version = "2.02-0.86.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-pc-modules",Version = "2.02-0.86.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-ppc-modules",Version = "2.02-0.86.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-ppc64",Version = "2.02-0.86.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-ppc64-modules",Version = "2.02-0.86.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-ppc64le",Version = "2.02-0.86.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-ppc64le-modules",Version = "2.02-0.86.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-tools",Version = "2.02-0.86.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-tools-extra",Version = "2.02-0.86.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-tools-minimal",Version = "2.02-0.86.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mokutil",Version = "15-7.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "shim-ia32",Version = "15-7.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "shim-x64",Version = "15-7.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3217)

RHSA_2020_3220_Rule = VulRule:new()

RHSA_2020_3220 = RHSA_2020_3220_Rule:new{
PatchId = "RHSA-2020:3220",
CVEId = "CVE-2020-12654",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-bootwrapper",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump-devel",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python-perf",Version = "3.10.0-1127.18.2.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3220)

RHSA_2020_3253_Rule = VulRule:new()

RHSA_2020_3253 = RHSA_2020_3253_Rule:new{
PatchId = "RHSA-2020:3253",
CVEId = "CVE-2020-6514",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "68.11.0-1.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3253)

RHSA_2020_3281_Rule = VulRule:new()

RHSA_2020_3281 = RHSA_2020_3281_Rule:new{
PatchId = "RHSA-2020:3281",
CVEId = "CVE-2017-18922",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvncserver",Version = "0.9.9-14.el7_8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvncserver-devel",Version = "0.9.9-14.el7_8.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3281)

RHSA_2020_3285_Rule = VulRule:new()

RHSA_2020_3285 = RHSA_2020_3285_Rule:new{
PatchId = "RHSA-2020:3285",
CVEId = "CVE-2020-13692",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-jdbc",Version = "9.2.1002-8.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-jdbc-javadoc",Version = "9.2.1002-8.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3285)

RHSA_2020_3344_Rule = VulRule:new()

RHSA_2020_3344 = RHSA_2020_3344_Rule:new{
PatchId = "RHSA-2020:3344",
CVEId = "CVE-2020-6463",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "68.11.0-1.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3344)

RHSA_2020_3388_Rule = VulRule:new()

RHSA_2020_3388 = RHSA_2020_3388_Rule:new{
PatchId = "RHSA-2020:3388",
CVEId = "CVE-2020-2601",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm",Version = "1.7.1.4.70-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-demo",Version = "1.7.1.4.70-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-devel",Version = "1.7.1.4.70-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-jdbc",Version = "1.7.1.4.70-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-plugin",Version = "1.7.1.4.70-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-src",Version = "1.7.1.4.70-1jpp.1.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3388)

RHSA_2020_3556_Rule = VulRule:new()

RHSA_2020_3556 = RHSA_2020_3556_Rule:new{
PatchId = "RHSA-2020:3556",
CVEId = "CVE-2020-15669",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "68.12.0-1.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3556)

RHSA_2020_3617_Rule = VulRule:new()

RHSA_2020_3617 = RHSA_2020_3617_Rule:new{
PatchId = "RHSA-2020:3617",
CVEId = "CVE-2020-12674",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dovecot",Version = "2.2.36-6.el7_8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dovecot-devel",Version = "2.2.36-6.el7_8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dovecot-mysql",Version = "2.2.36-6.el7_8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dovecot-pgsql",Version = "2.2.36-6.el7_8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dovecot-pigeonhole",Version = "2.2.36-6.el7_8.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3617)

RHSA_2020_3631_Rule = VulRule:new()

RHSA_2020_3631 = RHSA_2020_3631_Rule:new{
PatchId = "RHSA-2020:3631",
CVEId = "CVE-2020-15664",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "68.12.0-1.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3631)

RHSA_2020_3848_Rule = VulRule:new()

RHSA_2020_3848 = RHSA_2020_3848_Rule:new{
PatchId = "RHSA-2020:3848",
CVEId = "CVE-2019-1010305",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libmspack",Version = "0.5-0.8.alpha.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libmspack-devel",Version = "0.5-0.8.alpha.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3848)

RHSA_2020_3861_Rule = VulRule:new()

RHSA_2020_3861 = RHSA_2020_3861_Rule:new{
PatchId = "RHSA-2020:3861",
CVEId = "CVE-2019-19126",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc",Version = "2.17-317.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-common",Version = "2.17-317.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-devel",Version = "2.17-317.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-headers",Version = "2.17-317.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-static",Version = "2.17-317.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-utils",Version = "2.17-317.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nscd",Version = "2.17-317.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3861)

RHSA_2020_3864_Rule = VulRule:new()

RHSA_2020_3864 = RHSA_2020_3864_Rule:new{
PatchId = "RHSA-2020:3864",
CVEId = "CVE-2019-8696",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "cups",Version = "1.6.3-51.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "cups-client",Version = "1.6.3-51.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "cups-devel",Version = "1.6.3-51.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "cups-filesystem",Version = "1.6.3-51.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "cups-ipptool",Version = "1.6.3-51.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "cups-libs",Version = "1.6.3-51.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "cups-lpd",Version = "1.6.3-51.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3864)

RHSA_2020_3868_Rule = VulRule:new()

RHSA_2020_3868 = RHSA_2020_3868_Rule:new{
PatchId = "RHSA-2020:3868",
CVEId = "CVE-2019-7638",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "SDL",Version = "1.2.15-17.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "SDL-devel",Version = "1.2.15-17.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "SDL-static",Version = "1.2.15-17.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3868)

RHSA_2020_3869_Rule = VulRule:new()

RHSA_2020_3869 = RHSA_2020_3869_Rule:new{
PatchId = "RHSA-2020:3869",
CVEId = "CVE-2019-3696",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-conf",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-devel",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-doc",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-export-pcp2elasticsearch",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-export-pcp2graphite",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-export-pcp2influxdb",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-export-pcp2json",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-export-pcp2spark",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-export-pcp2xml",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-export-pcp2zabbix",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-export-zabbix-agent",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-gui",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-import-collectl2pcp",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-import-ganglia2pcp",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-import-iostat2pcp",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-import-mrtg2pcp",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-import-sar2pcp",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-libs",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-libs-devel",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-manager",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-activemq",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-apache",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-bash",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-bcc",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-bind2",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-bonding",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-cifs",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-cisco",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-dbping",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-dm",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-docker",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-ds389",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-ds389log",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-elasticsearch",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-gfs2",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-gluster",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-gpfs",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-gpsd",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-haproxy",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-infiniband",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-json",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-libvirt",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-lio",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-lmsensors",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-logger",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-lustre",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-lustrecomm",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-mailq",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-memcache",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-mic",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-mounts",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-mysql",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-named",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-netfilter",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-news",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-nfsclient",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-nginx",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-nvidia-gpu",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-oracle",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-pdns",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-perfevent",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-postfix",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-postgresql",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-prometheus",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-redis",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-roomtemp",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-rpm",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-rsyslog",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-samba",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-sendmail",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-shping",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-slurm",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-smart",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-snmp",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-summary",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-systemd",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-trace",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-unbound",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-vmware",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-weblog",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-zimbra",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-pmda-zswap",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-selinux",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-system-tools",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-testsuite",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-webapi",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-webapp-blinkenlights",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-webapp-grafana",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-webapp-graphite",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-webapp-vector",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-webjs",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pcp-zeroconf",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-PCP-LogImport",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-PCP-LogSummary",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-PCP-MMV",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-PCP-PMDA",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-pcp",Version = "4.3.2-12.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3869)

RHSA_2020_3873_Rule = VulRule:new()

RHSA_2020_3873 = RHSA_2020_3873_Rule:new{
PatchId = "RHSA-2020:3873",
CVEId = "CVE-2015-6360",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libsrtp",Version = "1.4.4-11.20101004cvs.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libsrtp-devel",Version = "1.4.4-11.20101004cvs.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3873)

RHSA_2020_3875_Rule = VulRule:new()

RHSA_2020_3875 = RHSA_2020_3875_Rule:new{
PatchId = "RHSA-2020:3875",
CVEId = "CVE-2019-15695",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tigervnc",Version = "1.8.0-21.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tigervnc-icons",Version = "1.8.0-21.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tigervnc-license",Version = "1.8.0-21.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tigervnc-server",Version = "1.8.0-21.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tigervnc-server-applet",Version = "1.8.0-21.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tigervnc-server-minimal",Version = "1.8.0-21.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tigervnc-server-module",Version = "1.8.0-21.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3875)

RHSA_2020_3876_Rule = VulRule:new()

RHSA_2020_3876 = RHSA_2020_3876_Rule:new{
PatchId = "RHSA-2020:3876",
CVEId = "CVE-2020-0034",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvpx",Version = "1.3.0-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvpx-devel",Version = "1.3.0-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvpx-utils",Version = "1.3.0-8.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3876)

RHSA_2020_3877_Rule = VulRule:new()

RHSA_2020_3877 = RHSA_2020_3877_Rule:new{
PatchId = "RHSA-2020:3877",
CVEId = "CVE-2018-17095",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "audiofile",Version = "0.3.6-9.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "audiofile-devel",Version = "0.3.6-9.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3877)

RHSA_2020_3878_Rule = VulRule:new()

RHSA_2020_3878 = RHSA_2020_3878_Rule:new{
PatchId = "RHSA-2020:3878",
CVEId = "CVE-2019-14834",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dnsmasq",Version = "2.76-16.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dnsmasq-utils",Version = "2.76-16.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3878)

RHSA_2020_3887_Rule = VulRule:new()

RHSA_2020_3887 = RHSA_2020_3887_Rule:new{
PatchId = "RHSA-2020:3887",
CVEId = "CVE-2020-5313",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-pillow",Version = "2.0.0-21.gitd1c6db8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-pillow-devel",Version = "2.0.0-21.gitd1c6db8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-pillow-doc",Version = "2.0.0-21.gitd1c6db8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-pillow-qt",Version = "2.0.0-21.gitd1c6db8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-pillow-sane",Version = "2.0.0-21.gitd1c6db8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-pillow-tk",Version = "2.0.0-21.gitd1c6db8.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3887)

RHSA_2020_3888_Rule = VulRule:new()

RHSA_2020_3888 = RHSA_2020_3888_Rule:new{
PatchId = "RHSA-2020:3888",
CVEId = "CVE-2020-8492",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python3",Version = "3.6.8-17.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-debug",Version = "3.6.8-17.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-devel",Version = "3.6.8-17.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-idle",Version = "3.6.8-17.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-libs",Version = "3.6.8-17.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-test",Version = "3.6.8-17.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-tkinter",Version = "3.6.8-17.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3888)

RHSA_2020_3898_Rule = VulRule:new()

RHSA_2020_3898 = RHSA_2020_3898_Rule:new{
PatchId = "RHSA-2020:3898",
CVEId = "CVE-2020-8632",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "cloud-init",Version = "19.4-7.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3898)

RHSA_2020_3901_Rule = VulRule:new()

RHSA_2020_3901 = RHSA_2020_3901_Rule:new{
PatchId = "RHSA-2020:3901",
CVEId = "CVE-2017-12652",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libpng",Version = "1.5.13-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libpng-devel",Version = "1.5.13-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libpng-static",Version = "1.5.13-8.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3901)

RHSA_2020_3902_Rule = VulRule:new()

RHSA_2020_3902 = RHSA_2020_3902_Rule:new{
PatchId = "RHSA-2020:3902",
CVEId = "CVE-2019-17546",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libtiff",Version = "4.0.3-35.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libtiff-devel",Version = "4.0.3-35.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libtiff-static",Version = "4.0.3-35.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libtiff-tools",Version = "4.0.3-35.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3902)

RHSA_2020_3906_Rule = VulRule:new()

RHSA_2020_3906 = RHSA_2020_3906_Rule:new{
PatchId = "RHSA-2020:3906",
CVEId = "CVE-2019-20382",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-img",Version = "1.5.3-175.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm",Version = "1.5.3-175.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-common",Version = "1.5.3-175.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-tools",Version = "1.5.3-175.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3906)

RHSA_2020_3907_Rule = VulRule:new()

RHSA_2020_3907 = RHSA_2020_3907_Rule:new{
PatchId = "RHSA-2020:3907",
CVEId = "CVE-2018-15746",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-img-ma",Version = "2.12.0-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-common-ma",Version = "2.12.0-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-ma",Version = "2.12.0-48.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-tools-ma",Version = "2.12.0-48.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3907)

RHSA_2020_3908_Rule = VulRule:new()

RHSA_2020_3908 = RHSA_2020_3908_Rule:new{
PatchId = "RHSA-2020:3908",
CVEId = "CVE-2019-14866",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "cpio",Version = "2.11-28.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3908)

RHSA_2020_3911_Rule = VulRule:new()

RHSA_2020_3911 = RHSA_2020_3911_Rule:new{
PatchId = "RHSA-2020:3911",
CVEId = "CVE-2019-16935",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python",Version = "2.7.5-89.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-debug",Version = "2.7.5-89.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-devel",Version = "2.7.5-89.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-libs",Version = "2.7.5-89.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-test",Version = "2.7.5-89.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-tools",Version = "2.7.5-89.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tkinter",Version = "2.7.5-89.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3911)

RHSA_2020_3915_Rule = VulRule:new()

RHSA_2020_3915 = RHSA_2020_3915_Rule:new{
PatchId = "RHSA-2020:3915",
CVEId = "CVE-2019-17498",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libssh2",Version = "1.8.0-4.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libssh2-devel",Version = "1.8.0-4.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libssh2-docs",Version = "1.8.0-4.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3915)

RHSA_2020_3916_Rule = VulRule:new()

RHSA_2020_3916 = RHSA_2020_3916_Rule:new{
PatchId = "RHSA-2020:3916",
CVEId = "CVE-2019-5482",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "curl",Version = "7.29.0-59.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libcurl",Version = "7.29.0-59.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libcurl-devel",Version = "7.29.0-59.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3916)

RHSA_2020_3922_Rule = VulRule:new()

RHSA_2020_3922 = RHSA_2020_3922_Rule:new{
PatchId = "RHSA-2020:3922",
CVEId = "CVE-2018-19662",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libsndfile",Version = "1.0.25-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libsndfile-devel",Version = "1.0.25-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libsndfile-utils",Version = "1.0.25-12.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3922)

RHSA_2020_3936_Rule = VulRule:new()

RHSA_2020_3936 = RHSA_2020_3936_Rule:new{
PatchId = "RHSA-2020:3936",
CVEId = "CVE-2020-1722",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipa-client",Version = "4.6.8-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipa-client-common",Version = "4.6.8-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipa-common",Version = "4.6.8-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipa-python-compat",Version = "4.6.8-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipa-server",Version = "4.6.8-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipa-server-common",Version = "4.6.8-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipa-server-dns",Version = "4.6.8-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipa-server-trust-ad",Version = "4.6.8-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python2-ipaclient",Version = "4.6.8-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python2-ipalib",Version = "4.6.8-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python2-ipaserver",Version = "4.6.8-5.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3936)

RHSA_2020_3940_Rule = VulRule:new()

RHSA_2020_3940 = RHSA_2020_3940_Rule:new{
PatchId = "RHSA-2020:3940",
CVEId = "CVE-2019-3833",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libwsman-devel",Version = "2.6.3-7.git4391e5c.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libwsman1",Version = "2.6.3-7.git4391e5c.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openwsman-client",Version = "2.6.3-7.git4391e5c.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openwsman-perl",Version = "2.6.3-7.git4391e5c.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openwsman-python",Version = "2.6.3-7.git4391e5c.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openwsman-ruby",Version = "2.6.3-7.git4391e5c.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openwsman-server",Version = "2.6.3-7.git4391e5c.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3940)

RHSA_2020_3943_Rule = VulRule:new()

RHSA_2020_3943 = RHSA_2020_3943_Rule:new{
PatchId = "RHSA-2020:3943",
CVEId = "CVE-2019-6978",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libwmf",Version = "0.2.8.4-44.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libwmf-devel",Version = "0.2.8.4-44.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libwmf-lite",Version = "0.2.8.4-44.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3943)

RHSA_2020_3944_Rule = VulRule:new()

RHSA_2020_3944 = RHSA_2020_3944_Rule:new{
PatchId = "RHSA-2020:3944",
CVEId = "CVE-2019-17400",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "unoconv",Version = "0.6-8.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3944)

RHSA_2020_3949_Rule = VulRule:new()

RHSA_2020_3949 = RHSA_2020_3949_Rule:new{
PatchId = "RHSA-2020:3949",
CVEId = "CVE-2019-18609",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "librabbitmq",Version = "0.8.0-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "librabbitmq-devel",Version = "0.8.0-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "librabbitmq-examples",Version = "0.8.0-3.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3949)

RHSA_2020_3952_Rule = VulRule:new()

RHSA_2020_3952 = RHSA_2020_3952_Rule:new{
PatchId = "RHSA-2020:3952",
CVEId = "CVE-2019-15903",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "expat",Version = "2.1.0-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "expat-devel",Version = "2.1.0-12.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "expat-static",Version = "2.1.0-12.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3952)

RHSA_2020_3958_Rule = VulRule:new()

RHSA_2020_3958 = RHSA_2020_3958_Rule:new{
PatchId = "RHSA-2020:3958",
CVEId = "CVE-2020-1934",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "httpd",Version = "2.4.6-95.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "httpd-devel",Version = "2.4.6-95.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "httpd-manual",Version = "2.4.6-95.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "httpd-tools",Version = "2.4.6-95.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mod_ldap",Version = "2.4.6-95.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mod_proxy_html",Version = "2.4.6-95.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mod_session",Version = "2.4.6-95.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mod_ssl",Version = "2.4.6-95.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3958)

RHSA_2020_3966_Rule = VulRule:new()

RHSA_2020_3966 = RHSA_2020_3966_Rule:new{
PatchId = "RHSA-2020:3966",
CVEId = "CVE-2020-5395",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fontforge",Version = "20120731b-13.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fontforge-devel",Version = "20120731b-13.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3966)

RHSA_2020_3970_Rule = VulRule:new()

RHSA_2020_3970 = RHSA_2020_3970_Rule:new{
PatchId = "RHSA-2020:3970",
CVEId = "CVE-2019-20479",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mod_auth_openidc",Version = "1.8.8-7.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3970)

RHSA_2020_3971_Rule = VulRule:new()

RHSA_2020_3971 = RHSA_2020_3971_Rule:new{
PatchId = "RHSA-2020:3971",
CVEId = "CVE-2019-16707",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "hunspell",Version = "1.3.2-16.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "hunspell-devel",Version = "1.3.2-16.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3971)

RHSA_2020_3972_Rule = VulRule:new()

RHSA_2020_3972 = RHSA_2020_3972_Rule:new{
PatchId = "RHSA-2020:3972",
CVEId = "CVE-2018-11782",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mod_dav_svn",Version = "1.7.14-16.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "subversion",Version = "1.7.14-16.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "subversion-devel",Version = "1.7.14-16.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "subversion-gnome",Version = "1.7.14-16.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "subversion-javahl",Version = "1.7.14-16.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "subversion-kde",Version = "1.7.14-16.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "subversion-libs",Version = "1.7.14-16.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "subversion-perl",Version = "1.7.14-16.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "subversion-python",Version = "1.7.14-16.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "subversion-ruby",Version = "1.7.14-16.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "subversion-tools",Version = "1.7.14-16.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3972)

RHSA_2020_3973_Rule = VulRule:new()

RHSA_2020_3973 = RHSA_2020_3973_Rule:new{
PatchId = "RHSA-2020:3973",
CVEId = "CVE-2019-12420",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "spamassassin",Version = "3.4.0-6.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3973)

RHSA_2020_3977_Rule = VulRule:new()

RHSA_2020_3977 = RHSA_2020_3977_Rule:new{
PatchId = "RHSA-2020:3977",
CVEId = "CVE-2019-14494",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evince",Version = "3.28.2-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evince-browser-plugin",Version = "3.28.2-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evince-devel",Version = "3.28.2-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evince-dvi",Version = "3.28.2-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evince-libs",Version = "3.28.2-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "evince-nautilus",Version = "3.28.2-10.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "poppler",Version = "0.26.5-43.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "poppler-cpp",Version = "0.26.5-43.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "poppler-cpp-devel",Version = "0.26.5-43.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "poppler-demos",Version = "0.26.5-43.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "poppler-devel",Version = "0.26.5-43.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "poppler-glib",Version = "0.26.5-43.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "poppler-glib-devel",Version = "0.26.5-43.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "poppler-qt",Version = "0.26.5-43.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "poppler-qt-devel",Version = "0.26.5-43.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "poppler-utils",Version = "0.26.5-43.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3977)

RHSA_2020_3978_Rule = VulRule:new()

RHSA_2020_3978 = RHSA_2020_3978_Rule:new{
PatchId = "RHSA-2020:3978",
CVEId = "CVE-2019-14822",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ibus",Version = "1.5.17-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ibus-devel",Version = "1.5.17-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ibus-devel-docs",Version = "1.5.17-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ibus-gtk2",Version = "1.5.17-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ibus-gtk3",Version = "1.5.17-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ibus-libs",Version = "1.5.17-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ibus-pygtk2",Version = "1.5.17-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ibus-setup",Version = "1.5.17-11.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2",Version = "2.56.1-7.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-devel",Version = "2.56.1-7.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-doc",Version = "2.56.1-7.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-fam",Version = "2.56.1-7.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-static",Version = "2.56.1-7.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-tests",Version = "2.56.1-7.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3978)

RHSA_2020_3981_Rule = VulRule:new()

RHSA_2020_3981 = RHSA_2020_3981_Rule:new{
PatchId = "RHSA-2020:3981",
CVEId = "CVE-2019-14907",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ctdb",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ctdb-tests",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libsmbclient",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libsmbclient-devel",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libwbclient",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libwbclient-devel",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-client",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-client-libs",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-common",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-common-libs",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-common-tools",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-dc",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-dc-libs",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-devel",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-krb5-printing",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-libs",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-pidl",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-python",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-python-test",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-test",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-test-libs",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-vfs-glusterfs",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winbind",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winbind-clients",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winbind-krb5-locator",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winbind-modules",Version = "4.10.16-5.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3981)

RHSA_2020_3984_Rule = VulRule:new()

RHSA_2020_3984 = RHSA_2020_3984_Rule:new{
PatchId = "RHSA-2020:3984",
CVEId = "CVE-2019-17185",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "freeradius",Version = "3.0.13-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "freeradius-devel",Version = "3.0.13-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "freeradius-doc",Version = "3.0.13-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "freeradius-krb5",Version = "3.0.13-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "freeradius-ldap",Version = "3.0.13-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "freeradius-mysql",Version = "3.0.13-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "freeradius-perl",Version = "3.0.13-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "freeradius-postgresql",Version = "3.0.13-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "freeradius-python",Version = "3.0.13-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "freeradius-sqlite",Version = "3.0.13-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "freeradius-unixODBC",Version = "3.0.13-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "freeradius-utils",Version = "3.0.13-15.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3984)

RHSA_2020_3996_Rule = VulRule:new()

RHSA_2020_3996 = RHSA_2020_3996_Rule:new{
PatchId = "RHSA-2020:3996",
CVEId = "CVE-2020-7595",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libxml2",Version = "2.9.1-6.el7.5",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libxml2-devel",Version = "2.9.1-6.el7.5",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libxml2-python",Version = "2.9.1-6.el7.5",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libxml2-static",Version = "2.9.1-6.el7.5",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3996)

RHSA_2020_4000_Rule = VulRule:new()

RHSA_2020_4000 = RHSA_2020_4000_Rule:new{
PatchId = "RHSA-2020:4000",
CVEId = "CVE-2020-10703",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-admin",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-bash-completion",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-client",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-config-network",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-config-nwfilter",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-interface",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-lxc",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-network",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-nodedev",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-nwfilter",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-qemu",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-secret",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-storage",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-storage-core",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-storage-disk",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-storage-gluster",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-storage-iscsi",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-storage-logical",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-storage-mpath",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-storage-rbd",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-storage-scsi",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-kvm",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-lxc",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-devel",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-docs",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-libs",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-lock-sanlock",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-login-shell",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-nss",Version = "4.5.0-36.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4000)

RHSA_2020_4001_Rule = VulRule:new()

RHSA_2020_4001 = RHSA_2020_4001_Rule:new{
PatchId = "RHSA-2020:4001",
CVEId = "CVE-2020-0556",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez",Version = "5.44-7.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez-cups",Version = "5.44-7.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez-hid2hci",Version = "5.44-7.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez-libs",Version = "5.44-7.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez-libs-devel",Version = "5.44-7.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4001)

RHSA_2020_4003_Rule = VulRule:new()

RHSA_2020_4003 = RHSA_2020_4003_Rule:new{
PatchId = "RHSA-2020:4003",
CVEId = "CVE-2020-10754",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager",Version = "1.18.8-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-adsl",Version = "1.18.8-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-bluetooth",Version = "1.18.8-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-config-server",Version = "1.18.8-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-dispatcher-routing-rules",Version = "1.18.8-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-glib",Version = "1.18.8-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-glib-devel",Version = "1.18.8-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-libnm",Version = "1.18.8-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-libnm-devel",Version = "1.18.8-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-ovs",Version = "1.18.8-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-ppp",Version = "1.18.8-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-team",Version = "1.18.8-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-tui",Version = "1.18.8-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-wifi",Version = "1.18.8-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-wwan",Version = "1.18.8-1.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4003)

RHSA_2020_4004_Rule = VulRule:new()

RHSA_2020_4004 = RHSA_2020_4004_Rule:new{
PatchId = "RHSA-2020:4004",
CVEId = "CVE-2020-13935",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat",Version = "7.0.76-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-admin-webapps",Version = "7.0.76-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-docs-webapp",Version = "7.0.76-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-el-2.2-api",Version = "7.0.76-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-javadoc",Version = "7.0.76-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-jsp-2.2-api",Version = "7.0.76-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-jsvc",Version = "7.0.76-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-lib",Version = "7.0.76-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-servlet-3.0-api",Version = "7.0.76-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-webapps",Version = "7.0.76-15.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4004)

RHSA_2020_4005_Rule = VulRule:new()

RHSA_2020_4005 = RHSA_2020_4005_Rule:new{
PatchId = "RHSA-2020:4005",
CVEId = "CVE-2019-18197",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libxslt",Version = "1.1.28-6.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libxslt-devel",Version = "1.1.28-6.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libxslt-python",Version = "1.1.28-6.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4005)

RHSA_2020_4007_Rule = VulRule:new()

RHSA_2020_4007 = RHSA_2020_4007_Rule:new{
PatchId = "RHSA-2020:4007",
CVEId = "CVE-2019-20386",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libgudev1",Version = "219-78.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libgudev1-devel",Version = "219-78.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd",Version = "219-78.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-devel",Version = "219-78.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-journal-gateway",Version = "219-78.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-libs",Version = "219-78.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-networkd",Version = "219-78.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-python",Version = "219-78.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-resolved",Version = "219-78.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-sysv",Version = "219-78.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4007)

RHSA_2020_4011_Rule = VulRule:new()

RHSA_2020_4011 = RHSA_2020_4011_Rule:new{
PatchId = "RHSA-2020:4011",
CVEId = "CVE-2019-5188",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "e2fsprogs",Version = "1.42.9-19.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "e2fsprogs-devel",Version = "1.42.9-19.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "e2fsprogs-libs",Version = "1.42.9-19.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "e2fsprogs-static",Version = "1.42.9-19.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libcom_err",Version = "1.42.9-19.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libcom_err-devel",Version = "1.42.9-19.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libss",Version = "1.42.9-19.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libss-devel",Version = "1.42.9-19.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4011)

RHSA_2020_4024_Rule = VulRule:new()

RHSA_2020_4024 = RHSA_2020_4024_Rule:new{
PatchId = "RHSA-2020:4024",
CVEId = "CVE-2020-9359",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "okular",Version = "4.10.5-9.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "okular-devel",Version = "4.10.5-9.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "okular-libs",Version = "4.10.5-9.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "okular-part",Version = "4.10.5-9.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4024)

RHSA_2020_4025_Rule = VulRule:new()

RHSA_2020_4025 = RHSA_2020_4025_Rule:new{
PatchId = "RHSA-2020:4025",
CVEId = "CVE-2020-0570",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt5-qtbase",Version = "5.9.7-4.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt5-qtbase-common",Version = "5.9.7-4.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt5-qtbase-devel",Version = "5.9.7-4.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt5-qtbase-doc",Version = "5.9.7-4.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt5-qtbase-examples",Version = "5.9.7-4.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt5-qtbase-gui",Version = "5.9.7-4.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt5-qtbase-mysql",Version = "5.9.7-4.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt5-qtbase-odbc",Version = "5.9.7-4.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt5-qtbase-postgresql",Version = "5.9.7-4.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt5-qtbase-static",Version = "5.9.7-4.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt5-rpm-macros",Version = "5.9.7-4.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4025)

RHSA_2020_4026_Rule = VulRule:new()

RHSA_2020_4026 = RHSA_2020_4026_Rule:new{
PatchId = "RHSA-2020:4026",
CVEId = "CVE-2021-2144",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mariadb",Version = "5.5.68-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mariadb-bench",Version = "5.5.68-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mariadb-devel",Version = "5.5.68-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mariadb-embedded",Version = "5.5.68-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mariadb-embedded-devel",Version = "5.5.68-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mariadb-libs",Version = "5.5.68-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mariadb-server",Version = "5.5.68-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "mariadb-test",Version = "5.5.68-1.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4026)

RHSA_2020_4030_Rule = VulRule:new()

RHSA_2020_4030 = RHSA_2020_4030_Rule:new{
PatchId = "RHSA-2020:4030",
CVEId = "CVE-2019-17402",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "exiv2",Version = "0.27.0-3.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "exiv2-devel",Version = "0.27.0-3.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "exiv2-doc",Version = "0.27.0-3.el7_8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "exiv2-libs",Version = "0.27.0-3.el7_8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4030)

RHSA_2020_4031_Rule = VulRule:new()

RHSA_2020_4031 = RHSA_2020_4031_Rule:new{
PatchId = "RHSA-2020:4031",
CVEId = "CVE-2020-13397",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "freerdp",Version = "2.1.1-2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "freerdp-devel",Version = "2.1.1-2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "freerdp-libs",Version = "2.1.1-2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libwinpr",Version = "2.1.1-2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libwinpr-devel",Version = "2.1.1-2.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4031)

RHSA_2020_4032_Rule = VulRule:new()

RHSA_2020_4032 = RHSA_2020_4032_Rule:new{
PatchId = "RHSA-2020:4032",
CVEId = "CVE-2019-12749",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dbus",Version = "1.10.24-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dbus-devel",Version = "1.10.24-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dbus-doc",Version = "1.10.24-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dbus-libs",Version = "1.10.24-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dbus-tests",Version = "1.10.24-15.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dbus-x11",Version = "1.10.24-15.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4032)

RHSA_2020_4035_Rule = VulRule:new()

RHSA_2020_4035 = RHSA_2020_4035_Rule:new{
PatchId = "RHSA-2020:4035",
CVEId = "CVE-2020-3902",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "webkitgtk4",Version = "2.28.2-2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "webkitgtk4-devel",Version = "2.28.2-2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "webkitgtk4-doc",Version = "2.28.2-2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "webkitgtk4-jsc",Version = "2.28.2-2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "webkitgtk4-jsc-devel",Version = "2.28.2-2.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4035)

RHSA_2020_4039_Rule = VulRule:new()

RHSA_2020_4039 = RHSA_2020_4039_Rule:new{
PatchId = "RHSA-2020:4039",
CVEId = "CVE-2020-11764",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "OpenEXR",Version = "1.7.1-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "OpenEXR-devel",Version = "1.7.1-8.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "OpenEXR-libs",Version = "1.7.1-8.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4039)

RHSA_2020_4040_Rule = VulRule:new()

RHSA_2020_4040 = RHSA_2020_4040_Rule:new{
PatchId = "RHSA-2020:4040",
CVEId = "CVE-2020-13114",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libexif",Version = "0.6.22-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libexif-devel",Version = "0.6.22-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libexif-doc",Version = "0.6.22-1.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4040)

RHSA_2020_4041_Rule = VulRule:new()

RHSA_2020_4041 = RHSA_2020_4041_Rule:new{
PatchId = "RHSA-2020:4041",
CVEId = "CVE-2020-12243",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openldap",Version = "2.4.44-22.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openldap-clients",Version = "2.4.44-22.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openldap-devel",Version = "2.4.44-22.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openldap-servers",Version = "2.4.44-22.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openldap-servers-sql",Version = "2.4.44-22.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4041)

RHSA_2020_4060_Rule = VulRule:new()

RHSA_2020_4060 = RHSA_2020_4060_Rule:new{
PatchId = "RHSA-2020:4060",
CVEId = "CVE-2020-9383",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-bootwrapper",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump-devel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python-perf",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4060)

RHSA_2020_4072_Rule = VulRule:new()

RHSA_2020_4072 = RHSA_2020_4072_Rule:new{
PatchId = "RHSA-2020:4072",
CVEId = "CVE-2020-12825",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libcroco",Version = "0.6.12-6.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libcroco-devel",Version = "0.6.12-6.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4072)

RHSA_2020_4076_Rule = VulRule:new()

RHSA_2020_4076 = RHSA_2020_4076_Rule:new{
PatchId = "RHSA-2020:4076",
CVEId = "CVE-2020-6829",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nspr",Version = "4.25.0-2.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nspr-devel",Version = "4.25.0-2.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nss-util",Version = "3.53.1-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nss-util-devel",Version = "3.53.1-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nss",Version = "3.53.1-3.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nss-devel",Version = "3.53.1-3.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nss-pkcs11-devel",Version = "3.53.1-3.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nss-sysinit",Version = "3.53.1-3.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nss-tools",Version = "3.53.1-3.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nss-softokn",Version = "3.53.1-6.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nss-softokn-devel",Version = "3.53.1-6.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nss-softokn-freebl",Version = "3.53.1-6.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nss-softokn-freebl-devel",Version = "3.53.1-6.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4076)

RHSA_2020_4078_Rule = VulRule:new()

RHSA_2020_4078 = RHSA_2020_4078_Rule:new{
PatchId = "RHSA-2020:4078",
CVEId = "CVE-2020-14364",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-img-ma",Version = "2.12.0-48.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-common-ma",Version = "2.12.0-48.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-ma",Version = "2.12.0-48.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-tools-ma",Version = "2.12.0-48.el7_9.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4078)

RHSA_2020_4079_Rule = VulRule:new()

RHSA_2020_4079 = RHSA_2020_4079_Rule:new{
PatchId = "RHSA-2020:4079",
CVEId = "CVE-2020-1983",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-img",Version = "1.5.3-175.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm",Version = "1.5.3-175.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-common",Version = "1.5.3-175.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-tools",Version = "1.5.3-175.el7_9.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4079)

RHSA_2020_4080_Rule = VulRule:new()

RHSA_2020_4080 = RHSA_2020_4080_Rule:new{
PatchId = "RHSA-2020:4080",
CVEId = "CVE-2020-15678",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "78.3.0-1.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4080)

RHSA_2020_4082_Rule = VulRule:new()

RHSA_2020_4082 = RHSA_2020_4082_Rule:new{
PatchId = "RHSA-2020:4082",
CVEId = "CVE-2020-8450",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "squid",Version = "3.5.20-17.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "squid-migration-script",Version = "3.5.20-17.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "squid-sysvinit",Version = "3.5.20-17.el7_9.4",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4082)

RHSA_2020_4163_Rule = VulRule:new()

RHSA_2020_4163 = RHSA_2020_4163_Rule:new{
PatchId = "RHSA-2020:4163",
CVEId = "CVE-2020-15677",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "78.3.1-1.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4163)

RHSA_2020_4187_Rule = VulRule:new()

RHSA_2020_4187 = RHSA_2020_4187_Rule:new{
PatchId = "RHSA-2020:4187",
CVEId = "CVE-2020-14355",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "spice-glib",Version = "0.35-5.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "spice-glib-devel",Version = "0.35-5.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "spice-gtk-tools",Version = "0.35-5.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "spice-gtk3",Version = "0.35-5.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "spice-gtk3-devel",Version = "0.35-5.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "spice-gtk3-vala",Version = "0.35-5.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "spice-server",Version = "0.14.0-9.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "spice-server-devel",Version = "0.14.0-9.el7_9.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4187)

RHSA_2020_4276_Rule = VulRule:new()

RHSA_2020_4276 = RHSA_2020_4276_Rule:new{
PatchId = "RHSA-2020:4276",
CVEId = "CVE-2020-12352",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-bootwrapper",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump-devel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python-perf",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4276)

RHSA_2020_4307_Rule = VulRule:new()

RHSA_2020_4307 = RHSA_2020_4307_Rule:new{
PatchId = "RHSA-2020:4307",
CVEId = "CVE-2020-14803",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk",Version = "11.0.9.11-0.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-demo",Version = "11.0.9.11-0.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-devel",Version = "11.0.9.11-0.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-headless",Version = "11.0.9.11-0.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-javadoc",Version = "11.0.9.11-0.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-javadoc-zip",Version = "11.0.9.11-0.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-jmods",Version = "11.0.9.11-0.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-src",Version = "11.0.9.11-0.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-static-libs",Version = "11.0.9.11-0.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4307)

RHSA_2020_4310_Rule = VulRule:new()

RHSA_2020_4310 = RHSA_2020_4310_Rule:new{
PatchId = "RHSA-2020:4310",
CVEId = "CVE-2020-15969",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "78.4.0-1.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4310)

RHSA_2020_4350_Rule = VulRule:new()

RHSA_2020_4350 = RHSA_2020_4350_Rule:new{
PatchId = "RHSA-2020:4350",
CVEId = "CVE-2020-14797",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk",Version = "1.8.0.272.b10-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-accessibility",Version = "1.8.0.272.b10-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-demo",Version = "1.8.0.272.b10-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-devel",Version = "1.8.0.272.b10-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-headless",Version = "1.8.0.272.b10-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-javadoc",Version = "1.8.0.272.b10-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-javadoc-zip",Version = "1.8.0.272.b10-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-src",Version = "1.8.0.272.b10-1.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4350)

RHSA_2020_4907_Rule = VulRule:new()

RHSA_2020_4907 = RHSA_2020_4907_Rule:new{
PatchId = "RHSA-2020:4907",
CVEId = "CVE-2020-15999",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "freetype",Version = "2.8-14.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "freetype-demos",Version = "2.8-14.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "freetype-devel",Version = "2.8-14.el7_9.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4907)

RHSA_2020_4908_Rule = VulRule:new()

RHSA_2020_4908 = RHSA_2020_4908_Rule:new{
PatchId = "RHSA-2020:4908",
CVEId = "CVE-2020-14363",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libX11",Version = "1.6.7-3.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libX11-common",Version = "1.6.7-3.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libX11-devel",Version = "1.6.7-3.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4908)

RHSA_2020_4909_Rule = VulRule:new()

RHSA_2020_4909 = RHSA_2020_4909_Rule:new{
PatchId = "RHSA-2020:4909",
CVEId = "CVE-2020-15683",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "78.4.0-1.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4909)

RHSA_2020_4910_Rule = VulRule:new()

RHSA_2020_4910 = RHSA_2020_4910_Rule:new{
PatchId = "RHSA-2020:4910",
CVEId = "CVE-2020-14362",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-Xdmx",Version = "1.20.4-12.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-Xephyr",Version = "1.20.4-12.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-Xnest",Version = "1.20.4-12.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-Xorg",Version = "1.20.4-12.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-Xvfb",Version = "1.20.4-12.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-Xwayland",Version = "1.20.4-12.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-common",Version = "1.20.4-12.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-devel",Version = "1.20.4-12.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-source",Version = "1.20.4-12.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4910)

RHSA_2020_5002_Rule = VulRule:new()

RHSA_2020_5002 = RHSA_2020_5002_Rule:new{
PatchId = "RHSA-2020:5002",
CVEId = "CVE-2020-8177",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "curl",Version = "7.29.0-59.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libcurl",Version = "7.29.0-59.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libcurl-devel",Version = "7.29.0-59.el7_9.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5002)

RHSA_2020_5003_Rule = VulRule:new()

RHSA_2020_5003 = RHSA_2020_5003_Rule:new{
PatchId = "RHSA-2020:5003",
CVEId = "CVE-2020-11078",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-aliyun",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-all",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-amt-ws",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-apc",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-apc-snmp",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-aws",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-azure-arm",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-bladecenter",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-brocade",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-cisco-mds",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-cisco-ucs",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-common",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-compute",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-drac5",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-eaton-snmp",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-emerson",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-eps",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-gce",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-heuristics-ping",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-hpblade",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-ibmblade",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-ifmib",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-ilo-moonshot",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-ilo-mp",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-ilo-ssh",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-ilo2",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-intelmodular",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-ipdu",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-ipmilan",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-kdump",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-lpar",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-mpath",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-redfish",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-rhevm",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-rsa",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-rsb",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-sbd",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-scsi",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-virsh",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-vmware-rest",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-vmware-soap",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-wti",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "fence-agents-zvm",Version = "4.2.1-41.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "resource-agents",Version = "4.1.1-61.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "resource-agents-aliyun",Version = "4.1.1-61.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "resource-agents-gcp",Version = "4.1.1-61.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "resource-agents-sap",Version = "4.1.1-61.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "resource-agents-sap-hana",Version = "4.1.1-61.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "resource-agents-sap-hana-scaleout",Version = "0.164.0-6.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "sap-cluster-connector",Version = "3.0.1-37.el7_9.4",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5003)

RHSA_2020_5009_Rule = VulRule:new()

RHSA_2020_5009 = RHSA_2020_5009_Rule:new{
PatchId = "RHSA-2020:5009",
CVEId = "CVE-2019-20907",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python",Version = "2.7.5-90.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-debug",Version = "2.7.5-90.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-devel",Version = "2.7.5-90.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-libs",Version = "2.7.5-90.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-test",Version = "2.7.5-90.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-tools",Version = "2.7.5-90.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tkinter",Version = "2.7.5-90.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5009)

RHSA_2020_5010_Rule = VulRule:new()

RHSA_2020_5010 = RHSA_2020_5010_Rule:new{
PatchId = "RHSA-2020:5010",
CVEId = "CVE-2020-14422",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python3",Version = "3.6.8-18.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-debug",Version = "3.6.8-18.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-devel",Version = "3.6.8-18.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-idle",Version = "3.6.8-18.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-libs",Version = "3.6.8-18.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-test",Version = "3.6.8-18.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-tkinter",Version = "3.6.8-18.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5010)

RHSA_2020_5011_Rule = VulRule:new()

RHSA_2020_5011 = RHSA_2020_5011_Rule:new{
PatchId = "RHSA-2020:5011",
CVEId = "CVE-2020-8624",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind",Version = "9.11.4-26.P2.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-chroot",Version = "9.11.4-26.P2.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-devel",Version = "9.11.4-26.P2.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-export-devel",Version = "9.11.4-26.P2.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-export-libs",Version = "9.11.4-26.P2.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-libs",Version = "9.11.4-26.P2.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-libs-lite",Version = "9.11.4-26.P2.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-license",Version = "9.11.4-26.P2.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-lite-devel",Version = "9.11.4-26.P2.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11",Version = "9.11.4-26.P2.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-devel",Version = "9.11.4-26.P2.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-libs",Version = "9.11.4-26.P2.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-utils",Version = "9.11.4-26.P2.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-sdb",Version = "9.11.4-26.P2.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-sdb-chroot",Version = "9.11.4-26.P2.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-utils",Version = "9.11.4-26.P2.el7_9.2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5011)

RHSA_2020_5012_Rule = VulRule:new()

RHSA_2020_5012 = RHSA_2020_5012_Rule:new{
PatchId = "RHSA-2020:5012",
CVEId = "CVE-2020-14352",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "librepo",Version = "1.8.1-8.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "librepo-devel",Version = "1.8.1-8.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-librepo",Version = "1.8.1-8.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5012)

RHSA_2020_5020_Rule = VulRule:new()

RHSA_2020_5020 = RHSA_2020_5020_Rule:new{
PatchId = "RHSA-2020:5020",
CVEId = "CVE-2020-1935",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat",Version = "7.0.76-16.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-admin-webapps",Version = "7.0.76-16.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-docs-webapp",Version = "7.0.76-16.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-el-2.2-api",Version = "7.0.76-16.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-javadoc",Version = "7.0.76-16.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-jsp-2.2-api",Version = "7.0.76-16.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-jsvc",Version = "7.0.76-16.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-lib",Version = "7.0.76-16.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-servlet-3.0-api",Version = "7.0.76-16.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat-webapps",Version = "7.0.76-16.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5020)

RHSA_2020_5021_Rule = VulRule:new()

RHSA_2020_5021 = RHSA_2020_5021_Rule:new{
PatchId = "RHSA-2020:5021",
CVEId = "CVE-2020-17507",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt5-qtbase",Version = "5.9.7-5.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt5-qtbase-common",Version = "5.9.7-5.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt5-qtbase-devel",Version = "5.9.7-5.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt5-qtbase-doc",Version = "5.9.7-5.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt5-qtbase-examples",Version = "5.9.7-5.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt5-qtbase-gui",Version = "5.9.7-5.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt5-qtbase-mysql",Version = "5.9.7-5.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt5-qtbase-odbc",Version = "5.9.7-5.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt5-qtbase-postgresql",Version = "5.9.7-5.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt5-qtbase-static",Version = "5.9.7-5.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt5-rpm-macros",Version = "5.9.7-5.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt",Version = "4.8.7-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-assistant",Version = "4.8.7-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-config",Version = "4.8.7-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-demos",Version = "4.8.7-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-devel",Version = "4.8.7-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-devel-private",Version = "4.8.7-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-doc",Version = "4.8.7-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-examples",Version = "4.8.7-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-mysql",Version = "4.8.7-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-odbc",Version = "4.8.7-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-postgresql",Version = "4.8.7-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-qdbusviewer",Version = "4.8.7-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-qvfb",Version = "4.8.7-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt-x11",Version = "4.8.7-9.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5021)

RHSA_2020_5023_Rule = VulRule:new()

RHSA_2020_5023 = RHSA_2020_5023_Rule:new{
PatchId = "RHSA-2020:5023",
CVEId = "CVE-2020-14331",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-bootwrapper",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump-devel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python-perf",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5023)

RHSA_2020_5040_Rule = VulRule:new()

RHSA_2020_5040 = RHSA_2020_5040_Rule:new{
PatchId = "RHSA-2020:5040",
CVEId = "CVE-2020-25637",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-admin",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-bash-completion",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-client",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-config-network",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-config-nwfilter",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-interface",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-lxc",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-network",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-nodedev",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-nwfilter",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-qemu",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-secret",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-storage",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-storage-core",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-storage-disk",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-storage-gluster",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-storage-iscsi",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-storage-logical",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-storage-mpath",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-storage-rbd",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-driver-storage-scsi",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-kvm",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-daemon-lxc",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-devel",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-docs",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-libs",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-lock-sanlock",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-login-shell",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libvirt-nss",Version = "4.5.0-36.el7_9.3",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5040)

RHSA_2020_5050_Rule = VulRule:new()

RHSA_2020_5050 = RHSA_2020_5050_Rule:new{
PatchId = "RHSA-2020:5050",
CVEId = "CVE-2020-14385",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160",Version = "1-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.2.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.2.1.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.2.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160_2_1",Version = "1-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160_2_2",Version = "1-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160_6_1",Version = "1-1.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5050)

RHSA_2020_5083_Rule = VulRule:new()

RHSA_2020_5083 = RHSA_2020_5083_Rule:new{
PatchId = "RHSA-2020:5083",
CVEId = "CVE-2020-8698",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "microcode_ctl",Version = "2.1-73.2.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5083)

RHSA_2020_5099_Rule = VulRule:new()

RHSA_2020_5099 = RHSA_2020_5099_Rule:new{
PatchId = "RHSA-2020:5099",
CVEId = "CVE-2020-26950",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "78.4.1-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "78.4.3-1.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5099)

RHSA_2020_5235_Rule = VulRule:new()

RHSA_2020_5235 = RHSA_2020_5235_Rule:new{
PatchId = "RHSA-2020:5235",
CVEId = "CVE-2020-26968",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "78.5.0-1.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5235)

RHSA_2020_5239_Rule = VulRule:new()

RHSA_2020_5239 = RHSA_2020_5239_Rule:new{
PatchId = "RHSA-2020:5239",
CVEId = "CVE-2020-26965",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "78.5.0-1.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5239)

RHSA_2020_5350_Rule = VulRule:new()

RHSA_2020_5350 = RHSA_2020_5350_Rule:new{
PatchId = "RHSA-2020:5350",
CVEId = "CVE-2020-15862",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp",Version = "5.7.2-49.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-agent-libs",Version = "5.7.2-49.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-devel",Version = "5.7.2-49.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-gui",Version = "5.7.2-49.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-libs",Version = "5.7.2-49.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-perl",Version = "5.7.2-49.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-python",Version = "5.7.2-49.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-sysvinit",Version = "5.7.2-49.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-utils",Version = "5.7.2-49.el7_9.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5350)

RHSA_2020_5400_Rule = VulRule:new()

RHSA_2020_5400 = RHSA_2020_5400_Rule:new{
PatchId = "RHSA-2020:5400",
CVEId = "CVE-2020-26970",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "78.5.1-1.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5400)

RHSA_2020_5402_Rule = VulRule:new()

RHSA_2020_5402 = RHSA_2020_5402_Rule:new{
PatchId = "RHSA-2020:5402",
CVEId = "CVE-2020-0452",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libexif",Version = "0.6.22-2.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libexif-devel",Version = "0.6.22-2.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libexif-doc",Version = "0.6.22-2.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5402)

RHSA_2020_5408_Rule = VulRule:new()

RHSA_2020_5408 = RHSA_2020_5408_Rule:new{
PatchId = "RHSA-2020:5408",
CVEId = "CVE-2020-25712",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-Xdmx",Version = "1.20.4-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-Xephyr",Version = "1.20.4-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-Xnest",Version = "1.20.4-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-Xorg",Version = "1.20.4-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-Xvfb",Version = "1.20.4-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-Xwayland",Version = "1.20.4-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-common",Version = "1.20.4-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-devel",Version = "1.20.4-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-source",Version = "1.20.4-15.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5408)

RHSA_2020_5434_Rule = VulRule:new()

RHSA_2020_5434 = RHSA_2020_5434_Rule:new{
PatchId = "RHSA-2020:5434",
CVEId = "CVE-2020-13867",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "targetcli",Version = "2.1.53-1.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5434)

RHSA_2020_5435_Rule = VulRule:new()

RHSA_2020_5435 = RHSA_2020_5435_Rule:new{
PatchId = "RHSA-2020:5435",
CVEId = "CVE-2020-14019",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-rtslib",Version = "2.1.74-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-rtslib-doc",Version = "2.1.74-1.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5435)

RHSA_2020_5437_Rule = VulRule:new()

RHSA_2020_5437 = RHSA_2020_5437_Rule:new{
PatchId = "RHSA-2020:5437",
CVEId = "CVE-2020-25643",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-bootwrapper",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump-devel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python-perf",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5437)

RHSA_2020_5439_Rule = VulRule:new()

RHSA_2020_5439 = RHSA_2020_5439_Rule:new{
PatchId = "RHSA-2020:5439",
CVEId = "CVE-2020-1472",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ctdb",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ctdb-tests",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libsmbclient",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libsmbclient-devel",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libwbclient",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libwbclient-devel",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-client",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-client-libs",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-common",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-common-libs",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-common-tools",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-dc",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-dc-libs",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-devel",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-krb5-printing",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-libs",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-pidl",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-python",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-python-test",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-test",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-test-libs",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-vfs-glusterfs",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winbind",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winbind-clients",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winbind-krb5-locator",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winbind-modules",Version = "4.10.16-9.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5439)

RHSA_2020_5443_Rule = VulRule:new()

RHSA_2020_5443 = RHSA_2020_5443_Rule:new{
PatchId = "RHSA-2020:5443",
CVEId = "CVE-2016-5766",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gd",Version = "2.0.35-27.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gd-devel",Version = "2.0.35-27.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gd-progs",Version = "2.0.35-27.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5443)

RHSA_2020_5453_Rule = VulRule:new()

RHSA_2020_5453 = RHSA_2020_5453_Rule:new{
PatchId = "RHSA-2020:5453",
CVEId = "CVE-2020-25654",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pacemaker",Version = "1.1.23-1.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pacemaker-cli",Version = "1.1.23-1.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pacemaker-cluster-libs",Version = "1.1.23-1.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pacemaker-cts",Version = "1.1.23-1.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pacemaker-doc",Version = "1.1.23-1.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pacemaker-libs",Version = "1.1.23-1.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pacemaker-libs-devel",Version = "1.1.23-1.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pacemaker-nagios-plugins-metadata",Version = "1.1.23-1.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pacemaker-remote",Version = "1.1.23-1.el7_9.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5453)

RHSA_2020_5561_Rule = VulRule:new()

RHSA_2020_5561 = RHSA_2020_5561_Rule:new{
PatchId = "RHSA-2020:5561",
CVEId = "CVE-2020-35113",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "78.6.0-1.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5561)

RHSA_2020_5566_Rule = VulRule:new()

RHSA_2020_5566 = RHSA_2020_5566_Rule:new{
PatchId = "RHSA-2020:5566",
CVEId = "CVE-2020-1971",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl",Version = "1.0.2k-21.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl-devel",Version = "1.0.2k-21.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl-libs",Version = "1.0.2k-21.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl-perl",Version = "1.0.2k-21.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl-static",Version = "1.0.2k-21.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5566)

RHSA_2020_5585_Rule = VulRule:new()

RHSA_2020_5585 = RHSA_2020_5585_Rule:new{
PatchId = "RHSA-2020:5585",
CVEId = "CVE-2020-2590",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-ibm",Version = "1.8.0.6.20-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-ibm-demo",Version = "1.8.0.6.20-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-ibm-devel",Version = "1.8.0.6.20-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-ibm-jdbc",Version = "1.8.0.6.20-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-ibm-plugin",Version = "1.8.0.6.20-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-ibm-src",Version = "1.8.0.6.20-1jpp.1.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5585)

RHSA_2020_5586_Rule = VulRule:new()

RHSA_2020_5586 = RHSA_2020_5586_Rule:new{
PatchId = "RHSA-2020:5586",
CVEId = "CVE-2020-14796",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm",Version = "1.7.1.4.75-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-demo",Version = "1.7.1.4.75-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-devel",Version = "1.7.1.4.75-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-jdbc",Version = "1.7.1.4.75-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-plugin",Version = "1.7.1.4.75-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-src",Version = "1.7.1.4.75-1jpp.1.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5586)

RHSA_2020_5618_Rule = VulRule:new()

RHSA_2020_5618 = RHSA_2020_5618_Rule:new{
PatchId = "RHSA-2020:5618",
CVEId = "CVE-2020-35111",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "78.6.0-1.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5618)

RHSA_2021_0024_Rule = VulRule:new()

RHSA_2021_0024 = RHSA_2021_0024_Rule:new{
PatchId = "RHSA-2021:0024",
CVEId = "CVE-2020-29599",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ImageMagick",Version = "6.9.10.68-5.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ImageMagick-c++",Version = "6.9.10.68-5.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ImageMagick-c++-devel",Version = "6.9.10.68-5.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ImageMagick-devel",Version = "6.9.10.68-5.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ImageMagick-doc",Version = "6.9.10.68-5.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ImageMagick-perl",Version = "6.9.10.68-5.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0024)

RHSA_2021_0053_Rule = VulRule:new()

RHSA_2021_0053 = RHSA_2021_0053_Rule:new{
PatchId = "RHSA-2021:0053",
CVEId = "CVE-2020-16044",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "78.6.1-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "78.6.1-1.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0053)

RHSA_2021_0153_Rule = VulRule:new()

RHSA_2021_0153 = RHSA_2021_0153_Rule:new{
PatchId = "RHSA-2021:0153",
CVEId = "CVE-2020-25686",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dnsmasq",Version = "2.76-16.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dnsmasq-utils",Version = "2.76-16.el7_9.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0153)

RHSA_2021_0162_Rule = VulRule:new()

RHSA_2021_0162 = RHSA_2021_0162_Rule:new{
PatchId = "RHSA-2021:0162",
CVEId = "CVE-2020-26217",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xstream",Version = "1.3.1-12.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xstream-javadoc",Version = "1.3.1-12.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0162)

RHSA_2021_0221_Rule = VulRule:new()

RHSA_2021_0221 = RHSA_2021_0221_Rule:new{
PatchId = "RHSA-2021:0221",
CVEId = "CVE-2021-3156",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "sudo",Version = "1.8.23-10.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "sudo-devel",Version = "1.8.23-10.el7_9.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0221)

RHSA_2021_0290_Rule = VulRule:new()

RHSA_2021_0290 = RHSA_2021_0290_Rule:new{
PatchId = "RHSA-2021:0290",
CVEId = "CVE-2021-23964",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "78.7.0-2.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0290)

RHSA_2021_0297_Rule = VulRule:new()

RHSA_2021_0297 = RHSA_2021_0297_Rule:new{
PatchId = "RHSA-2021:0297",
CVEId = "CVE-2021-23960",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "78.7.0-1.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0297)

RHSA_2021_0336_Rule = VulRule:new()

RHSA_2021_0336 = RHSA_2021_0336_Rule:new{
PatchId = "RHSA-2021:0336",
CVEId = "CVE-2020-35513",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-bootwrapper",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump-devel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python-perf",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0336)

RHSA_2021_0339_Rule = VulRule:new()

RHSA_2021_0339 = RHSA_2021_0339_Rule:new{
PatchId = "RHSA-2021:0339",
CVEId = "CVE-2020-12321",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl100-firmware",Version = "39.31.5.1-80.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl1000-firmware",Version = "39.31.5.1-80.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl105-firmware",Version = "18.168.6.1-80.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl135-firmware",Version = "18.168.6.1-80.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl2000-firmware",Version = "18.168.6.1-80.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl2030-firmware",Version = "18.168.6.1-80.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl3160-firmware",Version = "25.30.13.0-80.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl3945-firmware",Version = "15.32.2.9-80.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl4965-firmware",Version = "228.61.2.24-80.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl5000-firmware",Version = "8.83.5.1_1-80.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl5150-firmware",Version = "8.24.2.2-80.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl6000-firmware",Version = "9.221.4.1-80.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl6000g2a-firmware",Version = "18.168.6.1-80.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl6000g2b-firmware",Version = "18.168.6.1-80.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl6050-firmware",Version = "41.28.5.1-80.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl7260-firmware",Version = "25.30.13.0-80.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "linux-firmware",Version = "20200421-80.git78c0348.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0339)

RHSA_2021_0343_Rule = VulRule:new()

RHSA_2021_0343 = RHSA_2021_0343_Rule:new{
PatchId = "RHSA-2021:0343",
CVEId = "CVE-2020-12723",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl",Version = "5.16.3-299.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-CPAN",Version = "1.9800-299.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-ExtUtils-CBuilder",Version = "0.28.2.6-299.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-ExtUtils-Embed",Version = "1.30-299.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-ExtUtils-Install",Version = "1.58-299.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-IO-Zlib",Version = "1.10-299.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Locale-Maketext-Simple",Version = "0.21-299.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Module-CoreList",Version = "2.76.02-299.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Module-Loaded",Version = "0.08-299.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Object-Accessor",Version = "0.42-299.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Package-Constants",Version = "0.02-299.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Pod-Escapes",Version = "1.04-299.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Time-Piece",Version = "1.20.1-299.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-core",Version = "5.16.3-299.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-devel",Version = "5.16.3-299.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-libs",Version = "5.16.3-299.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-macros",Version = "5.16.3-299.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-tests",Version = "5.16.3-299.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0343)

RHSA_2021_0346_Rule = VulRule:new()

RHSA_2021_0346 = RHSA_2021_0346_Rule:new{
PatchId = "RHSA-2021:0346",
CVEId = "CVE-2020-16092",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-img-ma",Version = "2.12.0-48.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-common-ma",Version = "2.12.0-48.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-ma",Version = "2.12.0-48.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-tools-ma",Version = "2.12.0-48.el7_9.2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0346)

RHSA_2021_0347_Rule = VulRule:new()

RHSA_2021_0347 = RHSA_2021_0347_Rule:new{
PatchId = "RHSA-2021:0347",
CVEId = "CVE-2020-13765",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-img",Version = "1.5.3-175.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm",Version = "1.5.3-175.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-common",Version = "1.5.3-175.el7_9.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-tools",Version = "1.5.3-175.el7_9.3",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0347)

RHSA_2021_0348_Rule = VulRule:new()

RHSA_2021_0348 = RHSA_2021_0348_Rule:new{
PatchId = "RHSA-2021:0348",
CVEId = "CVE-2020-29573",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc",Version = "2.17-322.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-common",Version = "2.17-322.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-devel",Version = "2.17-322.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-headers",Version = "2.17-322.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-static",Version = "2.17-322.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-utils",Version = "2.17-322.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nscd",Version = "2.17-322.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0348)

RHSA_2021_0411_Rule = VulRule:new()

RHSA_2021_0411 = RHSA_2021_0411_Rule:new{
PatchId = "RHSA-2021:0411",
CVEId = "CVE-2021-21261",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "flatpak",Version = "1.0.9-10.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "flatpak-builder",Version = "1.0.0-10.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "flatpak-devel",Version = "1.0.9-10.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "flatpak-libs",Version = "1.0.9-10.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0411)

RHSA_2021_0617_Rule = VulRule:new()

RHSA_2021_0617 = RHSA_2021_0617_Rule:new{
PatchId = "RHSA-2021:0617",
CVEId = "CVE-2021-27135",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xterm",Version = "295-3.el7_9.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0617)

RHSA_2021_0656_Rule = VulRule:new()

RHSA_2021_0656 = RHSA_2021_0656_Rule:new{
PatchId = "RHSA-2021:0656",
CVEId = "CVE-2021-23978",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "78.8.0-1.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0656)

RHSA_2021_0661_Rule = VulRule:new()

RHSA_2021_0661 = RHSA_2021_0661_Rule:new{
PatchId = "RHSA-2021:0661",
CVEId = "CVE-2021-23973",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "78.8.0-1.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0661)

RHSA_2021_0671_Rule = VulRule:new()

RHSA_2021_0671 = RHSA_2021_0671_Rule:new{
PatchId = "RHSA-2021:0671",
CVEId = "CVE-2020-8625",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind",Version = "9.11.4-26.P2.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-chroot",Version = "9.11.4-26.P2.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-devel",Version = "9.11.4-26.P2.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-export-devel",Version = "9.11.4-26.P2.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-export-libs",Version = "9.11.4-26.P2.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-libs",Version = "9.11.4-26.P2.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-libs-lite",Version = "9.11.4-26.P2.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-license",Version = "9.11.4-26.P2.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-lite-devel",Version = "9.11.4-26.P2.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11",Version = "9.11.4-26.P2.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-devel",Version = "9.11.4-26.P2.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-libs",Version = "9.11.4-26.P2.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-utils",Version = "9.11.4-26.P2.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-sdb",Version = "9.11.4-26.P2.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-sdb-chroot",Version = "9.11.4-26.P2.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-utils",Version = "9.11.4-26.P2.el7_9.4",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0671)

RHSA_2021_0699_Rule = VulRule:new()

RHSA_2021_0699 = RHSA_2021_0699_Rule:new{
PatchId = "RHSA-2021:0699",
CVEId = "CVE-2021-20233",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2",Version = "2.02-0.87.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-common",Version = "2.02-0.87.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-aa64-modules",Version = "2.02-0.87.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-ia32",Version = "2.02-0.87.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-ia32-cdboot",Version = "2.02-0.87.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-ia32-modules",Version = "2.02-0.87.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-x64",Version = "2.02-0.87.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-x64-cdboot",Version = "2.02-0.87.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-x64-modules",Version = "2.02-0.87.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-pc",Version = "2.02-0.87.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-pc-modules",Version = "2.02-0.87.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-ppc-modules",Version = "2.02-0.87.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-ppc64",Version = "2.02-0.87.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-ppc64-modules",Version = "2.02-0.87.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-ppc64le",Version = "2.02-0.87.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-ppc64le-modules",Version = "2.02-0.87.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-tools",Version = "2.02-0.87.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-tools-extra",Version = "2.02-0.87.el7_9.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-tools-minimal",Version = "2.02-0.87.el7_9.2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0699)

RHSA_2021_0717_Rule = VulRule:new()

RHSA_2021_0717 = RHSA_2021_0717_Rule:new{
PatchId = "RHSA-2021:0717",
CVEId = "CVE-2020-2773",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-ibm",Version = "1.8.0.6.25-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-ibm-demo",Version = "1.8.0.6.25-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-ibm-devel",Version = "1.8.0.6.25-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-ibm-jdbc",Version = "1.8.0.6.25-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-ibm-plugin",Version = "1.8.0.6.25-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-ibm-src",Version = "1.8.0.6.25-1jpp.1.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0717)

RHSA_2021_0733_Rule = VulRule:new()

RHSA_2021_0733 = RHSA_2021_0733_Rule:new{
PatchId = "RHSA-2021:0733",
CVEId = "CVE-2020-27221",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm",Version = "1.7.1.4.80-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-demo",Version = "1.7.1.4.80-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-devel",Version = "1.7.1.4.80-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-jdbc",Version = "1.7.1.4.80-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-plugin",Version = "1.7.1.4.80-1jpp.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.1-ibm-src",Version = "1.7.1.4.80-1jpp.1.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0733)

RHSA_2021_0742_Rule = VulRule:new()

RHSA_2021_0742 = RHSA_2021_0742_Rule:new{
PatchId = "RHSA-2021:0742",
CVEId = "CVE-2021-26937",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "screen",Version = "4.1.0-0.27.20120314git3c2946.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0742)

RHSA_2021_0808_Rule = VulRule:new()

RHSA_2021_0808 = RHSA_2021_0808_Rule:new{
PatchId = "RHSA-2021:0808",
CVEId = "CVE-2021-27803",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "wpa_supplicant",Version = "2.6-12.el7_9.2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0808)

RHSA_2021_0851_Rule = VulRule:new()

RHSA_2021_0851 = RHSA_2021_0851_Rule:new{
PatchId = "RHSA-2021:0851",
CVEId = "CVE-2021-20179",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pki-base",Version = "10.5.18-12.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pki-base-java",Version = "10.5.18-12.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pki-ca",Version = "10.5.18-12.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pki-javadoc",Version = "10.5.18-12.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pki-kra",Version = "10.5.18-12.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pki-server",Version = "10.5.18-12.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pki-symkey",Version = "10.5.18-12.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pki-tools",Version = "10.5.18-12.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0851)

RHSA_2021_0856_Rule = VulRule:new()

RHSA_2021_0856 = RHSA_2021_0856_Rule:new{
PatchId = "RHSA-2021:0856",
CVEId = "CVE-2021-20265",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-bootwrapper",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump-devel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python-perf",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0856)

RHSA_2021_0860_Rule = VulRule:new()

RHSA_2021_0860 = RHSA_2021_0860_Rule:new{
PatchId = "RHSA-2021:0860",
CVEId = "CVE-2020-11023",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipa-client",Version = "4.6.8-5.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipa-client-common",Version = "4.6.8-5.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipa-common",Version = "4.6.8-5.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipa-python-compat",Version = "4.6.8-5.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipa-server",Version = "4.6.8-5.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipa-server-common",Version = "4.6.8-5.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipa-server-dns",Version = "4.6.8-5.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ipa-server-trust-ad",Version = "4.6.8-5.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python2-ipaclient",Version = "4.6.8-5.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python2-ipalib",Version = "4.6.8-5.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python2-ipaserver",Version = "4.6.8-5.el7_9.4",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0860)

RHSA_2021_0862_Rule = VulRule:new()

RHSA_2021_0862 = RHSA_2021_0862_Rule:new{
PatchId = "RHSA-2021:0862",
CVEId = "CVE-2020-29661",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160",Version = "1-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.2.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.2.1.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.2.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160_2_1",Version = "1-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160_2_2",Version = "1-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160_6_1",Version = "1-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160_11_1",Version = "1-2.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160_15_2",Version = "1-2.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0862)

RHSA_2021_0992_Rule = VulRule:new()

RHSA_2021_0992 = RHSA_2021_0992_Rule:new{
PatchId = "RHSA-2021:0992",
CVEId = "CVE-2021-23987",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "78.9.0-1.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0992)

RHSA_2021_0996_Rule = VulRule:new()

RHSA_2021_0996 = RHSA_2021_0996_Rule:new{
PatchId = "RHSA-2021:0996",
CVEId = "CVE-2021-23984",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "78.9.0-3.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0996)

RHSA_2021_1002_Rule = VulRule:new()

RHSA_2021_1002 = RHSA_2021_1002_Rule:new{
PatchId = "RHSA-2021:1002",
CVEId = "CVE-2021-21381",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "flatpak",Version = "1.0.9-11.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "flatpak-builder",Version = "1.0.0-11.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "flatpak-devel",Version = "1.0.9-11.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "flatpak-libs",Version = "1.0.9-11.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1002)

RHSA_2021_1069_Rule = VulRule:new()

RHSA_2021_1069 = RHSA_2021_1069_Rule:new{
PatchId = "RHSA-2021:1069",
CVEId = "CVE-2021-27365",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160",Version = "1-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.2.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.2.1.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.2.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160_2_1",Version = "1-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160_2_2",Version = "1-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160_6_1",Version = "1-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160_11_1",Version = "1-4.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160_15_2",Version = "1-4.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160_21_1",Version = "1-2.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1069)

RHSA_2021_1071_Rule = VulRule:new()

RHSA_2021_1071 = RHSA_2021_1071_Rule:new{
PatchId = "RHSA-2021:1071",
CVEId = "CVE-2021-27364",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-bootwrapper",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump-devel",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python-perf",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1071)

RHSA_2021_1072_Rule = VulRule:new()

RHSA_2021_1072 = RHSA_2021_1072_Rule:new{
PatchId = "RHSA-2021:1072",
CVEId = "CVE-2021-20277",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ldb-tools",Version = "1.5.4-2.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libldb",Version = "1.5.4-2.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libldb-devel",Version = "1.5.4-2.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pyldb",Version = "1.5.4-2.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "pyldb-devel",Version = "1.5.4-2.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1072)

RHSA_2021_1135_Rule = VulRule:new()

RHSA_2021_1135 = RHSA_2021_1135_Rule:new{
PatchId = "RHSA-2021:1135",
CVEId = "CVE-2020-25097",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "squid",Version = "3.5.20-17.el7_9.6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "squid-migration-script",Version = "3.5.20-17.el7_9.6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "squid-sysvinit",Version = "3.5.20-17.el7_9.6",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1135)

RHSA_2021_1145_Rule = VulRule:new()

RHSA_2021_1145 = RHSA_2021_1145_Rule:new{
PatchId = "RHSA-2021:1145",
CVEId = "CVE-2021-20305",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nettle",Version = "2.7.1-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nettle-devel",Version = "2.7.1-9.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1145)

RHSA_2021_1192_Rule = VulRule:new()

RHSA_2021_1192 = RHSA_2021_1192_Rule:new{
PatchId = "RHSA-2021:1192",
CVEId = "CVE-2021-29950",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "78.9.1-1.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1192)

RHSA_2021_1297_Rule = VulRule:new()

RHSA_2021_1297 = RHSA_2021_1297_Rule:new{
PatchId = "RHSA-2021:1297",
CVEId = "CVE-2021-2163",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk",Version = "11.0.11.0.9-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-demo",Version = "11.0.11.0.9-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-devel",Version = "11.0.11.0.9-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-headless",Version = "11.0.11.0.9-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-javadoc",Version = "11.0.11.0.9-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-javadoc-zip",Version = "11.0.11.0.9-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-jmods",Version = "11.0.11.0.9-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-src",Version = "11.0.11.0.9-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-11-openjdk-static-libs",Version = "11.0.11.0.9-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk",Version = "1.8.0.292.b10-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-accessibility",Version = "1.8.0.292.b10-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-demo",Version = "1.8.0.292.b10-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-devel",Version = "1.8.0.292.b10-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-headless",Version = "1.8.0.292.b10-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-javadoc",Version = "1.8.0.292.b10-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-javadoc-zip",Version = "1.8.0.292.b10-1.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-src",Version = "1.8.0.292.b10-1.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1297)

RHSA_2021_1350_Rule = VulRule:new()

RHSA_2021_1350 = RHSA_2021_1350_Rule:new{
PatchId = "RHSA-2021:1350",
CVEId = "CVE-2021-29948",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "78.10.0-1.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1350)

RHSA_2021_1354_Rule = VulRule:new()

RHSA_2021_1354 = RHSA_2021_1354_Rule:new{
PatchId = "RHSA-2021:1354",
CVEId = "CVE-2021-21350",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xstream",Version = "1.3.1-13.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xstream-javadoc",Version = "1.3.1-13.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1354)

RHSA_2021_1363_Rule = VulRule:new()

RHSA_2021_1363 = RHSA_2021_1363_Rule:new{
PatchId = "RHSA-2021:1363",
CVEId = "CVE-2021-29946",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "78.10.0-1.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1363)

RHSA_2021_1384_Rule = VulRule:new()

RHSA_2021_1384 = RHSA_2021_1384_Rule:new{
PatchId = "RHSA-2021:1384",
CVEId = "CVE-2020-25648",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nss",Version = "3.53.1-7.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nss-devel",Version = "3.53.1-7.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nss-pkcs11-devel",Version = "3.53.1-7.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nss-sysinit",Version = "3.53.1-7.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "nss-tools",Version = "3.53.1-7.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1384)

RHSA_2021_1389_Rule = VulRule:new()

RHSA_2021_1389 = RHSA_2021_1389_Rule:new{
PatchId = "RHSA-2021:1389",
CVEId = "CVE-2020-25692",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openldap",Version = "2.4.44-23.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openldap-clients",Version = "2.4.44-23.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openldap-devel",Version = "2.4.44-23.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openldap-servers",Version = "2.4.44-23.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "openldap-servers-sql",Version = "2.4.44-23.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1389)

RHSA_2021_1469_Rule = VulRule:new()

RHSA_2021_1469 = RHSA_2021_1469_Rule:new{
PatchId = "RHSA-2021:1469",
CVEId = "CVE-2021-25215",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind",Version = "9.11.4-26.P2.el7_9.5",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-chroot",Version = "9.11.4-26.P2.el7_9.5",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-devel",Version = "9.11.4-26.P2.el7_9.5",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-export-devel",Version = "9.11.4-26.P2.el7_9.5",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-export-libs",Version = "9.11.4-26.P2.el7_9.5",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-libs",Version = "9.11.4-26.P2.el7_9.5",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-libs-lite",Version = "9.11.4-26.P2.el7_9.5",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-license",Version = "9.11.4-26.P2.el7_9.5",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-lite-devel",Version = "9.11.4-26.P2.el7_9.5",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11",Version = "9.11.4-26.P2.el7_9.5",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-devel",Version = "9.11.4-26.P2.el7_9.5",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-libs",Version = "9.11.4-26.P2.el7_9.5",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-utils",Version = "9.11.4-26.P2.el7_9.5",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-sdb",Version = "9.11.4-26.P2.el7_9.5",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-sdb-chroot",Version = "9.11.4-26.P2.el7_9.5",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-utils",Version = "9.11.4-26.P2.el7_9.5",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1469)

RHSA_2021_1512_Rule = VulRule:new()

RHSA_2021_1512 = RHSA_2021_1512_Rule:new{
PatchId = "RHSA-2021:1512",
CVEId = "CVE-2020-25695",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql",Version = "9.2.24-6.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-contrib",Version = "9.2.24-6.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-devel",Version = "9.2.24-6.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-docs",Version = "9.2.24-6.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-libs",Version = "9.2.24-6.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-plperl",Version = "9.2.24-6.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-plpython",Version = "9.2.24-6.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-pltcl",Version = "9.2.24-6.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-server",Version = "9.2.24-6.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-static",Version = "9.2.24-6.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-test",Version = "9.2.24-6.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-upgrade",Version = "9.2.24-6.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1512)

RHSA_2021_2032_Rule = VulRule:new()

RHSA_2021_2032 = RHSA_2021_2032_Rule:new{
PatchId = "RHSA-2021:2032",
CVEId = "CVE-2021-3480",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "slapi-nis",Version = "0.56.5-4.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2032)

RHSA_2021_2033_Rule = VulRule:new()

RHSA_2021_2033 = RHSA_2021_2033_Rule:new{
PatchId = "RHSA-2021:2033",
CVEId = "CVE-2021-3472",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-Xdmx",Version = "1.20.4-16.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-Xephyr",Version = "1.20.4-16.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-Xnest",Version = "1.20.4-16.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-Xorg",Version = "1.20.4-16.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-Xvfb",Version = "1.20.4-16.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-Xwayland",Version = "1.20.4-16.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-common",Version = "1.20.4-16.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-devel",Version = "1.20.4-16.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-source",Version = "1.20.4-16.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2033)

RHSA_2021_2147_Rule = VulRule:new()

RHSA_2021_2147 = RHSA_2021_2147_Rule:new{
PatchId = "RHSA-2021:2147",
CVEId = "CVE-2021-27219",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2",Version = "2.56.1-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-devel",Version = "2.56.1-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-doc",Version = "2.56.1-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-fam",Version = "2.56.1-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-static",Version = "2.56.1-9.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-tests",Version = "2.56.1-9.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2147)

RHSA_2021_2206_Rule = VulRule:new()

RHSA_2021_2206 = RHSA_2021_2206_Rule:new{
PatchId = "RHSA-2021:2206",
CVEId = "CVE-2021-29967",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "78.11.0-3.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2206)

RHSA_2021_2260_Rule = VulRule:new()

RHSA_2021_2260 = RHSA_2021_2260_Rule:new{
PatchId = "RHSA-2021:2260",
CVEId = "CVE-2020-36329",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libwebp",Version = "0.3.0-10.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libwebp-devel",Version = "0.3.0-10.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libwebp-java",Version = "0.3.0-10.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libwebp-tools",Version = "0.3.0-10.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2260)

RHSA_2021_2263_Rule = VulRule:new()

RHSA_2021_2263 = RHSA_2021_2263_Rule:new{
PatchId = "RHSA-2021:2263",
CVEId = "CVE-2021-29957",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "78.11.0-1.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2263)

RHSA_2021_2285_Rule = VulRule:new()

RHSA_2021_2285 = RHSA_2021_2285_Rule:new{
PatchId = "RHSA-2021:2285",
CVEId = "CVE-2021-3347",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160",Version = "1-6.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.2.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.2.1.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.2.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160_2_1",Version = "1-6.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.2.2.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160_2_2",Version = "1-6.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.6.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160_6_1",Version = "1-6.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.11.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160_11_1",Version = "1-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.15.2.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160_15_2",Version = "1-5.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.21.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160_21_1",Version = "1-3.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.24.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160_24_1",Version = "1-1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.25.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.25.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "3.10.0-1160.25.1.el7",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.25.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.25.1.el7",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-3_10_0-1160_25_1",Version = "1-1.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2285)

RHSA_2021_2305_Rule = VulRule:new()

RHSA_2021_2305 = RHSA_2021_2305_Rule:new{
PatchId = "RHSA-2021:2305",
CVEId = "CVE-2020-24513",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "microcode_ctl",Version = "2.1-73.9.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2305)

RHSA_2021_2313_Rule = VulRule:new()

RHSA_2021_2313 = RHSA_2021_2313_Rule:new{
PatchId = "RHSA-2021:2313",
CVEId = "CVE-2021-20254",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ctdb",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ctdb-tests",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libsmbclient",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libsmbclient-devel",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libwbclient",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "libwbclient-devel",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-client",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-client-libs",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-common",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-common-libs",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-common-tools",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-dc",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-dc-libs",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-devel",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-krb5-printing",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-libs",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-pidl",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-python",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-python-test",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-test",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-test-libs",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-vfs-glusterfs",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winbind",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winbind-clients",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winbind-krb5-locator",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winbind-modules",Version = "4.10.16-15.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2313)

RHSA_2021_2314_Rule = VulRule:new()

RHSA_2021_2314 = RHSA_2021_2314_Rule:new{
PatchId = "RHSA-2021:2314",
CVEId = "CVE-2020-8648",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-bootwrapper",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump-devel",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python-perf",Version = "3.10.0-1160.31.1.el7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2314)

RHSA_2021_2318_Rule = VulRule:new()

RHSA_2021_2318 = RHSA_2021_2318_Rule:new{
PatchId = "RHSA-2021:2318",
CVEId = "CVE-2021-3504",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "hivex",Version = "1.3.10-6.11.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "hivex-devel",Version = "1.3.10-6.11.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ocaml-hivex",Version = "1.3.10-6.11.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ocaml-hivex-devel",Version = "1.3.10-6.11.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-hivex",Version = "1.3.10-6.11.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "python-hivex",Version = "1.3.10-6.11.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "ruby-hivex",Version = "1.3.10-6.11.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2318)

RHSA_2021_2322_Rule = VulRule:new()

RHSA_2021_2322 = RHSA_2021_2322_Rule:new{
PatchId = "RHSA-2021:2322",
CVEId = "CVE-2020-29443",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-img",Version = "1.5.3-175.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm",Version = "1.5.3-175.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-common",Version = "1.5.3-175.el7_9.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-tools",Version = "1.5.3-175.el7_9.4",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2322)

RHSA_2021_2323_Rule = VulRule:new()

RHSA_2021_2323 = RHSA_2021_2323_Rule:new{
PatchId = "RHSA-2021:2323",
CVEId = "CVE-2020-35518",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "389-ds-base",Version = "1.3.10.2-12.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "389-ds-base-devel",Version = "1.3.10.2-12.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "389-ds-base-libs",Version = "1.3.10.2-12.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "389-ds-base-snmp",Version = "1.3.10.2-12.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2323)

RHSA_2021_2328_Rule = VulRule:new()

RHSA_2021_2328 = RHSA_2021_2328_Rule:new{
PatchId = "RHSA-2021:2328",
CVEId = "CVE-2020-36328",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt5-qtimageformats",Version = "5.9.7-2.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "qt5-qtimageformats-doc",Version = "5.9.7-2.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2328)

RHSA_2021_2357_Rule = VulRule:new()

RHSA_2021_2357 = RHSA_2021_2357_Rule:new{
PatchId = "RHSA-2021:2357",
CVEId = "CVE-2021-25217",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dhclient",Version = "4.2.5-83.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dhcp",Version = "4.2.5-83.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dhcp-common",Version = "4.2.5-83.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dhcp-devel",Version = "4.2.5-83.el7_9.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "dhcp-libs",Version = "4.2.5-83.el7_9.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2357)

RHSA_2021_2397_Rule = VulRule:new()

RHSA_2021_2397 = RHSA_2021_2397_Rule:new{
PatchId = "RHSA-2021:2397",
CVEId = "CVE-2021-32027",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql",Version = "9.2.24-7.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-contrib",Version = "9.2.24-7.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-devel",Version = "9.2.24-7.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-docs",Version = "9.2.24-7.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-libs",Version = "9.2.24-7.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-plperl",Version = "9.2.24-7.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-plpython",Version = "9.2.24-7.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-pltcl",Version = "9.2.24-7.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-server",Version = "9.2.24-7.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-static",Version = "9.2.24-7.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-test",Version = "9.2.24-7.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-upgrade",Version = "9.2.24-7.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2397)

RHSA_2021_2417_Rule = VulRule:new()

RHSA_2021_2417 = RHSA_2021_2417_Rule:new{
PatchId = "RHSA-2021:2417",
CVEId = "CVE-2021-33516",
criteria = {
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gupnp",Version = "1.0.2-6.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gupnp-devel",Version = "1.0.2-6.el7_9",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel7,
logic = {
{Type = BaseType.linux_kernel,filename = "gupnp-docs",Version = "1.0.2-6.el7_9",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2417)




local allrule = GetModule()


local result = {}

function ScanFun()
    local result = "{\"result\":["
	local bfind = false
---扫描所有规则
    for _, v in pairs(allrule) do 
		if v:Scan() then
			local PatchId,PatchUrl,PatchFull,CVEId,CVEUrl,CVEUrlFull,description,CVEType = v:createScanResult()
			if bfind then
				result = table.concat{result, ",{\"Patchid\":\"", PatchId, "\",\"PatchUrl\":\"",PatchUrl,"\",\"PatchFull\":\"",PatchFull,"\",\"CveId\":\"",CVEId,"\",\"CVEUrl\":\"",CVEUrl,"\",\"CVEUrlFull\":\"",CVEUrlFull,"\",\"Type\":\"",CVEType,"\",\"desc\":\"", description, "\"}"}
			else
				result = table.concat{result, "{\"Patchid\":\"", PatchId, "\",\"PatchUrl\":\"",PatchUrl,"\",\"PatchFull\":\"",PatchFull,"\",\"CveId\":\"",CVEId,"\",\"CVEUrl\":\"",CVEUrl,"\",\"CVEUrlFull\":\"",CVEUrlFull,"\",\"Type\":\"",CVEType,"\",\"desc\":\"", description, "\"}"}
			end
			bfind = true
		end 
	end

	result = table.concat{result, "]}"}
    return result
end

--ScanFun()
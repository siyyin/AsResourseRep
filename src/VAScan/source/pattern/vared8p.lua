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
            for _, value in pairs(tab.logic) do
                local Oper = value["Oper"]
                local Type = value["Type"]
                local filename = value["filename"]
                local Version = value["Version"]
                if Type == BaseType.kernel_running then
                    if FileVersionCompare(GetKernelRuning(), Version) ~= Oper then
                        Bfind = false
                        break
                    end
                elseif Type == BaseType.kernel_boot then
                    if FileVersionCompare(GetKernelBoot(), Version) ~= Oper then
                        Bfind = false
                        break
                    end
                elseif Type == BaseType.linux_kernel then
                    if FileVersionCompare(GetFileVersion(filename), Version) ~= Oper then
                        Bfind = false
                        break
                    end
                end

                ---for key0, value0 in pairs(value) do
                ---	print("\t", key0, "===>", value0)
                ---end
            end

            if Bfind then
                ---print(self.CVEId)
                ---print(tab.OS)
                return true
            end
        end
    end
    return false
end

function VulRule:createScanResult() return self.PatchId,self.PatchUrl,self.PatchFull,self.CVEId,self.CVEUrl,self.CVEUrlFull,self.description,self.CVEType end

RHBA_2020_1376_Rule = VulRule:new()

RHBA_2020_1376 = RHBA_2020_1376_Rule:new{
PatchId = "RHBA-2020:1376",
CVEId = "CVE-2019-20892",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp",Version = "5.8-12.el8_1.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-agent-libs",Version = "5.8-12.el8_1.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-devel",Version = "5.8-12.el8_1.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-libs",Version = "5.8-12.el8_1.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-utils",Version = "5.8-12.el8_1.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHBA_2020_1376)

RHBA_2021_0621_Rule = VulRule:new()

RHBA_2021_0621 = RHBA_2021_0621_Rule:new{
PatchId = "RHBA-2021:0621",
CVEId = "CVE-2020-8696",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "microcode_ctl",Version = "20200609-2.20210216.1.el8_3",Oper = BaseOper.lessthan}}}}
}

AddModule(RHBA_2021_0621)

RHEA_2020_4505_Rule = VulRule:new()

RHEA_2020_4505 = RHEA_2020_4505_Rule:new{
PatchId = "RHEA-2020:4505",
CVEId = "CVE-2020-14019",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-rtslib",Version = "2.1.73-2.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "target-restore",Version = "2.1.73-2.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHEA_2020_4505)

RHEA_2021_1580_Rule = VulRule:new()

RHEA_2021_1580 = RHEA_2021_1580_Rule:new{
PatchId = "RHEA-2021:1580",
CVEId = "CVE-2017-14502",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bsdtar",Version = "3.3.3-1.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libarchive",Version = "3.3.3-1.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libarchive-devel",Version = "3.3.3-1.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHEA_2021_1580)

RHSA_2020_0271_Rule = VulRule:new()

RHSA_2020_0271 = RHSA_2020_0271_Rule:new{
PatchId = "RHSA-2020:0271",
CVEId = "CVE-2019-18408",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bsdtar",Version = "3.3.2-8.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libarchive",Version = "3.3.2-8.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libarchive-devel",Version = "3.3.2-8.el8_1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0271)

RHSA_2020_0273_Rule = VulRule:new()

RHSA_2020_0273 = RHSA_2020_0273_Rule:new{
PatchId = "RHSA-2020:0273",
CVEId = "CVE-2019-13734",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "lemon",Version = "3.26.0-4.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sqlite",Version = "3.26.0-4.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sqlite-devel",Version = "3.26.0-4.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sqlite-doc",Version = "3.26.0-4.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sqlite-libs",Version = "3.26.0-4.el8_1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0273)

RHSA_2020_0335_Rule = VulRule:new()

RHSA_2020_0335 = RHSA_2020_0335_Rule:new{
PatchId = "RHSA-2020:0335",
CVEId = "CVE-2019-14865",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-common",Version = "2.02-78.el8_1.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-aa64",Version = "2.02-78.el8_1.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-aa64-cdboot",Version = "2.02-78.el8_1.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-aa64-modules",Version = "2.02-78.el8_1.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-ia32",Version = "2.02-78.el8_1.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-ia32-cdboot",Version = "2.02-78.el8_1.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-ia32-modules",Version = "2.02-78.el8_1.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-x64",Version = "2.02-78.el8_1.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-x64-cdboot",Version = "2.02-78.el8_1.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-x64-modules",Version = "2.02-78.el8_1.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-pc",Version = "2.02-78.el8_1.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-pc-modules",Version = "2.02-78.el8_1.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-ppc64le",Version = "2.02-78.el8_1.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-ppc64le-modules",Version = "2.02-78.el8_1.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-tools",Version = "2.02-78.el8_1.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-tools-efi",Version = "2.02-78.el8_1.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-tools-extra",Version = "2.02-78.el8_1.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-tools-minimal",Version = "2.02-78.el8_1.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0335)

RHSA_2020_0339_Rule = VulRule:new()

RHSA_2020_0339 = RHSA_2020_0339_Rule:new{
PatchId = "RHSA-2020:0339",
CVEId = "CVE-2019-19338",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-core",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-cross-headers",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-core",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules-extra",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules-extra",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-core",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-devel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules-extra",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python3-perf",Version = "4.18.0-147.5.1.el8_1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0339)

RHSA_2020_0487_Rule = VulRule:new()

RHSA_2020_0487 = RHSA_2020_0487_Rule:new{
PatchId = "RHSA-2020:0487",
CVEId = "CVE-2019-18634",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sudo",Version = "1.8.25p1-8.el8_1.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0487)

RHSA_2020_0575_Rule = VulRule:new()

RHSA_2020_0575 = RHSA_2020_0575_Rule:new{
PatchId = "RHSA-2020:0575",
CVEId = "CVE-2020-1712",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd",Version = "239-18.el8_1.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-container",Version = "239-18.el8_1.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-devel",Version = "239-18.el8_1.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-journal-remote",Version = "239-18.el8_1.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-libs",Version = "239-18.el8_1.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-pam",Version = "239-18.el8_1.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-tests",Version = "239-18.el8_1.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-udev",Version = "239-18.el8_1.4",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0575)

RHSA_2020_0633_Rule = VulRule:new()

RHSA_2020_0633 = RHSA_2020_0633_Rule:new{
PatchId = "RHSA-2020:0633",
CVEId = "CVE-2020-8597",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "network-scripts-ppp",Version = "2.4.7-26.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "ppp",Version = "2.4.7-26.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "ppp-devel",Version = "2.4.7-26.el8_1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0633)

RHSA_2020_0902_Rule = VulRule:new()

RHSA_2020_0902 = RHSA_2020_0902_Rule:new{
PatchId = "RHSA-2020:0902",
CVEId = "CVE-2020-10531",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "icu",Version = "60.3-2.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libicu",Version = "60.3-2.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libicu-devel",Version = "60.3-2.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libicu-doc",Version = "60.3-2.el8_1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0902)

RHSA_2020_0903_Rule = VulRule:new()

RHSA_2020_0903 = RHSA_2020_0903_Rule:new{
PatchId = "RHSA-2020:0903",
CVEId = "CVE-2019-20044",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "zsh",Version = "5.5.1-6.el8_1.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "zsh-html",Version = "5.5.1-6.el8_1.2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0903)

RHSA_2020_1372_Rule = VulRule:new()

RHSA_2020_1372 = RHSA_2020_1372_Rule:new{
PatchId = "RHSA-2020:1372",
CVEId = "CVE-2019-19527",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-core",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-cross-headers",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-core",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules-extra",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules-extra",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-core",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-devel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules-extra",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python3-perf",Version = "4.18.0-147.8.1.el8_1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1372)

RHSA_2020_1764_Rule = VulRule:new()

RHSA_2020_1764 = RHSA_2020_1764_Rule:new{
PatchId = "RHSA-2020:1764",
CVEId = "CVE-2019-16056",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "platform-python",Version = "3.6.8-23.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "platform-python-debug",Version = "3.6.8-23.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "platform-python-devel",Version = "3.6.8-23.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-idle",Version = "3.6.8-23.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-libs",Version = "3.6.8-23.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-test",Version = "3.6.8-23.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-tkinter",Version = "3.6.8-23.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1764)

RHSA_2020_1765_Rule = VulRule:new()

RHSA_2020_1765 = RHSA_2020_1765_Rule:new{
PatchId = "RHSA-2020:1765",
CVEId = "CVE-2019-8696",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cups",Version = "2.2.6-33.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cups-client",Version = "2.2.6-33.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cups-devel",Version = "2.2.6-33.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cups-filesystem",Version = "2.2.6-33.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cups-ipptool",Version = "2.2.6-33.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cups-libs",Version = "2.2.6-33.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cups-lpd",Version = "2.2.6-33.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1765)

RHSA_2020_1766_Rule = VulRule:new()

RHSA_2020_1766 = RHSA_2020_1766_Rule:new{
PatchId = "RHSA-2020:1766",
CVEId = "CVE-2019-3825",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gvfs",Version = "1.36.2-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gvfs-afc",Version = "1.36.2-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gvfs-afp",Version = "1.36.2-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gvfs-archive",Version = "1.36.2-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gvfs-client",Version = "1.36.2-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gvfs-devel",Version = "1.36.2-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gvfs-fuse",Version = "1.36.2-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gvfs-goa",Version = "1.36.2-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gvfs-gphoto2",Version = "1.36.2-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gvfs-mtp",Version = "1.36.2-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gvfs-smb",Version = "1.36.2-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "baobab",Version = "3.28.0-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "LibRaw",Version = "0.19.5-1.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "LibRaw-devel",Version = "0.19.5-1.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "evince",Version = "3.28.4-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "evince-browser-plugin",Version = "3.28.4-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "evince-libs",Version = "3.28.4-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "evince-nautilus",Version = "3.28.4-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-online-accounts",Version = "3.28.2-1.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-online-accounts-devel",Version = "3.28.2-1.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gtk-update-icon-cache",Version = "3.22.30-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gtk3",Version = "3.22.30-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gtk3-devel",Version = "3.22.30-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gtk3-immodule-xim",Version = "3.22.30-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gsettings-desktop-schemas",Version = "3.32.0-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gsettings-desktop-schemas-devel",Version = "3.32.0-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-session",Version = "3.28.1-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-session-wayland-session",Version = "3.28.1-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-session-xsession",Version = "3.28.1-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-settings-daemon",Version = "3.32.0-9.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-remote-desktop",Version = "0.1.6-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "appstream-data",Version = "8-20191129.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-menus",Version = "3.13.3-11.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-menus-devel",Version = "3.13.3-11.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "nautilus",Version = "3.28.1-12.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "nautilus-devel",Version = "3.28.1-12.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "nautilus-extensions",Version = "3.28.1-12.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-terminal",Version = "3.28.3-1.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-terminal-nautilus",Version = "3.28.3-1.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "accountsservice",Version = "0.6.50-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "accountsservice-devel",Version = "0.6.50-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "accountsservice-libs",Version = "0.6.50-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libxslt",Version = "1.1.32-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libxslt-devel",Version = "1.1.32-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "vinagre",Version = "3.22.0-21.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-boxes",Version = "3.28.5-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-software",Version = "3.30.6-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-software-editor",Version = "3.30.6-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gdm",Version = "3.28.3-29.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "mozjs52",Version = "52.9.0-2.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "mozjs52-devel",Version = "52.9.0-2.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "vala",Version = "0.40.19-1.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "vala-devel",Version = "0.40.19-1.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "mozjs60",Version = "60.9.0-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "mozjs60-devel",Version = "60.9.0-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gjs",Version = "1.56.2-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gjs-devel",Version = "1.56.2-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-tweaks",Version = "3.28.1-7.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "clutter",Version = "1.26.2-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "clutter-devel",Version = "1.26.2-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "clutter-doc",Version = "1.26.2-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-control-center",Version = "3.28.2-19.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-control-center-filesystem",Version = "3.28.2-19.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-shell",Version = "3.32.2-14.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "mutter",Version = "3.32.2-34.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "mutter-devel",Version = "3.32.2-34.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libvncserver",Version = "0.9.11-14.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libvncserver-devel",Version = "0.9.11-14.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1766)

RHSA_2020_1769_Rule = VulRule:new()

RHSA_2020_1769 = RHSA_2020_1769_Rule:new{
PatchId = "RHSA-2020:1769",
CVEId = "CVE-2020-7053",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-core",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-cross-headers",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-core",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules-extra",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules-extra",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-core",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-devel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules-extra",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python3-perf",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1769)

RHSA_2020_1787_Rule = VulRule:new()

RHSA_2020_1787 = RHSA_2020_1787_Rule:new{
PatchId = "RHSA-2020:1787",
CVEId = "CVE-2019-13232",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "unzip",Version = "6.0-43.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1787)

RHSA_2020_1792_Rule = VulRule:new()

RHSA_2020_1792 = RHSA_2020_1792_Rule:new{
PatchId = "RHSA-2020:1792",
CVEId = "CVE-2019-5482",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "curl",Version = "7.61.1-12.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libcurl",Version = "7.61.1-12.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libcurl-devel",Version = "7.61.1-12.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libcurl-minimal",Version = "7.61.1-12.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1792)

RHSA_2020_1794_Rule = VulRule:new()

RHSA_2020_1794 = RHSA_2020_1794_Rule:new{
PatchId = "RHSA-2020:1794",
CVEId = "CVE-2019-3844",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd",Version = "239-29.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-container",Version = "239-29.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-devel",Version = "239-29.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-journal-remote",Version = "239-29.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-libs",Version = "239-29.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-pam",Version = "239-29.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-tests",Version = "239-29.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-udev",Version = "239-29.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1794)

RHSA_2020_1797_Rule = VulRule:new()

RHSA_2020_1797 = RHSA_2020_1797_Rule:new{
PatchId = "RHSA-2020:1797",
CVEId = "CVE-2019-17451",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "binutils",Version = "2.30-73.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "binutils-devel",Version = "2.30-73.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1797)

RHSA_2020_1804_Rule = VulRule:new()

RHSA_2020_1804 = RHSA_2020_1804_Rule:new{
PatchId = "RHSA-2020:1804",
CVEId = "CVE-2019-19234",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sudo",Version = "1.8.29-5.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1804)

RHSA_2020_1810_Rule = VulRule:new()

RHSA_2020_1810 = RHSA_2020_1810_Rule:new{
PatchId = "RHSA-2020:1810",
CVEId = "CVE-2019-8457",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "lemon",Version = "3.26.0-6.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sqlite",Version = "3.26.0-6.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sqlite-devel",Version = "3.26.0-6.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sqlite-doc",Version = "3.26.0-6.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sqlite-libs",Version = "3.26.0-6.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1810)

RHSA_2020_1827_Rule = VulRule:new()

RHSA_2020_1827 = RHSA_2020_1827_Rule:new{
PatchId = "RHSA-2020:1827",
CVEId = "CVE-2018-9251",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libxml2",Version = "2.9.7-7.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libxml2-devel",Version = "2.9.7-7.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-libxml2",Version = "2.9.7-7.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1827)

RHSA_2020_1828_Rule = VulRule:new()

RHSA_2020_1828 = RHSA_2020_1828_Rule:new{
PatchId = "RHSA-2020:1828",
CVEId = "CVE-2019-19126",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "compat-libpthread-nonshared",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-all-langpacks",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-benchtests",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-common",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-devel",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-headers",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-aa",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-af",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-agr",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ak",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-am",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-an",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-anp",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ar",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-as",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ast",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ayc",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-az",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-be",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-bem",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ber",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-bg",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-bhb",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-bho",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-bi",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-bn",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-bo",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-br",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-brx",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-bs",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-byn",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ca",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ce",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-chr",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-cmn",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-crh",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-cs",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-csb",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-cv",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-cy",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-da",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-de",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-doi",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-dsb",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-dv",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-dz",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-el",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-en",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-eo",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-es",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-et",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-eu",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-fa",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ff",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-fi",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-fil",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-fo",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-fr",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-fur",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-fy",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ga",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-gd",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-gez",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-gl",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-gu",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-gv",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ha",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-hak",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-he",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-hi",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-hif",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-hne",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-hr",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-hsb",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ht",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-hu",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-hy",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ia",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-id",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ig",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ik",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-is",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-it",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-iu",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ja",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ka",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-kab",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-kk",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-kl",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-km",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-kn",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ko",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-kok",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ks",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ku",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-kw",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ky",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-lb",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-lg",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-li",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-lij",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ln",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-lo",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-lt",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-lv",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-lzh",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mag",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mai",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mfe",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mg",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mhr",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mi",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-miq",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mjw",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mk",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ml",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mn",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mni",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mr",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ms",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mt",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-my",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-nan",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-nb",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-nds",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ne",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-nhn",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-niu",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-nl",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-nn",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-nr",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-nso",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-oc",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-om",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-or",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-os",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-pa",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-pap",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-pl",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ps",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-pt",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-quz",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-raj",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ro",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ru",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-rw",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sa",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sah",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sat",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sc",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sd",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-se",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sgs",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-shn",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-shs",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-si",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sid",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sk",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sl",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sm",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-so",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sq",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sr",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ss",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-st",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sv",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sw",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-szl",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ta",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tcy",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-te",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tg",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-th",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-the",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ti",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tig",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tk",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tl",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tn",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-to",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tpi",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tr",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ts",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tt",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ug",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-uk",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-unm",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ur",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-uz",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ve",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-vi",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-wa",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-wae",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-wal",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-wo",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-xh",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-yi",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-yo",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-yue",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-yuw",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-zh",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-zu",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-locale-source",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-minimal-langpack",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-nss-devel",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-static",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-utils",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libnsl",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "nscd",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "nss_db",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "nss_hesiod",Version = "2.28-101.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1828)

RHSA_2020_1840_Rule = VulRule:new()

RHSA_2020_1840 = RHSA_2020_1840_Rule:new{
PatchId = "RHSA-2020:1840",
CVEId = "CVE-2019-1563",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl",Version = "1.1.1c-15.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl-devel",Version = "1.1.1c-15.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl-libs",Version = "1.1.1c-15.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl-perl",Version = "1.1.1c-15.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1840)

RHSA_2020_1845_Rule = VulRule:new()

RHSA_2020_1845 = RHSA_2020_1845_Rule:new{
PatchId = "RHSA-2020:1845",
CVEId = "CVE-2019-6477",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind",Version = "9.11.13-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-chroot",Version = "9.11.13-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-devel",Version = "9.11.13-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-export-devel",Version = "9.11.13-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-export-libs",Version = "9.11.13-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-libs",Version = "9.11.13-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-libs-lite",Version = "9.11.13-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-license",Version = "9.11.13-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-lite-devel",Version = "9.11.13-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11",Version = "9.11.13-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-devel",Version = "9.11.13-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-libs",Version = "9.11.13-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-utils",Version = "9.11.13-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-sdb",Version = "9.11.13-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-sdb-chroot",Version = "9.11.13-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-utils",Version = "9.11.13-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-bind",Version = "9.11.13-3.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1845)

RHSA_2020_1852_Rule = VulRule:new()

RHSA_2020_1852 = RHSA_2020_1852_Rule:new{
PatchId = "RHSA-2020:1852",
CVEId = "CVE-2019-13636",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "patch",Version = "2.7.6-11.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1852)

RHSA_2020_1864_Rule = VulRule:new()

RHSA_2020_1864 = RHSA_2020_1864_Rule:new{
PatchId = "RHSA-2020:1864",
CVEId = "CVE-2019-15847",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cpp",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gcc",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gcc-c++",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gcc-gdb-plugin",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gcc-gfortran",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gcc-offload-nvptx",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gcc-plugin-devel",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libasan",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libatomic",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libatomic-static",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libgcc",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libgfortran",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libgomp",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libgomp-offload-nvptx",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libitm",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libitm-devel",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "liblsan",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libquadmath",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libquadmath-devel",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libstdc++",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libstdc++-devel",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libstdc++-docs",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libstdc++-static",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libtsan",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libubsan",Version = "8.3.1-5.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1864)

RHSA_2020_1878_Rule = VulRule:new()

RHSA_2020_1878 = RHSA_2020_1878_Rule:new{
PatchId = "RHSA-2020:1878",
CVEId = "CVE-2019-14907",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "openchange",Version = "2.3-24.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "ctdb",Version = "4.11.2-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "ctdb-tests",Version = "4.11.2-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libsmbclient",Version = "4.11.2-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libsmbclient-devel",Version = "4.11.2-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libwbclient",Version = "4.11.2-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libwbclient-devel",Version = "4.11.2-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-samba",Version = "4.11.2-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-samba-test",Version = "4.11.2-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba",Version = "4.11.2-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-client",Version = "4.11.2-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-client-libs",Version = "4.11.2-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-common",Version = "4.11.2-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-common-libs",Version = "4.11.2-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-common-tools",Version = "4.11.2-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-krb5-printing",Version = "4.11.2-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-libs",Version = "4.11.2-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-pidl",Version = "4.11.2-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-test",Version = "4.11.2-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-test-libs",Version = "4.11.2-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winbind",Version = "4.11.2-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winbind-clients",Version = "4.11.2-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winbind-krb5-locator",Version = "4.11.2-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winbind-modules",Version = "4.11.2-13.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1878)

RHSA_2020_1880_Rule = VulRule:new()

RHSA_2020_1880 = RHSA_2020_1880_Rule:new{
PatchId = "RHSA-2020:1880",
CVEId = "CVE-2019-14822",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "ibus",Version = "1.5.19-11.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "ibus-devel",Version = "1.5.19-11.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "ibus-devel-docs",Version = "1.5.19-11.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "ibus-gtk2",Version = "1.5.19-11.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "ibus-gtk3",Version = "1.5.19-11.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "ibus-libs",Version = "1.5.19-11.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "ibus-setup",Version = "1.5.19-11.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "ibus-wayland",Version = "1.5.19-11.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2",Version = "2.56.4-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-devel",Version = "2.56.4-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-doc",Version = "2.56.4-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-fam",Version = "2.56.4-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-static",Version = "2.56.4-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-tests",Version = "2.56.4-8.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1880)

RHSA_2020_1912_Rule = VulRule:new()

RHSA_2020_1912 = RHSA_2020_1912_Rule:new{
PatchId = "RHSA-2020:1912",
CVEId = "CVE-2018-10910",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez",Version = "5.50-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez-cups",Version = "5.50-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez-hid2hci",Version = "5.50-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez-libs",Version = "5.50-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez-libs-devel",Version = "5.50-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez-obexd",Version = "5.50-3.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1912)

RHSA_2020_1913_Rule = VulRule:new()

RHSA_2020_1913 = RHSA_2020_1913_Rule:new{
PatchId = "RHSA-2020:1913",
CVEId = "CVE-2019-5188",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "e2fsprogs",Version = "1.45.4-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "e2fsprogs-devel",Version = "1.45.4-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "e2fsprogs-libs",Version = "1.45.4-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libcom_err",Version = "1.45.4-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libcom_err-devel",Version = "1.45.4-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libss",Version = "1.45.4-3.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1913)

RHSA_2020_1916_Rule = VulRule:new()

RHSA_2020_1916 = RHSA_2020_1916_Rule:new{
PatchId = "RHSA-2020:1916",
CVEId = "CVE-2019-11324",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "platform-python-pip",Version = "9.0.3-16.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-pip",Version = "9.0.3-16.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-pip-wheel",Version = "9.0.3-16.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1916)

RHSA_2020_1998_Rule = VulRule:new()

RHSA_2020_1998 = RHSA_2020_1998_Rule:new{
PatchId = "RHSA-2020:1998",
CVEId = "CVE-2020-11501",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnutls",Version = "3.6.8-10.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnutls-c++",Version = "3.6.8-10.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnutls-dane",Version = "3.6.8-10.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnutls-devel",Version = "3.6.8-10.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnutls-utils",Version = "3.6.8-10.el8_2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1998)

RHSA_2020_2102_Rule = VulRule:new()

RHSA_2020_2102 = RHSA_2020_2102_Rule:new{
PatchId = "RHSA-2020:2102",
CVEId = "CVE-2020-2732",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-core",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-cross-headers",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-core",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules-extra",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules-extra",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-core",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-devel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules-extra",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python3-perf",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2102)

RHSA_2020_2338_Rule = VulRule:new()

RHSA_2020_2338 = RHSA_2020_2338_Rule:new{
PatchId = "RHSA-2020:2338",
CVEId = "CVE-2020-8617",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind",Version = "9.11.13-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-chroot",Version = "9.11.13-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-devel",Version = "9.11.13-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-export-devel",Version = "9.11.13-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-export-libs",Version = "9.11.13-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-libs",Version = "9.11.13-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-libs-lite",Version = "9.11.13-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-license",Version = "9.11.13-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-lite-devel",Version = "9.11.13-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11",Version = "9.11.13-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-devel",Version = "9.11.13-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-libs",Version = "9.11.13-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-utils",Version = "9.11.13-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-sdb",Version = "9.11.13-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-sdb-chroot",Version = "9.11.13-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-utils",Version = "9.11.13-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-bind",Version = "9.11.13-5.el8_2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2338)

RHSA_2020_2427_Rule = VulRule:new()

RHSA_2020_2427 = RHSA_2020_2427_Rule:new{
PatchId = "RHSA-2020:2427",
CVEId = "CVE-2020-12657",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-core",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-cross-headers",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-core",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules-extra",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules-extra",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-core",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-devel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules-extra",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python3-perf",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "4.18.0-193.el8",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-4_18_0-193",Version = "1-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-4_18_0-193_1_2",Version = "1-1.el8_2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2427)

RHSA_2020_2431_Rule = VulRule:new()

RHSA_2020_2431 = RHSA_2020_2431_Rule:new{
PatchId = "RHSA-2020:2431",
CVEId = "CVE-2020-0549",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "microcode_ctl",Version = "20191115-4.20200602.2.el8_2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2431)

RHSA_2020_2637_Rule = VulRule:new()

RHSA_2020_2637 = RHSA_2020_2637_Rule:new{
PatchId = "RHSA-2020:2637",
CVEId = "CVE-2020-13777",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnutls",Version = "3.6.8-11.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnutls-c++",Version = "3.6.8-11.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnutls-dane",Version = "3.6.8-11.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnutls-devel",Version = "3.6.8-11.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnutls-utils",Version = "3.6.8-11.el8_2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2637)

RHSA_2020_2755_Rule = VulRule:new()

RHSA_2020_2755 = RHSA_2020_2755_Rule:new{
PatchId = "RHSA-2020:2755",
CVEId = "CVE-2020-11080",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libnghttp2",Version = "1.33.0-3.el8_2.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libnghttp2-devel",Version = "1.33.0-3.el8_2.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "nghttp2",Version = "1.33.0-3.el8_2.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2755)

RHSA_2020_3010_Rule = VulRule:new()

RHSA_2020_3010 = RHSA_2020_3010_Rule:new{
PatchId = "RHSA-2020:3010",
CVEId = "CVE-2020-12888",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-core",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-cross-headers",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-core",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules-extra",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules-extra",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-core",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-devel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules-extra",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python3-perf",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3010)

RHSA_2020_3011_Rule = VulRule:new()

RHSA_2020_3011 = RHSA_2020_3011_Rule:new{
PatchId = "RHSA-2020:3011",
CVEId = "CVE-2020-10754",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager",Version = "1.22.8-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-adsl",Version = "1.22.8-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-bluetooth",Version = "1.22.8-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-cloud-setup",Version = "1.22.8-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-config-connectivity-redhat",Version = "1.22.8-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-config-server",Version = "1.22.8-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-dispatcher-routing-rules",Version = "1.22.8-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-libnm",Version = "1.22.8-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-libnm-devel",Version = "1.22.8-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-ovs",Version = "1.22.8-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-ppp",Version = "1.22.8-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-team",Version = "1.22.8-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-tui",Version = "1.22.8-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-wifi",Version = "1.22.8-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-wwan",Version = "1.22.8-5.el8_2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3011)

RHSA_2020_3014_Rule = VulRule:new()

RHSA_2020_3014 = RHSA_2020_3014_Rule:new{
PatchId = "RHSA-2020:3014",
CVEId = "CVE-2020-12049",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "dbus",Version = "1.12.8-10.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "dbus-common",Version = "1.12.8-10.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "dbus-daemon",Version = "1.12.8-10.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "dbus-devel",Version = "1.12.8-10.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "dbus-libs",Version = "1.12.8-10.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "dbus-tools",Version = "1.12.8-10.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "dbus-x11",Version = "1.12.8-10.el8_2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3014)

RHSA_2020_3073_Rule = VulRule:new()

RHSA_2020_3073 = RHSA_2020_3073_Rule:new{
PatchId = "RHSA-2020:3073",
CVEId = "CVE-2020-10768",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "4.18.0-193.el8",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-4_18_0-193",Version = "1-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-4_18_0-193_1_2",Version = "1-3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-4_18_0-193_6_3",Version = "1-2.el8_2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3073)

RHSA_2020_3216_Rule = VulRule:new()

RHSA_2020_3216 = RHSA_2020_3216_Rule:new{
PatchId = "RHSA-2020:3216",
CVEId = "CVE-2020-15707",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "shim-unsigned-x64",Version = "15-7.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "shim-aa64",Version = "15-14.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "shim-ia32",Version = "15-14.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "shim-x64",Version = "15-14.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "fwupd",Version = "1.1.4-7.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-common",Version = "2.02-87.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-aa64",Version = "2.02-87.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-aa64-cdboot",Version = "2.02-87.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-aa64-modules",Version = "2.02-87.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-ia32",Version = "2.02-87.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-ia32-cdboot",Version = "2.02-87.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-ia32-modules",Version = "2.02-87.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-x64",Version = "2.02-87.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-x64-cdboot",Version = "2.02-87.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-x64-modules",Version = "2.02-87.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-pc",Version = "2.02-87.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-pc-modules",Version = "2.02-87.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-ppc64le",Version = "2.02-87.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-ppc64le-modules",Version = "2.02-87.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-tools",Version = "2.02-87.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-tools-efi",Version = "2.02-87.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-tools-extra",Version = "2.02-87.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-tools-minimal",Version = "2.02-87.el8_2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3216)

RHSA_2020_3218_Rule = VulRule:new()

RHSA_2020_3218 = RHSA_2020_3218_Rule:new{
PatchId = "RHSA-2020:3218",
CVEId = "CVE-2020-15780",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-core",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-cross-headers",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-core",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules-extra",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules-extra",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-core",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-devel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules-extra",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python3-perf",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3218)

RHSA_2020_3654_Rule = VulRule:new()

RHSA_2020_3654 = RHSA_2020_3654_Rule:new{
PatchId = "RHSA-2020:3654",
CVEId = "CVE-2020-12825",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libcroco",Version = "0.6.12-4.el8_2.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libcroco-devel",Version = "0.6.12-4.el8_2.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3654)

RHSA_2020_3658_Rule = VulRule:new()

RHSA_2020_3658 = RHSA_2020_3658_Rule:new{
PatchId = "RHSA-2020:3658",
CVEId = "CVE-2020-14352",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "librepo",Version = "1.11.0-3.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-librepo",Version = "1.11.0-3.el8_2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3658)

RHSA_2020_4286_Rule = VulRule:new()

RHSA_2020_4286 = RHSA_2020_4286_Rule:new{
PatchId = "RHSA-2020:4286",
CVEId = "CVE-2020-14386",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-core",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-cross-headers",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-core",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules-extra",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules-extra",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-core",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-devel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules-extra",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python3-perf",Version = "4.18.0-193.28.1.el8_2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4286)

RHSA_2020_4331_Rule = VulRule:new()

RHSA_2020_4331 = RHSA_2020_4331_Rule:new{
PatchId = "RHSA-2020:4331",
CVEId = "CVE-2020-14385",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "4.18.0-193.el8",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.el8",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-4_18_0-193",Version = "1-7.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.1.2.el8_2",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-4_18_0-193_1_2",Version = "1-5.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.6.3.el8_2",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-4_18_0-193_6_3",Version = "1-4.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.13.2.el8_2",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-4_18_0-193_13_2",Version = "1-2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.14.3.el8_2",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-4_18_0-193_14_3",Version = "1-2.el8_2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.19.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.19.1.el8_2",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "4.18.0-193.19.1.el8_2",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-193.19.1.el8_2",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-193.19.1.el8_2",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-4_18_0-193_19_1",Version = "1-2.el8_2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4331)

RHSA_2020_4431_Rule = VulRule:new()

RHSA_2020_4431 = RHSA_2020_4431_Rule:new{
PatchId = "RHSA-2020:4431",
CVEId = "CVE-2020-8649",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-core",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-cross-headers",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-core",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules-extra",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules-extra",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-core",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-devel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules-extra",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python3-perf",Version = "4.18.0-240.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4431)

RHSA_2020_4432_Rule = VulRule:new()

RHSA_2020_4432 = RHSA_2020_4432_Rule:new{
PatchId = "RHSA-2020:4432",
CVEId = "CVE-2019-20916",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "platform-python-pip",Version = "9.0.3-18.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-pip",Version = "9.0.3-18.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-pip-wheel",Version = "9.0.3-18.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4432)

RHSA_2020_4433_Rule = VulRule:new()

RHSA_2020_4433 = RHSA_2020_4433_Rule:new{
PatchId = "RHSA-2020:4433",
CVEId = "CVE-2020-8492",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "platform-python",Version = "3.6.8-31.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "platform-python-debug",Version = "3.6.8-31.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "platform-python-devel",Version = "3.6.8-31.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-idle",Version = "3.6.8-31.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-libs",Version = "3.6.8-31.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-test",Version = "3.6.8-31.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-tkinter",Version = "3.6.8-31.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4433)

RHSA_2020_4436_Rule = VulRule:new()

RHSA_2020_4436 = RHSA_2020_4436_Rule:new{
PatchId = "RHSA-2020:4436",
CVEId = "CVE-2020-10759",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libxmlb",Version = "0.1.15-1.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-software",Version = "3.36.1-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "appstream-data",Version = "8-20200724.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "fwupd",Version = "1.4.2-4.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4436)

RHSA_2020_4442_Rule = VulRule:new()

RHSA_2020_4442 = RHSA_2020_4442_Rule:new{
PatchId = "RHSA-2020:4442",
CVEId = "CVE-2020-9327",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "lemon",Version = "3.26.0-11.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sqlite",Version = "3.26.0-11.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sqlite-devel",Version = "3.26.0-11.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sqlite-doc",Version = "3.26.0-11.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sqlite-libs",Version = "3.26.0-11.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4442)

RHSA_2020_4443_Rule = VulRule:new()

RHSA_2020_4443 = RHSA_2020_4443_Rule:new{
PatchId = "RHSA-2020:4443",
CVEId = "CVE-2019-19221",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bsdtar",Version = "3.3.2-9.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libarchive",Version = "3.3.2-9.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libarchive-devel",Version = "3.3.2-9.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4443)

RHSA_2020_4444_Rule = VulRule:new()

RHSA_2020_4444 = RHSA_2020_4444_Rule:new{
PatchId = "RHSA-2020:4444",
CVEId = "CVE-2020-1752",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "compat-libpthread-nonshared",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-all-langpacks",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-benchtests",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-common",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-devel",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-headers",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-aa",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-af",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-agr",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ak",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-am",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-an",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-anp",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ar",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-as",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ast",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ayc",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-az",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-be",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-bem",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ber",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-bg",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-bhb",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-bho",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-bi",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-bn",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-bo",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-br",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-brx",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-bs",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-byn",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ca",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ce",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-chr",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-cmn",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-crh",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-cs",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-csb",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-cv",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-cy",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-da",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-de",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-doi",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-dsb",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-dv",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-dz",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-el",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-en",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-eo",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-es",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-et",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-eu",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-fa",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ff",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-fi",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-fil",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-fo",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-fr",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-fur",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-fy",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ga",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-gd",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-gez",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-gl",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-gu",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-gv",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ha",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-hak",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-he",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-hi",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-hif",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-hne",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-hr",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-hsb",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ht",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-hu",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-hy",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ia",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-id",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ig",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ik",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-is",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-it",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-iu",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ja",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ka",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-kab",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-kk",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-kl",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-km",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-kn",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ko",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-kok",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ks",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ku",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-kw",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ky",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-lb",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-lg",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-li",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-lij",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ln",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-lo",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-lt",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-lv",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-lzh",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mag",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mai",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mfe",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mg",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mhr",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mi",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-miq",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mjw",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mk",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ml",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mn",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mni",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mr",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ms",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mt",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-my",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-nan",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-nb",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-nds",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ne",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-nhn",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-niu",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-nl",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-nn",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-nr",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-nso",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-oc",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-om",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-or",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-os",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-pa",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-pap",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-pl",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ps",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-pt",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-quz",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-raj",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ro",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ru",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-rw",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sa",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sah",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sat",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sc",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sd",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-se",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sgs",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-shn",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-shs",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-si",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sid",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sk",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sl",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sm",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-so",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sq",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sr",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ss",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-st",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sv",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sw",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-szl",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ta",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tcy",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-te",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tg",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-th",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-the",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ti",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tig",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tk",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tl",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tn",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-to",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tpi",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tr",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ts",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tt",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ug",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-uk",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-unm",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ur",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-uz",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ve",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-vi",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-wa",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-wae",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-wal",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-wo",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-xh",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-yi",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-yo",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-yue",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-yuw",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-zh",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-zu",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-locale-source",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-minimal-langpack",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-nss-devel",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-static",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-utils",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libnsl",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "nscd",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "nss_db",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "nss_hesiod",Version = "2.28-127.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4444)

RHSA_2020_4445_Rule = VulRule:new()

RHSA_2020_4445 = RHSA_2020_4445_Rule:new{
PatchId = "RHSA-2020:4445",
CVEId = "CVE-2019-18609",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "librabbitmq",Version = "0.9.0-2.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "librabbitmq-devel",Version = "0.9.0-2.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4445)

RHSA_2020_4451_Rule = VulRule:new()

RHSA_2020_4451 = RHSA_2020_4451_Rule:new{
PatchId = "RHSA-2020:4451",
CVEId = "CVE-2020-9925",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "webkit2gtk3",Version = "2.28.4-1.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "webkit2gtk3-devel",Version = "2.28.4-1.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "webkit2gtk3-jsc",Version = "2.28.4-1.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "webkit2gtk3-jsc-devel",Version = "2.28.4-1.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "LibRaw",Version = "0.19.5-2.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "LibRaw-devel",Version = "0.19.5-2.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnome-settings-daemon",Version = "3.32.0-11.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4451)

RHSA_2020_4453_Rule = VulRule:new()

RHSA_2020_4453 = RHSA_2020_4453_Rule:new{
PatchId = "RHSA-2020:4453",
CVEId = "CVE-2019-20807",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "vim-X11",Version = "8.0.1763-15.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "vim-common",Version = "8.0.1763-15.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "vim-enhanced",Version = "8.0.1763-15.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "vim-filesystem",Version = "8.0.1763-15.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "vim-minimal",Version = "8.0.1763-15.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4453)

RHSA_2020_4464_Rule = VulRule:new()

RHSA_2020_4464 = RHSA_2020_4464_Rule:new{
PatchId = "RHSA-2020:4464",
CVEId = "CVE-2019-18197",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libxslt",Version = "1.1.32-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libxslt-devel",Version = "1.1.32-5.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4464)

RHSA_2020_4465_Rule = VulRule:new()

RHSA_2020_4465 = RHSA_2020_4465_Rule:new{
PatchId = "RHSA-2020:4465",
CVEId = "CVE-2019-17450",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "binutils",Version = "2.30-79.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "binutils-devel",Version = "2.30-79.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4465)

RHSA_2020_4469_Rule = VulRule:new()

RHSA_2020_4469 = RHSA_2020_4469_Rule:new{
PatchId = "RHSA-2020:4469",
CVEId = "CVE-2020-3898",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cups",Version = "2.2.6-38.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cups-client",Version = "2.2.6-38.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cups-devel",Version = "2.2.6-38.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cups-filesystem",Version = "2.2.6-38.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cups-ipptool",Version = "2.2.6-38.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cups-libs",Version = "2.2.6-38.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cups-lpd",Version = "2.2.6-38.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4469)

RHSA_2020_4479_Rule = VulRule:new()

RHSA_2020_4479 = RHSA_2020_4479_Rule:new{
PatchId = "RHSA-2020:4479",
CVEId = "CVE-2020-7595",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libxml2",Version = "2.9.7-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libxml2-devel",Version = "2.9.7-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-libxml2",Version = "2.9.7-8.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4479)

RHSA_2020_4481_Rule = VulRule:new()

RHSA_2020_4481 = RHSA_2020_4481_Rule:new{
PatchId = "RHSA-2020:4481",
CVEId = "CVE-2020-0556",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez",Version = "5.50-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez-cups",Version = "5.50-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez-hid2hci",Version = "5.50-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez-libs",Version = "5.50-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez-libs-devel",Version = "5.50-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez-obexd",Version = "5.50-4.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4481)

RHSA_2020_4482_Rule = VulRule:new()

RHSA_2020_4482 = RHSA_2020_4482_Rule:new{
PatchId = "RHSA-2020:4482",
CVEId = "CVE-2019-13627",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libgcrypt",Version = "1.8.5-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libgcrypt-devel",Version = "1.8.5-4.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4482)

RHSA_2020_4483_Rule = VulRule:new()

RHSA_2020_4483 = RHSA_2020_4483_Rule:new{
PatchId = "RHSA-2020:4483",
CVEId = "CVE-2019-20792",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "opensc",Version = "0.20.0-2.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4483)

RHSA_2020_4484_Rule = VulRule:new()

RHSA_2020_4484 = RHSA_2020_4484_Rule:new{
PatchId = "RHSA-2020:4484",
CVEId = "CVE-2019-15903",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "expat",Version = "2.2.5-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "expat-devel",Version = "2.2.5-4.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4484)

RHSA_2020_4490_Rule = VulRule:new()

RHSA_2020_4490 = RHSA_2020_4490_Rule:new{
PatchId = "RHSA-2020:4490",
CVEId = "CVE-2019-13050",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnupg2",Version = "2.2.20-2.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnupg2-smime",Version = "2.2.20-2.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4490)

RHSA_2020_4497_Rule = VulRule:new()

RHSA_2020_4497 = RHSA_2020_4497_Rule:new{
PatchId = "RHSA-2020:4497",
CVEId = "CVE-2019-19906",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cyrus-sasl",Version = "2.1.27-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cyrus-sasl-devel",Version = "2.1.27-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cyrus-sasl-gs2",Version = "2.1.27-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cyrus-sasl-gssapi",Version = "2.1.27-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cyrus-sasl-ldap",Version = "2.1.27-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cyrus-sasl-lib",Version = "2.1.27-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cyrus-sasl-md5",Version = "2.1.27-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cyrus-sasl-ntlm",Version = "2.1.27-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cyrus-sasl-plain",Version = "2.1.27-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cyrus-sasl-scram",Version = "2.1.27-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cyrus-sasl-sql",Version = "2.1.27-5.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4497)

RHSA_2020_4500_Rule = VulRule:new()

RHSA_2020_4500 = RHSA_2020_4500_Rule:new{
PatchId = "RHSA-2020:4500",
CVEId = "CVE-2020-8624",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind",Version = "9.11.20-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-chroot",Version = "9.11.20-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-devel",Version = "9.11.20-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-export-devel",Version = "9.11.20-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-export-libs",Version = "9.11.20-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-libs",Version = "9.11.20-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-libs-lite",Version = "9.11.20-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-license",Version = "9.11.20-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-lite-devel",Version = "9.11.20-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11",Version = "9.11.20-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-devel",Version = "9.11.20-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-libs",Version = "9.11.20-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-utils",Version = "9.11.20-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-sdb",Version = "9.11.20-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-sdb-chroot",Version = "9.11.20-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-utils",Version = "9.11.20-5.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-bind",Version = "9.11.20-5.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4500)

RHSA_2020_4508_Rule = VulRule:new()

RHSA_2020_4508 = RHSA_2020_4508_Rule:new{
PatchId = "RHSA-2020:4508",
CVEId = "CVE-2019-20387",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libsolv",Version = "0.7.11-1.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-solv",Version = "0.7.11-1.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4508)

RHSA_2020_4514_Rule = VulRule:new()

RHSA_2020_4514 = RHSA_2020_4514_Rule:new{
PatchId = "RHSA-2020:4514",
CVEId = "CVE-2019-1551",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl",Version = "1.1.1g-11.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl-devel",Version = "1.1.1g-11.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl-libs",Version = "1.1.1g-11.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl-perl",Version = "1.1.1g-11.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4514)

RHSA_2020_4539_Rule = VulRule:new()

RHSA_2020_4539 = RHSA_2020_4539_Rule:new{
PatchId = "RHSA-2020:4539",
CVEId = "CVE-2019-20454",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "pcre2",Version = "10.32-2.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "pcre2-devel",Version = "10.32-2.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "pcre2-tools",Version = "10.32-2.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "pcre2-utf16",Version = "10.32-2.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "pcre2-utf32",Version = "10.32-2.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4539)

RHSA_2020_4542_Rule = VulRule:new()

RHSA_2020_4542 = RHSA_2020_4542_Rule:new{
PatchId = "RHSA-2020:4542",
CVEId = "CVE-2020-14382",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cryptsetup",Version = "2.3.3-2.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cryptsetup-devel",Version = "2.3.3-2.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cryptsetup-libs",Version = "2.3.3-2.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cryptsetup-reencrypt",Version = "2.3.3-2.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "integritysetup",Version = "2.3.3-2.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "veritysetup",Version = "2.3.3-2.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4542)

RHSA_2020_4545_Rule = VulRule:new()

RHSA_2020_4545 = RHSA_2020_4545_Rule:new{
PatchId = "RHSA-2020:4545",
CVEId = "CVE-2020-1730",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libssh",Version = "0.9.4-2.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libssh-config",Version = "0.9.4-2.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libssh-devel",Version = "0.9.4-2.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4545)

RHSA_2020_4547_Rule = VulRule:new()

RHSA_2020_4547 = RHSA_2020_4547_Rule:new{
PatchId = "RHSA-2020:4547",
CVEId = "CVE-2019-15165",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libpcap",Version = "1.9.1-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libpcap-devel",Version = "1.9.1-4.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4547)

RHSA_2020_4553_Rule = VulRule:new()

RHSA_2020_4553 = RHSA_2020_4553_Rule:new{
PatchId = "RHSA-2020:4553",
CVEId = "CVE-2019-20386",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd",Version = "239-40.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-container",Version = "239-40.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-devel",Version = "239-40.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-journal-remote",Version = "239-40.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-libs",Version = "239-40.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-pam",Version = "239-40.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-tests",Version = "239-40.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-udev",Version = "239-40.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4553)

RHSA_2020_4568_Rule = VulRule:new()

RHSA_2020_4568 = RHSA_2020_4568_Rule:new{
PatchId = "RHSA-2020:4568",
CVEId = "CVE-2020-10730",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "ldb-tools",Version = "2.1.3-2.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libldb",Version = "2.1.3-2.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libldb-devel",Version = "2.1.3-2.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-ldb",Version = "2.1.3-2.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4568)

RHSA_2020_4599_Rule = VulRule:new()

RHSA_2020_4599 = RHSA_2020_4599_Rule:new{
PatchId = "RHSA-2020:4599",
CVEId = "CVE-2020-8177",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "curl",Version = "7.61.1-14.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libcurl",Version = "7.61.1-14.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libcurl-devel",Version = "7.61.1-14.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libcurl-minimal",Version = "7.61.1-14.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4599)

RHSA_2020_4685_Rule = VulRule:new()

RHSA_2020_4685 = RHSA_2020_4685_Rule:new{
PatchId = "RHSA-2020:4685",
CVEId = "CVE-2020-25662",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-core",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-cross-headers",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-core",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules-extra",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules-extra",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-core",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-devel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules-extra",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python3-perf",Version = "4.18.0-240.1.1.el8_3",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4685)

RHSA_2020_4952_Rule = VulRule:new()

RHSA_2020_4952 = RHSA_2020_4952_Rule:new{
PatchId = "RHSA-2020:4952",
CVEId = "CVE-2020-15999",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "freetype",Version = "2.9.1-4.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "freetype-devel",Version = "2.9.1-4.el8_3.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4952)

RHSA_2020_5085_Rule = VulRule:new()

RHSA_2020_5085 = RHSA_2020_5085_Rule:new{
PatchId = "RHSA-2020:5085",
CVEId = "CVE-2020-8698",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "microcode_ctl",Version = "20200609-2.20201027.1.el8_3",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5085)

RHSA_2020_5473_Rule = VulRule:new()

RHSA_2020_5473 = RHSA_2020_5473_Rule:new{
PatchId = "RHSA-2020:5473",
CVEId = "CVE-2020-16166",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-core",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-core",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules-extra",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules-extra",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-core",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-devel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules-extra",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python3-perf",Version = "4.18.0-240.8.1.el8_3",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5473)

RHSA_2020_5476_Rule = VulRule:new()

RHSA_2020_5476 = RHSA_2020_5476_Rule:new{
PatchId = "RHSA-2020:5476",
CVEId = "CVE-2020-1971",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl",Version = "1.1.1g-12.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl-devel",Version = "1.1.1g-12.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl-libs",Version = "1.1.1g-12.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl-perl",Version = "1.1.1g-12.el8_3",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5476)

RHSA_2020_5479_Rule = VulRule:new()

RHSA_2020_5479 = RHSA_2020_5479_Rule:new{
PatchId = "RHSA-2020:5479",
CVEId = "CVE-2020-12321",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl100-firmware",Version = "39.31.5.1-101.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl1000-firmware",Version = "39.31.5.1-101.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl105-firmware",Version = "18.168.6.1-101.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl135-firmware",Version = "18.168.6.1-101.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl2000-firmware",Version = "18.168.6.1-101.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl2030-firmware",Version = "18.168.6.1-101.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl3160-firmware",Version = "25.30.13.0-101.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl3945-firmware",Version = "15.32.2.9-101.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl4965-firmware",Version = "228.61.2.24-101.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl5000-firmware",Version = "8.83.5.1_1-101.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl5150-firmware",Version = "8.24.2.2-101.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl6000-firmware",Version = "9.221.4.1-101.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl6000g2a-firmware",Version = "18.168.6.1-101.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl6000g2b-firmware",Version = "18.168.6.1-101.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl6050-firmware",Version = "41.28.5.1-101.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl7260-firmware",Version = "25.30.13.0-101.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libertas-sd8686-firmware",Version = "20200619-101.git3890db36.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libertas-sd8787-firmware",Version = "20200619-101.git3890db36.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libertas-usb8388-firmware",Version = "20200619-101.git3890db36.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libertas-usb8388-olpc-firmware",Version = "20200619-101.git3890db36.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "linux-firmware",Version = "20200619-101.git3890db36.el8_3",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5479)

RHSA_2020_5480_Rule = VulRule:new()

RHSA_2020_5480 = RHSA_2020_5480_Rule:new{
PatchId = "RHSA-2020:5480",
CVEId = "CVE-2020-15862",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp",Version = "5.8-18.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-agent-libs",Version = "5.8-18.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-devel",Version = "5.8-18.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-libs",Version = "5.8-18.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-perl",Version = "5.8-18.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-utils",Version = "5.8-18.el8_3.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5480)

RHSA_2020_5483_Rule = VulRule:new()

RHSA_2020_5483 = RHSA_2020_5483_Rule:new{
PatchId = "RHSA-2020:5483",
CVEId = "CVE-2020-24659",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnutls",Version = "3.6.14-7.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnutls-c++",Version = "3.6.14-7.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnutls-dane",Version = "3.6.14-7.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnutls-devel",Version = "3.6.14-7.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnutls-utils",Version = "3.6.14-7.el8_3",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5483)

RHSA_2021_0003_Rule = VulRule:new()

RHSA_2021_0003 = RHSA_2021_0003_Rule:new{
PatchId = "RHSA-2021:0003",
CVEId = "CVE-2020-25211",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-core",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-core",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules-extra",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules-extra",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-core",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-devel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules-extra",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python3-perf",Version = "4.18.0-240.10.1.el8_3",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0003)

RHSA_2021_0218_Rule = VulRule:new()

RHSA_2021_0218 = RHSA_2021_0218_Rule:new{
PatchId = "RHSA-2021:0218",
CVEId = "CVE-2021-3156",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sudo",Version = "1.8.29-6.el8_3.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0218)

RHSA_2021_0557_Rule = VulRule:new()

RHSA_2021_0557 = RHSA_2021_0557_Rule:new{
PatchId = "RHSA-2021:0557",
CVEId = "CVE-2020-12723",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl",Version = "5.26.3-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Attribute-Handlers",Version = "0.99-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Devel-Peek",Version = "1.26-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Devel-SelfStubber",Version = "1.06-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Errno",Version = "1.28-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-ExtUtils-Embed",Version = "1.34-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-ExtUtils-Miniperl",Version = "1.06-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-IO",Version = "1.38-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-IO-Zlib",Version = "1.10-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Locale-Maketext-Simple",Version = "0.21-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Math-Complex",Version = "1.59-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Memoize",Version = "1.03-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Module-Loaded",Version = "0.08-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Net-Ping",Version = "2.55-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Pod-Html",Version = "1.22.02-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-SelfLoader",Version = "1.23-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Test",Version = "1.30-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Time-Piece",Version = "1.31-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-devel",Version = "5.26.3-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-interpreter",Version = "5.26.3-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-libnetcfg",Version = "5.26.3-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-libs",Version = "5.26.3-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-macros",Version = "5.26.3-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-open",Version = "1.11-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-tests",Version = "5.26.3-417.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-utils",Version = "5.26.3-417.el8_3",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0557)

RHSA_2021_0558_Rule = VulRule:new()

RHSA_2021_0558 = RHSA_2021_0558_Rule:new{
PatchId = "RHSA-2021:0558",
CVEId = "CVE-2020-29661",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-core",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-cross-headers",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-core",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules-extra",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules-extra",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-core",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-devel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules-extra",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python3-perf",Version = "4.18.0-240.15.1.el8_3",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0558)

RHSA_2021_0618_Rule = VulRule:new()

RHSA_2021_0618 = RHSA_2021_0618_Rule:new{
PatchId = "RHSA-2021:0618",
CVEId = "CVE-2021-20230",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "stunnel",Version = "5.56-5.el8_3",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0618)

RHSA_2021_0670_Rule = VulRule:new()

RHSA_2021_0670 = RHSA_2021_0670_Rule:new{
PatchId = "RHSA-2021:0670",
CVEId = "CVE-2020-8625",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind",Version = "9.11.20-5.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-chroot",Version = "9.11.20-5.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-devel",Version = "9.11.20-5.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-export-devel",Version = "9.11.20-5.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-export-libs",Version = "9.11.20-5.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-libs",Version = "9.11.20-5.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-libs-lite",Version = "9.11.20-5.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-license",Version = "9.11.20-5.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-lite-devel",Version = "9.11.20-5.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11",Version = "9.11.20-5.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-devel",Version = "9.11.20-5.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-libs",Version = "9.11.20-5.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-utils",Version = "9.11.20-5.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-sdb",Version = "9.11.20-5.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-sdb-chroot",Version = "9.11.20-5.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-utils",Version = "9.11.20-5.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-bind",Version = "9.11.20-5.el8_3.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0670)

RHSA_2021_0696_Rule = VulRule:new()

RHSA_2021_0696 = RHSA_2021_0696_Rule:new{
PatchId = "RHSA-2021:0696",
CVEId = "CVE-2021-20233",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-common",Version = "2.02-90.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-aa64",Version = "2.02-90.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-aa64-cdboot",Version = "2.02-90.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-aa64-modules",Version = "2.02-90.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-ia32",Version = "2.02-90.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-ia32-cdboot",Version = "2.02-90.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-ia32-modules",Version = "2.02-90.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-x64",Version = "2.02-90.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-x64-cdboot",Version = "2.02-90.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-efi-x64-modules",Version = "2.02-90.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-pc",Version = "2.02-90.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-pc-modules",Version = "2.02-90.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-ppc64le",Version = "2.02-90.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-ppc64le-modules",Version = "2.02-90.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-tools",Version = "2.02-90.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-tools-efi",Version = "2.02-90.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-tools-extra",Version = "2.02-90.el8_3.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "grub2-tools-minimal",Version = "2.02-90.el8_3.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0696)

RHSA_2021_0809_Rule = VulRule:new()

RHSA_2021_0809 = RHSA_2021_0809_Rule:new{
PatchId = "RHSA-2021:0809",
CVEId = "CVE-2021-27803",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "wpa_supplicant",Version = "2.9-2.el8_3.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0809)

RHSA_2021_1024_Rule = VulRule:new()

RHSA_2021_1024 = RHSA_2021_1024_Rule:new{
PatchId = "RHSA-2021:1024",
CVEId = "CVE-2021-3450",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl",Version = "1.1.1g-15.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl-devel",Version = "1.1.1g-15.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl-libs",Version = "1.1.1g-15.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl-perl",Version = "1.1.1g-15.el8_3",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1024)

RHSA_2021_1093_Rule = VulRule:new()

RHSA_2021_1093 = RHSA_2021_1093_Rule:new{
PatchId = "RHSA-2021:1093",
CVEId = "CVE-2021-3347",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-core",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-cross-headers",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-core",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules-extra",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules-extra",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-core",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-devel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules-extra",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python3-perf",Version = "4.18.0-240.22.1.el8_3",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1093)

RHSA_2021_1197_Rule = VulRule:new()

RHSA_2021_1197 = RHSA_2021_1197_Rule:new{
PatchId = "RHSA-2021:1197",
CVEId = "CVE-2021-20277",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "ldb-tools",Version = "2.1.3-3.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libldb",Version = "2.1.3-3.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libldb-devel",Version = "2.1.3-3.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-ldb",Version = "2.1.3-3.el8_3",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1197)

RHSA_2021_1206_Rule = VulRule:new()

RHSA_2021_1206 = RHSA_2021_1206_Rule:new{
PatchId = "RHSA-2021:1206",
CVEId = "CVE-2021-20305",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "nettle",Version = "3.4.1-4.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "nettle-devel",Version = "3.4.1-4.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnutls",Version = "3.6.14-8.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnutls-c++",Version = "3.6.14-8.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnutls-dane",Version = "3.6.14-8.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnutls-devel",Version = "3.6.14-8.el8_3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "gnutls-utils",Version = "3.6.14-8.el8_3",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1206)

RHSA_2021_1574_Rule = VulRule:new()

RHSA_2021_1574 = RHSA_2021_1574_Rule:new{
PatchId = "RHSA-2021:1574",
CVEId = "CVE-2021-20297",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libnma",Version = "1.8.30-2.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libnma-devel",Version = "1.8.30-2.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager",Version = "1.30.0-7.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-adsl",Version = "1.30.0-7.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-bluetooth",Version = "1.30.0-7.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-cloud-setup",Version = "1.30.0-7.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-config-connectivity-redhat",Version = "1.30.0-7.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-config-server",Version = "1.30.0-7.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-dispatcher-routing-rules",Version = "1.30.0-7.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-libnm",Version = "1.30.0-7.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-libnm-devel",Version = "1.30.0-7.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-ovs",Version = "1.30.0-7.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-ppp",Version = "1.30.0-7.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-team",Version = "1.30.0-7.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-tui",Version = "1.30.0-7.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-wifi",Version = "1.30.0-7.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "NetworkManager-wwan",Version = "1.30.0-7.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1574)

RHSA_2021_1578_Rule = VulRule:new()

RHSA_2021_1578 = RHSA_2021_1578_Rule:new{
PatchId = "RHSA-2021:1578",
CVEId = "CVE-2021-0605",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-stablelists",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-core",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-cross-headers",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-core",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules-extra",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules-extra",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-core",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-devel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules-extra",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python3-perf",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1578)

RHSA_2021_1581_Rule = VulRule:new()

RHSA_2021_1581 = RHSA_2021_1581_Rule:new{
PatchId = "RHSA-2021:1581",
CVEId = "CVE-2020-15358",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "lemon",Version = "3.26.0-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sqlite",Version = "3.26.0-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sqlite-devel",Version = "3.26.0-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sqlite-doc",Version = "3.26.0-13.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sqlite-libs",Version = "3.26.0-13.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1581)

RHSA_2021_1582_Rule = VulRule:new()

RHSA_2021_1582 = RHSA_2021_1582_Rule:new{
PatchId = "RHSA-2021:1582",
CVEId = "CVE-2019-14866",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "cpio",Version = "2.12-10.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1582)

RHSA_2021_1585_Rule = VulRule:new()

RHSA_2021_1585 = RHSA_2021_1585_Rule:new{
PatchId = "RHSA-2021:1585",
CVEId = "CVE-2021-3326",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "compat-libpthread-nonshared",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-all-langpacks",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-benchtests",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-common",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-devel",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-headers",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-aa",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-af",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-agr",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ak",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-am",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-an",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-anp",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ar",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-as",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ast",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ayc",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-az",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-be",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-bem",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ber",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-bg",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-bhb",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-bho",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-bi",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-bn",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-bo",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-br",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-brx",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-bs",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-byn",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ca",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ce",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-chr",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-cmn",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-crh",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-cs",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-csb",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-cv",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-cy",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-da",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-de",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-doi",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-dsb",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-dv",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-dz",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-el",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-en",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-eo",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-es",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-et",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-eu",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-fa",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ff",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-fi",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-fil",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-fo",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-fr",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-fur",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-fy",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ga",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-gd",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-gez",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-gl",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-gu",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-gv",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ha",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-hak",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-he",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-hi",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-hif",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-hne",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-hr",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-hsb",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ht",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-hu",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-hy",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ia",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-id",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ig",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ik",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-is",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-it",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-iu",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ja",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ka",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-kab",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-kk",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-kl",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-km",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-kn",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ko",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-kok",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ks",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ku",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-kw",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ky",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-lb",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-lg",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-li",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-lij",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ln",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-lo",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-lt",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-lv",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-lzh",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mag",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mai",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mfe",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mg",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mhr",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mi",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-miq",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mjw",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mk",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ml",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mn",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mni",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mr",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ms",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-mt",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-my",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-nan",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-nb",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-nds",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ne",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-nhn",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-niu",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-nl",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-nn",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-nr",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-nso",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-oc",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-om",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-or",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-os",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-pa",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-pap",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-pl",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ps",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-pt",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-quz",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-raj",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ro",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ru",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-rw",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sa",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sah",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sat",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sc",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sd",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-se",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sgs",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-shn",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-shs",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-si",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sid",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sk",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sl",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sm",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-so",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sq",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sr",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ss",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-st",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sv",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-sw",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-szl",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ta",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tcy",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-te",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tg",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-th",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-the",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ti",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tig",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tk",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tl",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tn",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-to",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tpi",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tr",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ts",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-tt",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ug",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-uk",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-unm",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ur",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-uz",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-ve",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-vi",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-wa",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-wae",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-wal",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-wo",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-xh",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-yi",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-yo",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-yue",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-yuw",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-zh",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-langpack-zu",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-locale-source",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-minimal-langpack",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-nss-devel",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-static",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glibc-utils",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libnsl",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "nscd",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "nss_db",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "nss_hesiod",Version = "2.28-151.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1585)

RHSA_2021_1586_Rule = VulRule:new()

RHSA_2021_1586 = RHSA_2021_1586_Rule:new{
PatchId = "RHSA-2021:1586",
CVEId = "CVE-2020-9983",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2",Version = "2.56.4-9.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-devel",Version = "2.56.4-9.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-doc",Version = "2.56.4-9.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-fam",Version = "2.56.4-9.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-static",Version = "2.56.4-9.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-tests",Version = "2.56.4-9.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "webkit2gtk3",Version = "2.30.4-1.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "webkit2gtk3-devel",Version = "2.30.4-1.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "webkit2gtk3-jsc",Version = "2.30.4-1.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "webkit2gtk3-jsc-devel",Version = "2.30.4-1.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1586)

RHSA_2021_1593_Rule = VulRule:new()

RHSA_2021_1593 = RHSA_2021_1593_Rule:new{
PatchId = "RHSA-2021:1593",
CVEId = "CVE-2020-28196",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "krb5-devel",Version = "1.18.2-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "krb5-libs",Version = "1.18.2-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "krb5-pkinit",Version = "1.18.2-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "krb5-server",Version = "1.18.2-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "krb5-server-ldap",Version = "1.18.2-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "krb5-workstation",Version = "1.18.2-8.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libkadm5",Version = "1.18.2-8.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1593)

RHSA_2021_1597_Rule = VulRule:new()

RHSA_2021_1597 = RHSA_2021_1597_Rule:new{
PatchId = "RHSA-2021:1597",
CVEId = "CVE-2020-24977",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libxml2",Version = "2.9.7-9.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libxml2-devel",Version = "2.9.7-9.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-libxml2",Version = "2.9.7-9.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1597)

RHSA_2021_1598_Rule = VulRule:new()

RHSA_2021_1598 = RHSA_2021_1598_Rule:new{
PatchId = "RHSA-2021:1598",
CVEId = "CVE-2020-27153",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez",Version = "5.52-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez-cups",Version = "5.52-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez-hid2hci",Version = "5.52-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez-libs",Version = "5.52-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez-libs-devel",Version = "5.52-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bluez-obexd",Version = "5.52-4.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1598)

RHSA_2021_1600_Rule = VulRule:new()

RHSA_2021_1600 = RHSA_2021_1600_Rule:new{
PatchId = "RHSA-2021:1600",
CVEId = "CVE-2020-26572",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "opensc",Version = "0.20.0-4.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1600)

RHSA_2021_1608_Rule = VulRule:new()

RHSA_2021_1608 = RHSA_2021_1608_Rule:new{
PatchId = "RHSA-2021:1608",
CVEId = "CVE-2020-36242",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-cryptography",Version = "3.2.1-4.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1608)

RHSA_2021_1609_Rule = VulRule:new()

RHSA_2021_1609 = RHSA_2021_1609_Rule:new{
PatchId = "RHSA-2021:1609",
CVEId = "CVE-2020-29363",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "p11-kit",Version = "0.23.22-1.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "p11-kit-devel",Version = "0.23.22-1.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "p11-kit-server",Version = "0.23.22-1.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "p11-kit-trust",Version = "0.23.22-1.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1609)

RHSA_2021_1610_Rule = VulRule:new()

RHSA_2021_1610 = RHSA_2021_1610_Rule:new{
PatchId = "RHSA-2021:1610",
CVEId = "CVE-2020-8286",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "curl",Version = "7.61.1-18.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libcurl",Version = "7.61.1-18.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libcurl-devel",Version = "7.61.1-18.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libcurl-minimal",Version = "7.61.1-18.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1610)

RHSA_2021_1611_Rule = VulRule:new()

RHSA_2021_1611 = RHSA_2021_1611_Rule:new{
PatchId = "RHSA-2021:1611",
CVEId = "CVE-2020-13776",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd",Version = "239-45.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-container",Version = "239-45.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-devel",Version = "239-45.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-journal-remote",Version = "239-45.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-libs",Version = "239-45.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-pam",Version = "239-45.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-tests",Version = "239-45.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-udev",Version = "239-45.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1611)

RHSA_2021_1620_Rule = VulRule:new()

RHSA_2021_1620 = RHSA_2021_1620_Rule:new{
PatchId = "RHSA-2021:1620",
CVEId = "CVE-2020-12364",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl100-firmware",Version = "39.31.5.1-102.el8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl1000-firmware",Version = "39.31.5.1-102.el8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl105-firmware",Version = "18.168.6.1-102.el8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl135-firmware",Version = "18.168.6.1-102.el8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl2000-firmware",Version = "18.168.6.1-102.el8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl2030-firmware",Version = "18.168.6.1-102.el8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl3160-firmware",Version = "25.30.13.0-102.el8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl3945-firmware",Version = "15.32.2.9-102.el8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl4965-firmware",Version = "228.61.2.24-102.el8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl5000-firmware",Version = "8.83.5.1_1-102.el8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl5150-firmware",Version = "8.24.2.2-102.el8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl6000-firmware",Version = "9.221.4.1-102.el8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl6000g2a-firmware",Version = "18.168.6.1-102.el8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl6000g2b-firmware",Version = "18.168.6.1-102.el8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl6050-firmware",Version = "41.28.5.1-102.el8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "iwl7260-firmware",Version = "25.30.13.0-102.el8.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libertas-sd8686-firmware",Version = "20201218-102.git05789708.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libertas-sd8787-firmware",Version = "20201218-102.git05789708.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libertas-usb8388-firmware",Version = "20201218-102.git05789708.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libertas-usb8388-olpc-firmware",Version = "20201218-102.git05789708.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "linux-firmware",Version = "20201218-102.git05789708.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1620)

RHSA_2021_1627_Rule = VulRule:new()

RHSA_2021_1627 = RHSA_2021_1627_Rule:new{
PatchId = "RHSA-2021:1627",
CVEId = "CVE-2020-24332",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "trousers",Version = "0.3.15-1.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "trousers-devel",Version = "0.3.15-1.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "trousers-lib",Version = "0.3.15-1.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1627)

RHSA_2021_1631_Rule = VulRule:new()

RHSA_2021_1631 = RHSA_2021_1631_Rule:new{
PatchId = "RHSA-2021:1631",
CVEId = "CVE-2020-26137",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-urllib3",Version = "1.24.2-5.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1631)

RHSA_2021_1633_Rule = VulRule:new()

RHSA_2021_1633 = RHSA_2021_1633_Rule:new{
PatchId = "RHSA-2021:1633",
CVEId = "CVE-2021-3177",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "platform-python",Version = "3.6.8-37.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "platform-python-debug",Version = "3.6.8-37.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "platform-python-devel",Version = "3.6.8-37.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-idle",Version = "3.6.8-37.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-libs",Version = "3.6.8-37.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-test",Version = "3.6.8-37.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-tkinter",Version = "3.6.8-37.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1633)

RHSA_2021_1647_Rule = VulRule:new()

RHSA_2021_1647 = RHSA_2021_1647_Rule:new{
PatchId = "RHSA-2021:1647",
CVEId = "CVE-2020-1472",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "openchange",Version = "2.3-27.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "ctdb",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "ctdb-tests",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libsmbclient",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libsmbclient-devel",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libwbclient",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libwbclient-devel",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-samba",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-samba-test",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-client",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-client-libs",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-common",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-common-libs",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-common-tools",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-devel",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-krb5-printing",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-libs",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-pidl",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-test",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-test-libs",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winbind",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winbind-clients",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winbind-krb5-locator",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winbind-modules",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "samba-winexe",Version = "4.13.3-3.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1647)

RHSA_2021_1675_Rule = VulRule:new()

RHSA_2021_1675 = RHSA_2021_1675_Rule:new{
PatchId = "RHSA-2021:1675",
CVEId = "CVE-2019-2708",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libdb",Version = "5.3.28-40.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libdb-cxx",Version = "5.3.28-40.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libdb-cxx-devel",Version = "5.3.28-40.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libdb-devel",Version = "5.3.28-40.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libdb-devel-doc",Version = "5.3.28-40.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libdb-sql",Version = "5.3.28-40.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libdb-sql-devel",Version = "5.3.28-40.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libdb-utils",Version = "5.3.28-40.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1675)

RHSA_2021_1678_Rule = VulRule:new()

RHSA_2021_1678 = RHSA_2021_1678_Rule:new{
PatchId = "RHSA-2021:1678",
CVEId = "CVE-2020-10878",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl",Version = "5.26.3-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Attribute-Handlers",Version = "0.99-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Devel-Peek",Version = "1.26-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Devel-SelfStubber",Version = "1.06-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Errno",Version = "1.28-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-ExtUtils-Embed",Version = "1.34-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-ExtUtils-Miniperl",Version = "1.06-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-IO",Version = "1.38-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-IO-Zlib",Version = "1.10-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Locale-Maketext-Simple",Version = "0.21-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Math-Complex",Version = "1.59-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Memoize",Version = "1.03-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Module-Loaded",Version = "0.08-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Net-Ping",Version = "2.55-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Pod-Html",Version = "1.22.02-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-SelfLoader",Version = "1.23-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Test",Version = "1.30-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Time-Piece",Version = "1.31-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-devel",Version = "5.26.3-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-interpreter",Version = "5.26.3-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-libnetcfg",Version = "5.26.3-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-libs",Version = "5.26.3-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-macros",Version = "5.26.3-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-open",Version = "1.11-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-tests",Version = "5.26.3-419.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-utils",Version = "5.26.3-419.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1678)

RHSA_2021_1679_Rule = VulRule:new()

RHSA_2021_1679 = RHSA_2021_1679_Rule:new{
PatchId = "RHSA-2021:1679",
CVEId = "CVE-2019-18276",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bash",Version = "4.4.19-14.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bash-doc",Version = "4.4.19-14.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1679)

RHSA_2021_1686_Rule = VulRule:new()

RHSA_2021_1686 = RHSA_2021_1686_Rule:new{
PatchId = "RHSA-2021:1686",
CVEId = "CVE-2021-0326",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "wpa_supplicant",Version = "2.9-5.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1686)

RHSA_2021_1702_Rule = VulRule:new()

RHSA_2021_1702 = RHSA_2021_1702_Rule:new{
PatchId = "RHSA-2021:1702",
CVEId = "CVE-2020-8927",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "brotli",Version = "1.0.6-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "brotli-devel",Version = "1.0.6-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-brotli",Version = "1.0.6-3.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1702)

RHSA_2021_1723_Rule = VulRule:new()

RHSA_2021_1723 = RHSA_2021_1723_Rule:new{
PatchId = "RHSA-2021:1723",
CVEId = "CVE-2021-23240",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sudo",Version = "1.8.29-7.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1723)

RHSA_2021_1734_Rule = VulRule:new()

RHSA_2021_1734 = RHSA_2021_1734_Rule:new{
PatchId = "RHSA-2021:1734",
CVEId = "CVE-2021-20225",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "shim-unsigned-aarch64",Version = "15-7.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "shim-unsigned-x64",Version = "15.4-4.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "shim-aa64",Version = "15.4-2.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "shim-ia32",Version = "15.4-2.el8_1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "shim-x64",Version = "15.4-2.el8_1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1734)

RHSA_2021_1989_Rule = VulRule:new()

RHSA_2021_1989 = RHSA_2021_1989_Rule:new{
PatchId = "RHSA-2021:1989",
CVEId = "CVE-2021-25215",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind",Version = "9.11.26-4.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-chroot",Version = "9.11.26-4.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-devel",Version = "9.11.26-4.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-export-devel",Version = "9.11.26-4.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-export-libs",Version = "9.11.26-4.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-libs",Version = "9.11.26-4.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-libs-lite",Version = "9.11.26-4.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-license",Version = "9.11.26-4.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-lite-devel",Version = "9.11.26-4.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11",Version = "9.11.26-4.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-devel",Version = "9.11.26-4.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-libs",Version = "9.11.26-4.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-pkcs11-utils",Version = "9.11.26-4.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-sdb",Version = "9.11.26-4.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-sdb-chroot",Version = "9.11.26-4.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-utils",Version = "9.11.26-4.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-bind",Version = "9.11.26-4.el8_4",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1989)

RHSA_2021_2168_Rule = VulRule:new()

RHSA_2021_2168 = RHSA_2021_2168_Rule:new{
PatchId = "RHSA-2021:2168",
CVEId = "CVE-2021-3543",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-stablelists",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-core",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-cross-headers",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-core",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules-extra",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules-extra",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-core",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-devel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules-extra",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python3-perf",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2168)

RHSA_2021_2170_Rule = VulRule:new()

RHSA_2021_2170 = RHSA_2021_2170_Rule:new{
PatchId = "RHSA-2021:2170",
CVEId = "CVE-2021-27219",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2",Version = "2.56.4-10.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-devel",Version = "2.56.4-10.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-doc",Version = "2.56.4-10.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-fam",Version = "2.56.4-10.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-static",Version = "2.56.4-10.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-tests",Version = "2.56.4-10.el8_4",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2170)

RHSA_2021_2238_Rule = VulRule:new()

RHSA_2021_2238 = RHSA_2021_2238_Rule:new{
PatchId = "RHSA-2021:2238",
CVEId = "CVE-2021-3560",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "polkit",Version = "0.115-11.el8_4.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "polkit-devel",Version = "0.115-11.el8_4.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "polkit-docs",Version = "0.115-11.el8_4.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "polkit-libs",Version = "0.115-11.el8_4.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2238)

RHSA_2021_2308_Rule = VulRule:new()

RHSA_2021_2308 = RHSA_2021_2308_Rule:new{
PatchId = "RHSA-2021:2308",
CVEId = "CVE-2020-24513",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "microcode_ctl",Version = "20210216-1.20210525.1.el8_4",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2308)

RHSA_2021_2359_Rule = VulRule:new()

RHSA_2021_2359 = RHSA_2021_2359_Rule:new{
PatchId = "RHSA-2021:2359",
CVEId = "CVE-2021-25217",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "dhcp-client",Version = "4.3.6-44.el8_4.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "dhcp-common",Version = "4.3.6-44.el8_4.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "dhcp-libs",Version = "4.3.6-44.el8_4.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "dhcp-relay",Version = "4.3.6-44.el8_4.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "dhcp-server",Version = "4.3.6-44.el8_4.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2359)

RHSA_2021_2563_Rule = VulRule:new()

RHSA_2021_2563 = RHSA_2021_2563_Rule:new{
PatchId = "RHSA-2021:2563",
CVEId = "CVE-2021-33034",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "4.18.0-305.el8",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-4_18_0-305",Version = "1-2.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-4_18_0-305_3_1",Version = "1-1.el8_4",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2563)

RHSA_2021_2566_Rule = VulRule:new()

RHSA_2021_2566 = RHSA_2021_2566_Rule:new{
PatchId = "RHSA-2021:2566",
CVEId = "CVE-2020-27779",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "fwupd",Version = "1.5.9-1.el8_4",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2566)

RHSA_2021_2569_Rule = VulRule:new()

RHSA_2021_2569 = RHSA_2021_2569_Rule:new{
PatchId = "RHSA-2021:2569",
CVEId = "CVE-2021-3541",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libxml2",Version = "2.9.7-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libxml2-devel",Version = "2.9.7-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-libxml2",Version = "2.9.7-9.el8_4.2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2569)

RHSA_2021_2570_Rule = VulRule:new()

RHSA_2021_2570 = RHSA_2021_2570_Rule:new{
PatchId = "RHSA-2021:2570",
CVEId = "CVE-2020-26541",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-stablelists",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-core",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-cross-headers",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-core",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules-extra",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules-extra",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-core",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-devel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules-extra",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python3-perf",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2570)

RHSA_2021_2574_Rule = VulRule:new()

RHSA_2021_2574 = RHSA_2021_2574_Rule:new{
PatchId = "RHSA-2021:2574",
CVEId = "CVE-2021-20271",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-rpm",Version = "4.14.3-14.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "rpm",Version = "4.14.3-14.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "rpm-apidocs",Version = "4.14.3-14.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "rpm-build",Version = "4.14.3-14.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "rpm-build-libs",Version = "4.14.3-14.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "rpm-cron",Version = "4.14.3-14.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "rpm-devel",Version = "4.14.3-14.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "rpm-libs",Version = "4.14.3-14.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "rpm-plugin-fapolicyd",Version = "4.14.3-14.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "rpm-plugin-ima",Version = "4.14.3-14.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "rpm-plugin-prioreset",Version = "4.14.3-14.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "rpm-plugin-selinux",Version = "4.14.3-14.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "rpm-plugin-syslog",Version = "4.14.3-14.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "rpm-plugin-systemd-inhibit",Version = "4.14.3-14.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "rpm-sign",Version = "4.14.3-14.el8_4",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2574)

RHSA_2021_2575_Rule = VulRule:new()

RHSA_2021_2575 = RHSA_2021_2575_Rule:new{
PatchId = "RHSA-2021:2575",
CVEId = "CVE-2021-3520",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "lz4",Version = "1.8.3-3.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "lz4-devel",Version = "1.8.3-3.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "lz4-libs",Version = "1.8.3-3.el8_4",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2575)

RHSA_2021_2714_Rule = VulRule:new()

RHSA_2021_2714 = RHSA_2021_2714_Rule:new{
PatchId = "RHSA-2021:2714",
CVEId = "CVE-2021-33909",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-stablelists",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-core",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-cross-headers",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-core",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules-extra",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules-extra",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-core",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-devel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules-extra",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python3-perf",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2714)

RHSA_2021_2716_Rule = VulRule:new()

RHSA_2021_2716 = RHSA_2021_2716_Rule:new{
PatchId = "RHSA-2021:2716",
CVEId = "CVE-2021-32399",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "4.18.0-305.el8",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-4_18_0-305",Version = "1-3.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-4_18_0-305_3_1",Version = "1-2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-4_18_0-305_7_1",Version = "1-1.el8_4",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2716)

RHSA_2021_2717_Rule = VulRule:new()

RHSA_2021_2717 = RHSA_2021_2717_Rule:new{
PatchId = "RHSA-2021:2717",
CVEId = "CVE-2021-33910",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd",Version = "239-45.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-container",Version = "239-45.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-devel",Version = "239-45.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-journal-remote",Version = "239-45.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-libs",Version = "239-45.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-pam",Version = "239-45.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-tests",Version = "239-45.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "systemd-udev",Version = "239-45.el8_4.2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2717)

RHSA_2021_3027_Rule = VulRule:new()

RHSA_2021_3027 = RHSA_2021_3027_Rule:new{
PatchId = "RHSA-2021:3027",
CVEId = "CVE-2020-8695",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "microcode_ctl",Version = "20210216-1.20210608.1.el8_4",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_3027)

RHSA_2021_3044_Rule = VulRule:new()

RHSA_2021_3044 = RHSA_2021_3044_Rule:new{
PatchId = "RHSA-2021:3044",
CVEId = "CVE-2021-3609",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "4.18.0-305.el8",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-305.el8",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-4_18_0-305",Version = "1-4.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-305.3.1.el8_4",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-4_18_0-305_3_1",Version = "1-3.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-305.7.1.el8_4",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-4_18_0-305_7_1",Version = "1-2.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.notinstalled}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-305.10.2.el8_4",Oper = BaseOper.equalto},
{Type = BaseType.linux_kernel,filename = "kpatch-patch-4_18_0-305_10_2",Version = "1-1.el8_4",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_3044)

RHSA_2021_3057_Rule = VulRule:new()

RHSA_2021_3057 = RHSA_2021_3057_Rule:new{
PatchId = "RHSA-2021:3057",
CVEId = "CVE-2021-22555",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-stablelists",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-core",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-cross-headers",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-core",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules-extra",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-modules-extra",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-core",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-devel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules-extra",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python3-perf",Version = "4.18.0-305.12.1.el8_4",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_3057)

RHSA_2021_3058_Rule = VulRule:new()

RHSA_2021_3058 = RHSA_2021_3058_Rule:new{
PatchId = "RHSA-2021:3058",
CVEId = "CVE-2021-27218",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2",Version = "2.56.4-10.el8_4.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-devel",Version = "2.56.4-10.el8_4.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-doc",Version = "2.56.4-10.el8_4.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-fam",Version = "2.56.4-10.el8_4.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-static",Version = "2.56.4-10.el8_4.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-tests",Version = "2.56.4-10.el8_4.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_3058)

RHSA_2021_3151_Rule = VulRule:new()

RHSA_2021_3151 = RHSA_2021_3151_Rule:new{
PatchId = "RHSA-2021:3151",
CVEId = "CVE-2021-3621",
criteria = {
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libipa_hbac",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libsss_autofs",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libsss_certmap",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libsss_idmap",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libsss_nss_idmap",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libsss_nss_idmap-devel",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libsss_simpleifp",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "libsss_sudo",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-libipa_hbac",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-libsss_nss_idmap",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-sss",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-sss-murmur",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "python3-sssdconfig",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sssd",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sssd-ad",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sssd-client",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sssd-common",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sssd-common-pac",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sssd-dbus",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sssd-ipa",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sssd-kcm",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sssd-krb5",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sssd-krb5-common",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sssd-ldap",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sssd-libwbclient",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sssd-nfs-idmap",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sssd-polkit-rules",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sssd-proxy",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sssd-tools",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "sssd-winbind-idmap",Version = "2.4.0-9.el8_4.2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_3151)




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
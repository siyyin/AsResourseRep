patternver="1000.0001"
-- 定义漏洞匹配找到的信息类型
BaseType = {
    kb = 1,
    dll = 2,
    exe = 3,
    sys = 4,
    Windows_version = 5,
    Windows_build = 6,
    Windows_revison_number = 7,
    linux_kernel = 8,
    kernel_running = 9,
    kernel_boot = 10
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
    Windows_xp = 1000,
    Windows_7 = 1001,
    Windows_Server_2003 = 1002,
    Windows_Vista = 1003,
    Windows_Server_2008 = 1004,
    Windows_Server_2008_R2 = 1005,
    Windows_Server_2012 = 1006,
    Windows_Server_2012_R2 = 1007,
    Windows_8_1 = 1008,
    Windows_10 = 1009,
    Windows_Server_2016 = 1010,
    Windows_Server_2019 = 1011
}


local ruleList = {}
local Windows_version = nil
local Windows_build = nil
local Windows_revison_number = nil
local Windows_InstallKB = nil
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

function GetWindowsVersion() 
    return Windows_version 
end

function GetOsType() 
    return OS_Type 
end

function GetWindowsBuild() 
    return Windows_build 
end

function GetWindowsRevisonNumber() 
    return Windows_revison_number 
end

function GetInstallKB() 
    return Windows_InstallKB 
end

function GetFileVersion(filename)
    print(filename)
    if File_Version[filename] == nil then
        File_Version[filename] = extendFunc.GetFileVersion(filename)
        --File_Version[filename] = "0"
    end
    print(File_Version[filename])
    return File_Version[filename]
end

function FileVersionCompare(Version1, Version2)
    if Version1==nil or Version2==nil then
        return BaseOper.lessthan
    end
    local V1 = {}
    local V2 = {}
    local len

    for w in string.gmatch(Version1, '[%w]+') do
        V1[#V1+1] = w
    end

    for w in string.gmatch(Version2, '[%w]+') do
        V2[#V2+1] = w
    end
    len = #V1
    if len>#V2 then
        len = #V2
    end

    for i=1,len do
        if #V1[i]>#V2[i] then
            return BaseOper.greaterthan
        elseif #V1[i]<#V2[i] then
            return BaseOper.lessthan
        end
        if V1[i]>V2[i] then
            return BaseOper.greaterthan
        elseif V1[i]<V2[i] then
            return BaseOper.lessthan
        end
    end
    return BaseOper.equalto
end


function GetKernelRuning()
    return Linux_Kernel_Runing
end

function GetKernelBoot()
    return Linux_Kernel_Boot
end

function InitGetInfo()
    -- 初始化一次
    Windows_version = extendFunc.GetWindowsVersion()
    Windows_build = extendFunc.GetWindowsBuild()
    Windows_revison_number = extendFunc.GetWindowsRevisonNumber()
    Windows_InstallKB = extendFunc.GetInstallKB()
    OS_Type = extendFunc.GetWindowsOs()
    --Linux_Product = "Red Hat Enterprise Linux"
    --Linux_Version = "7.1"
    --Linux_Kernel_Runing = "2.10.0-693.21.1.el7.x86_64"
    --Linux_Kernel_Boot = "2.10.0-693.21.1.el7.x86_64"

    Linux_Product = extendFunc.GetLinuxBuild()
    Linux_Version = extendFunc.LinuxVersion()
    Linux_Kernel_Runing = extendFunc.GetKernelRuning()
    Linux_Kernel_Boot = extendFunc.GetKernelBoot()

    print(Windows_version);
    print(Windows_build);
    print(Windows_revison_number);
    print(Windows_InstallKB);
    print(OS_Type);

    print(Linux_Product);
    print(Linux_Version);
    print(Linux_Kernel_Runing);
    print(Linux_Kernel_Boot);

    ---获取Windows系统类型
    local type = ""
    for w in string.gmatch(string.lower(OS_Type), '[%w]+') do
        type = type .. w
    end

    local oslist = {
        "microsoftwindowsxp", "microsoftwindows7", "microsoftwindowsserver2003",
        "microsoftwindowsvista", "microsoftwindowsserver2008",
        "microsoftwindowsserver2008r2", "wmicrosoftindowsserver2012",
        "microsoftwindowsserver2012r2", "microsoftwindows81",
        "microsoftwindows10", "microsoftwindowsserver2016",
        "microsoftwindowsserver2019"
    }
    for key0, value0 in pairs(oslist) do
        if string.find(type, value0) ~= nil then
            OS_Type = key0 + 999
            break
        end
    end


    ---获取Linux系统类型
    Linux_Version = string.sub(Linux_Version, 1, 1)
    if string.find(string.lower(Linux_Product),string.lower("Red Hat Enterprise Linux")) ~= nil then
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


    
	print(OS_Type)
    return
end

function VultestWindow()

    File_Version["gdi32.dll"] = "10.0.10240.18518"
    File_Version["gdi32full.dll"] = "10.0.17134.1364"


    print(FileVersionCompare(File_Version["gdi32.dll"],File_Version["gdi32full.dll"]))

    -- 初始化一次
    Windows_version = "1809" -- extendFunc.GetWindowsVersion()
    Windows_build = "17763" -- extendFunc.GetWindowsBuild()
    Windows_revison_number = "1097" -- extendFunc.GetWindowsRevisonNumber()
    Windows_InstallKB = "KB4422" -- extendFunc.GetInstallKB()
    OS_Type = "Microsoft Windows 10" -- extendFunc.GetInstallKB()

    ---获取系统类型
    local type = ""
    for w in string.gmatch(string.lower(OS_Type), '[%w]+') do
        type = type .. w
    end

    local oslist = {
        "microsoftwindowsxp", "microsoftwindows7", "microsoftwindowsserver2003",
        "microsoftwindowsvista", "microsoftwindowsserver2008",
        "microsoftwindowsserver2008r2", "wmicrosoftindowsserver2012",
        "microsoftwindowsserver2012r2", "microsoftwindows81",
        "microsoftwindows10", "microsoftwindowsserver2016",
        "microsoftwindowsserver2019"
    }
    for key0, value0 in pairs(oslist) do
        if string.find(type, value0) ~= nil then
            OS_Type = key0 + 999
            break
        end
    end
    return
end


function VultestLinux()
    OS_Type = BaseOS.Rhel8 -- extendFunc.GetInstallKB()
    return
end

InitGetInfo()

---VultestLinux()


----------------------------------------------------------------------------------------
--              所有的pattern 都必须继承自该类。并实现其中的Scan                 --
----------------------------------------------------------------------------------------
--- the base class of VulRule

VulRule = {
    PatchId = "",
    CVEId = "",
    description = "",

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
                ---已经安装更新
                if Type == BaseType.kb then
                    if string.find(GetInstallKB(), filename) ~= nil then
                        Bfind = false
                        break
                    end
                    ---文件版本号比较
                elseif Type == BaseType.dll or Type == BaseType.exe or Type == BaseType.sys then
                    if FileVersionCompare(GetFileVersion(filename), Version) ~= Oper then
                        Bfind = false
                        break
                    end
                elseif Type == BaseType.Windows_version then
                    if FileVersionCompare(GetWindowsVersion(), Version) ~= Oper then
                        Bfind = false
                        break
                    end
                elseif Type == BaseType.Windows_build then
                    if FileVersionCompare(GetWindowsBuild(), Version) ~= Oper then
                        Bfind = false
                        break
                    end
                elseif Type == BaseType.Windows_revison_number then
                    if FileVersionCompare(GetWindowsRevisonNumber(), Version) ~= Oper then
                        Bfind = false
                        break
                    end
                elseif Type == BaseType.kernel_running then
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

function VulRule:createScanResult() return self.PatchId,self.CVEId,self.description end

RHBA_2020_3527_Rule = VulRule:new()

local RHBA_2020_3527 = RHBA_2020_3527_Rule:new{
    PatchId = "RHBA-2020:3527",
    CVEId = "CVE-2019-5108",
    description = "The kernel-rt packages provide the Real Time Linux Kernel, which enables fine-tuning for systems with extremely high determinism requirements",
    criteria = {
        {
            OS = BaseOS.Rhel7,
            logic = {
                {
                    Type = BaseType.kernel_running,
                    filename = "kernel",
                    Version = "3.10.0-1127.19.1.rt56.1116.el7",
                    Oper = BaseOper.lessthan
                }, {
                    Type = BaseType.kernel_boot,
                    filename = "kernel",
                    Version = "3.10.0-1127.19.1.rt56.1116.el7",
                    Oper = BaseOper.lessthan
                }
            }
        }, {
            OS = BaseOS.Rhel7,
            logic = {
                {
                    Type = BaseType.linux_kernel,
                    filename = "kernel-rt",
                    Version = "3.10.0-1127.19.1.rt56.1116.el7",
                    Oper = BaseOper.lessthan
                }, {
                    Type = BaseType.linux_kernel,
                    filename = "kernel-rt-debug",
                    Version = "3.10.0-1127.19.1.rt56.1116.el7",
                    Oper = BaseOper.lessthan
                }, {
                    Type = BaseType.linux_kernel,
                    filename = "kernel-rt-debug-devel",
                    Version = "3.10.0-1127.19.1.rt56.1116.el7",
                    Oper = BaseOper.lessthan
                }, {
                    Type = BaseType.linux_kernel,
                    filename = "kernel-rt-debug-kvm",
                    Version = "3.10.0-1127.19.1.rt56.1116.el7",
                    Oper = BaseOper.lessthan
                }, {
                    Type = BaseType.linux_kernel,
                    filename = "kernel-rt-devel",
                    Version = "3.10.0-1127.19.1.rt56.1116.el7",
                    Oper = BaseOper.lessthan
                }, {
                    Type = BaseType.linux_kernel,
                    filename = "kernel-rt-doc",
                    Version = "3.10.0-1127.19.1.rt56.1116.el7",
                    Oper = BaseOper.lessthan
                }, {
                    Type = BaseType.linux_kernel,
                    filename = "kernel-rt-kvm",
                    Version = "3.10.0-1127.19.1.rt56.1116.el7",
                    Oper = BaseOper.lessthan
                }, {
                    Type = BaseType.linux_kernel,
                    filename = "kernel-rt-trace",
                    Version = "3.10.0-1127.19.1.rt56.1116.el7",
                    Oper = BaseOper.lessthan
                }, {
                    Type = BaseType.linux_kernel,
                    filename = "kernel-rt-trace-devel",
                    Version = "3.10.0-1127.19.1.rt56.1116.el7",
                    Oper = BaseOper.lessthan
                }, {
                    Type = BaseType.linux_kernel,
                    filename = "kernel-rt-trace-kvm",
                    Version = "3.10.0-1127.19.1.rt56.1116.el7",
                    Oper = BaseOper.lessthan
                }
            }
        }
    }
}

AddModule(RHBA_2020_3527)

RHSA_2019_3517_Rule = VulRule:new()

local RHSA_2019_3517 = RHSA_2019_3517_Rule:new{PatchId = "RHSA-2019:3517",
CVEId = "CVE-2015-1593;CVE-2018-16884;CVE-2018-19854;CVE-2018-19985;CVE-2018-20169;CVE-2019-10126;CVE-2019-10207;CVE-2019-10638;CVE-2019-11599;CVE-2019-11833;CVE-2019-11884;CVE-2019-12382;CVE-2019-13233;CVE-2019-13648;CVE-2019-14821;CVE-2019-15214;CVE-2019-15666;CVE-2019-15916;CVE-2019-15919;CVE-2019-15920;CVE-2019-15921;CVE-2019-15924;CVE-2019-15927;CVE-2019-16994;CVE-2019-20811;CVE-2019-3459;CVE-2019-3460;CVE-2019-3874;CVE-2019-3882;CVE-2019-3900;CVE-2019-5489;CVE-2019-7222;CVE-2019-9506;CVE-2020-10720",
description = "kernel security, bug fix, and enhancement update",
criteria = {
{OS = BaseOS.Rhel8,
logic = {{Type = BaseType.linux_kernel,filename = "Red Hat CoreOS",Version = "4",Oper = BaseOper.equalto}}},
{OS = BaseOS.Rhel8,
logic = {{Type = BaseType.kernel_running,filename = "kernel",Version = "4.18.0-147.el8",Oper = BaseOper.lessthan}, 
{Type = BaseType.kernel_boot,filename = "kernel",Version = "4.18.0-147.el8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel8,
logic = {
{Type = BaseType.linux_kernel,filename = "bpftool",Version = "4.18.0-147.el8",Oper = BaseOper.lessthan}, 
{Type = BaseType.linux_kernel,filename = "kernel",Version = "4.18.0-147.el8",Oper = BaseOper.lessthan}, 
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "4.18.0-147.el8",Oper = BaseOper.lessthan}, 
{Type = BaseType.linux_kernel,filename = "kernel-core",Version = "4.18.0-147.el8",Oper = BaseOper.lessthan}, 
{Type = BaseType.linux_kernel,filename = "kernel-cross-headers",Version = "4.18.0-147.el8",Oper = BaseOper.lessthan}, 
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "4.18.0-147.el8",Oper = BaseOper.lessthan}, 
{Type = BaseType.linux_kernel,filename = "kernel-debug-core",Version = "4.18.0-147.el8",Oper = BaseOper.lessthan}, 
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "4.18.0-147.el8",Oper = BaseOper.lessthan}, 
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules",Version = "4.18.0-147.el8",Oper = BaseOper.lessthan}, 
{Type = BaseType.linux_kernel,filename = "kernel-debug-modules-extra",Version = "4.18.0-147.el8",Oper = BaseOper.lessthan}, 
{Type = BaseType.linux_kernel,filename = "kernel-tools",Version = "4.18.0-147.el8",Oper = BaseOper.lessthan}, 
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs",Version = "4.18.0-147.el8",Oper = BaseOper.lessthan}, 
{Type = BaseType.linux_kernel,filename = "kernel-tools-libs-devel",Version = "4.18.0-147.el8",Oper = BaseOper.lessthan}, 
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump",Version = "4.18.0-147.el8",Oper = BaseOper.lessthan}, 
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-core",Version = "4.18.0-147.el8",Oper = BaseOper.lessthan}, 
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-devel",Version = "4.18.0-147.el8", Oper = BaseOper.lessthan}, 
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules",Version = "4.18.0-147.el8",Oper = BaseOper.lessthan}, 
{Type = BaseType.linux_kernel,filename = "kernel-zfcpdump-modules-extra",Version = "4.18.0-147.el8",Oper = BaseOper.lessthan}, 
{Type = BaseType.linux_kernel,filename = "perf",Version = "4.18.0-147.el8",Oper = BaseOper.lessthan}, 
{Type = BaseType.linux_kernel,filename = "python3-perf",Version = "4.18.0-147.el8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2019_3517)

CVE_2020_0774_Rule = VulRule:new()

local CVE_2020_0774 = CVE_2020_0774_Rule:new{CVEId = "CVE-2020-0774",
    description = "An information disclosure vulnerability exists when the Windows GDI component improperly discloses the contents of its memory. An attacker who successfully exploited the vulnerability could obtain information to further compromise the user’s system. There are multiple ways an attacker could exploit the vulnerability, such as by convincing a user to open a specially crafted document, or by convincing a user to visit an untrusted webpage. The security update addresses the vulnerability by correcting how the Windows GDI component handles objects in memory.",
    criteria = {
        {
            OS = BaseOS.Windows_7,
            logic = {
                {
                    Type = BaseType.dll,
                    filename = "gdi32.dll",
                    Version = "6.1.7601.24549",
                    Oper = BaseOper.lessthan
                }
            }
        }, {
            OS = BaseOS.Windows_Server_2008_R2,
            logic = {
                {
                    Type = BaseType.dll,
                    filename = "gdi32.dll",
                    Version = "6.1.7601.24549",
                    Oper = BaseOper.lessthan
                }
            }
        }, {
            OS = BaseOS.Windows_Server_2012,
            logic = {
                {
                    Type = BaseType.dll,
                    filename = "gdi32.dll",
                    Version = "6.2.9200.22995",
                    Oper = BaseOper.lessthan
                }
            }
        }, {
            OS = BaseOS.Windows_8_1,
            logic = {
                {
                    Type = BaseType.dll,
                    filename = "gdi32.dll",
                    Version = "6.3.9600.19650",
                    Oper = BaseOper.lessthan
                }
            }
        }, {
            OS = BaseOS.Windows_Server_2012_R2,
            logic = {
                {
                    Type = BaseType.dll,
                    filename = "gdi32.dll",
                    Version = "6.3.9600.19650",
                    Oper = BaseOper.lessthan
                }
            }
        }, {
            OS = BaseOS.Windows_10,
            logic = {
                {
                    Type = BaseType.dll,
                    filename = "gdi32.dll",
                    Version = "10.0.10240.18519",
                    Oper = BaseOper.lessthan
                }
            }
        }, {
            OS = BaseOS.Windows_10,
            logic = {
                {
                    Type = BaseType.Windows_version,
                    filename = "1709",
                    Version = "1709",
                    Oper = BaseOper.equalto
                }, {
                    Type = BaseType.dll,
                    filename = "gdi32full.dll",
                    Version = "10.0.16299.1747",
                    Oper = BaseOper.lessthan
                }
            }
        }, {
            OS = BaseOS.Windows_10,
            logic = {
                {
                    Type = BaseType.Windows_version,
                    filename = "1803",
                    Version = "1803",
                    Oper = BaseOper.equalto
                }, {
                    Type = BaseType.dll,
                    filename = "gdi32full.dll",
                    Version = "10.0.17134.1365",
                    Oper = BaseOper.lessthan
                }
            }
        }, {
            OS = BaseOS.Windows_10,
            logic = {
                {
                    Type = BaseType.Windows_version,
                    filename = "1809",
                    Version = "1809",
                    Oper = BaseOper.equalto
                }, {
                    Type = BaseType.Windows_build,
                    filename = "17763",
                    Version = "17763",
                    Oper = BaseOper.equalto
                }, {
                    Type = BaseType.Windows_revison_number,
                    filename = "1098",
                    Version = "1098",
                    Oper = BaseOper.lessthan
                }
            }
        }, {
            OS = BaseOS.Windows_10,
            logic = {
                {
                    Type = BaseType.Windows_version,
                    filename = "1903",
                    Version = "1903",
                    Oper = BaseOper.equalto
                }, {
                    Type = BaseType.kb,
                    filename = "KB4540673",
                    Version = "4540673",
                    Oper = BaseOper.notinstalled
                }, {
                    Type = BaseType.Windows_build,
                    filename = "18362",
                    Version = "18362",
                    Oper = BaseOper.equalto
                }, {
                    Type = BaseType.Windows_revison_number,
                    filename = "719",
                    Version = "719",
                    Oper = BaseOper.lessthan
                }
            }
        }, {
            OS = BaseOS.Windows_10,
            logic = {
                {
                    Type = BaseType.Windows_version,
                    filename = "1903",
                    Version = "1903",
                    Oper = BaseOper.equalto
                }, {
                    Type = BaseType.kb,
                    filename = "KB4540673",
                    Version = "4540673",
                    Oper = BaseOper.notinstalled
                }, {
                    Type = BaseType.Windows_build,
                    filename = "18363",
                    Version = "18363",
                    Oper = BaseOper.equalto
                }, {
                    Type = BaseType.Windows_revison_number,
                    filename = "719",
                    Version = "719",
                    Oper = BaseOper.lessthan
                }
            }
        }, {
            OS = BaseOS.Windows_Server_2016,
            logic = {
                {
                    Type = BaseType.dll,
                    filename = "gdi32full.dll",
                    Version = "10.0.14393.3564",
                    Oper = BaseOper.lessthan
                }
            }
        }, {
            OS = BaseOS.Windows_Server_2019,
            logic = {
                {
                    Type = BaseType.kb,
                    filename = "KB4538461",
                    Version = "4538461",
                    Oper = BaseOper.notinstalled
                }, {
                    Type = BaseType.Windows_build,
                    filename = "17763",
                    Version = "17763",
                    Oper = BaseOper.lessthan
                }, {
                    Type = BaseType.Windows_revison_number,
                    filename = "1098",
                    Version = "1098",
                    Oper = BaseOper.lessthan
                }
            }
        }
    }
}

AddModule(CVE_2020_0774)

local allrule = GetModule()


local result = {}

function ScanFun()
    local result = "{\"result\":["
	local bfind = false
---扫描所有规则
    for _, v in pairs(allrule) do 
		if v:Scan() then
			local PatchId,CVEId,description = v:createScanResult()
			if bfind then
				result = table.concat{result, ",{\"Patchid\":\"", PatchId, "\",\"CveId\":\"",CVEId,"\",\"desc\":\"", description, "\"}"}
			else
				result = table.concat{result, "{\"Patchid\":\"", PatchId, "\",\"CveId\":\"",CVEId,"\",\"desc\":\"", description, "\"}"}
			end
			bfind = true
		end 
	end

	result = table.concat{result, "]}"}
    print(result)
    return result
end

--ScanFun()
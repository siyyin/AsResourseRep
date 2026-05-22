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

RHSA_2020_0086_Rule = VulRule:new()

RHSA_2020_0086 = RHSA_2020_0086_Rule:new{
PatchId = "RHSA-2020:0086",
CVEId = "CVE-2019-17026",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "68.4.1-1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0086)

RHSA_2020_0123_Rule = VulRule:new()

RHSA_2020_0123 = RHSA_2020_0123_Rule:new{
PatchId = "RHSA-2020:0123",
CVEId = "CVE-2019-17024",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "68.4.1-2.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0123)

RHSA_2020_0157_Rule = VulRule:new()

RHSA_2020_0157 = RHSA_2020_0157_Rule:new{
PatchId = "RHSA-2020:0157",
CVEId = "CVE-2020-2659",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk",Version = "1.8.0.242.b07-1.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-debug",Version = "1.8.0.242.b07-1.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-demo",Version = "1.8.0.242.b07-1.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-demo-debug",Version = "1.8.0.242.b07-1.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-devel",Version = "1.8.0.242.b07-1.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-devel-debug",Version = "1.8.0.242.b07-1.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-headless",Version = "1.8.0.242.b07-1.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-headless-debug",Version = "1.8.0.242.b07-1.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-javadoc",Version = "1.8.0.242.b07-1.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-javadoc-debug",Version = "1.8.0.242.b07-1.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-src",Version = "1.8.0.242.b07-1.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-src-debug",Version = "1.8.0.242.b07-1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0157)

RHSA_2020_0197_Rule = VulRule:new()

RHSA_2020_0197 = RHSA_2020_0197_Rule:new{
PatchId = "RHSA-2020:0197",
CVEId = "CVE-2019-17626",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "python-reportlab",Version = "2.3-3.el6_10.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "python-reportlab-docs",Version = "2.3-3.el6_10.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0197)

RHSA_2020_0199_Rule = VulRule:new()

RHSA_2020_0199 = RHSA_2020_0199_Rule:new{
PatchId = "RHSA-2020:0199",
CVEId = "CVE-2019-5544",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "openslp",Version = "2.0.0-4.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "openslp-devel",Version = "2.0.0-4.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "openslp-server",Version = "2.0.0-4.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0199)

RHSA_2020_0316_Rule = VulRule:new()

RHSA_2020_0316 = RHSA_2020_0316_Rule:new{
PatchId = "RHSA-2020:0316",
CVEId = "CVE-2018-17456",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "emacs-git",Version = "1.7.1-10.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "emacs-git-el",Version = "1.7.1-10.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "git",Version = "1.7.1-10.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "git-all",Version = "1.7.1-10.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "git-cvs",Version = "1.7.1-10.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "git-daemon",Version = "1.7.1-10.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "git-email",Version = "1.7.1-10.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "git-gui",Version = "1.7.1-10.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "git-svn",Version = "1.7.1-10.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "gitk",Version = "1.7.1-10.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "gitweb",Version = "1.7.1-10.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "perl-Git",Version = "1.7.1-10.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0316)

RHSA_2020_0471_Rule = VulRule:new()

RHSA_2020_0471 = RHSA_2020_0471_Rule:new{
PatchId = "RHSA-2020:0471",
CVEId = "CVE-2018-10893",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "spice-glib",Version = "0.26-8.el6_10.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "spice-glib-devel",Version = "0.26-8.el6_10.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "spice-gtk",Version = "0.26-8.el6_10.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "spice-gtk-devel",Version = "0.26-8.el6_10.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "spice-gtk-python",Version = "0.26-8.el6_10.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "spice-gtk-tools",Version = "0.26-8.el6_10.2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0471)

RHSA_2020_0515_Rule = VulRule:new()

RHSA_2020_0515 = RHSA_2020_0515_Rule:new{
PatchId = "RHSA-2020:0515",
CVEId = "CVE-2019-14868",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "ksh",Version = "20120801-38.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0515)

RHSA_2020_0521_Rule = VulRule:new()

RHSA_2020_0521 = RHSA_2020_0521_Rule:new{
PatchId = "RHSA-2020:0521",
CVEId = "CVE-2020-6800",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "68.5.0-2.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0521)

RHSA_2020_0574_Rule = VulRule:new()

RHSA_2020_0574 = RHSA_2020_0574_Rule:new{
PatchId = "RHSA-2020:0574",
CVEId = "CVE-2020-6798",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "68.5.0-1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0574)

RHSA_2020_0631_Rule = VulRule:new()

RHSA_2020_0631 = RHSA_2020_0631_Rule:new{
PatchId = "RHSA-2020:0631",
CVEId = "CVE-2020-8597",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "ppp",Version = "2.4.5-11.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "ppp-devel",Version = "2.4.5-11.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0631)

RHSA_2020_0632_Rule = VulRule:new()

RHSA_2020_0632 = RHSA_2020_0632_Rule:new{
PatchId = "RHSA-2020:0632",
CVEId = "CVE-2020-2654",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.0-openjdk",Version = "1.7.0.251-2.6.21.0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.0-openjdk-demo",Version = "1.7.0.251-2.6.21.0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.0-openjdk-devel",Version = "1.7.0.251-2.6.21.0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.0-openjdk-javadoc",Version = "1.7.0.251-2.6.21.0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.0-openjdk-src",Version = "1.7.0.251-2.6.21.0.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0632)

RHSA_2020_0702_Rule = VulRule:new()

RHSA_2020_0702 = RHSA_2020_0702_Rule:new{
PatchId = "RHSA-2020:0702",
CVEId = "CVE-2018-1311",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "xerces-c",Version = "3.0.1-21.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "xerces-c-devel",Version = "3.0.1-21.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "xerces-c-doc",Version = "3.0.1-21.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0702)

RHSA_2020_0726_Rule = VulRule:new()

RHSA_2020_0726 = RHSA_2020_0726_Rule:new{
PatchId = "RHSA-2020:0726",
CVEId = "CVE-2019-18634",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "sudo",Version = "1.8.6p3-29.el6_10.3",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "sudo-devel",Version = "1.8.6p3-29.el6_10.3",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0726)

RHSA_2020_0775_Rule = VulRule:new()

RHSA_2020_0775 = RHSA_2020_0775_Rule:new{
PatchId = "RHSA-2020:0775",
CVEId = "CVE-2020-7039",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-guest-agent",Version = "0.12.1.2-2.506.el6_10.6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-img",Version = "0.12.1.2-2.506.el6_10.6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm",Version = "0.12.1.2-2.506.el6_10.6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-tools",Version = "0.12.1.2-2.506.el6_10.6",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0775)

RHSA_2020_0790_Rule = VulRule:new()

RHSA_2020_0790 = RHSA_2020_0790_Rule:new{
PatchId = "RHSA-2020:0790",
CVEId = "CVE-2019-17133",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-bootwrapper",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-firmware",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump-devel",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python-perf",Version = "2.6.32-754.28.1.el6",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0790)

RHSA_2020_0816_Rule = VulRule:new()

RHSA_2020_0816 = RHSA_2020_0816_Rule:new{
PatchId = "RHSA-2020:0816",
CVEId = "CVE-2020-6814",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "68.6.0-1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0816)

RHSA_2020_0892_Rule = VulRule:new()

RHSA_2020_0892 = RHSA_2020_0892_Rule:new{
PatchId = "RHSA-2020:0892",
CVEId = "CVE-2019-20044",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "zsh",Version = "4.3.11-11.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "zsh-html",Version = "4.3.11-11.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0892)

RHSA_2020_0896_Rule = VulRule:new()

RHSA_2020_0896 = RHSA_2020_0896_Rule:new{
PatchId = "RHSA-2020:0896",
CVEId = "CVE-2020-10531",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "icu",Version = "4.2.1-15.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "libicu",Version = "4.2.1-15.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "libicu-devel",Version = "4.2.1-15.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "libicu-doc",Version = "4.2.1-15.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0896)

RHSA_2020_0898_Rule = VulRule:new()

RHSA_2020_0898 = RHSA_2020_0898_Rule:new{
PatchId = "RHSA-2020:0898",
CVEId = "CVE-2020-5312",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "python-imaging",Version = "1.1.6-20.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "python-imaging-devel",Version = "1.1.6-20.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "python-imaging-sane",Version = "1.1.6-20.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "python-imaging-tk",Version = "1.1.6-20.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0898)

RHSA_2020_0912_Rule = VulRule:new()

RHSA_2020_0912 = RHSA_2020_0912_Rule:new{
PatchId = "RHSA-2020:0912",
CVEId = "CVE-2020-1938",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat6",Version = "6.0.24-114.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat6-admin-webapps",Version = "6.0.24-114.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat6-docs-webapp",Version = "6.0.24-114.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat6-el-2.1-api",Version = "6.0.24-114.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat6-javadoc",Version = "6.0.24-114.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat6-jsp-2.1-api",Version = "6.0.24-114.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat6-lib",Version = "6.0.24-114.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat6-servlet-2.5-api",Version = "6.0.24-114.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat6-webapps",Version = "6.0.24-114.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0912)

RHSA_2020_0914_Rule = VulRule:new()

RHSA_2020_0914 = RHSA_2020_0914_Rule:new{
PatchId = "RHSA-2020:0914",
CVEId = "CVE-2020-6812",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "68.6.0-1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_0914)

RHSA_2020_1331_Rule = VulRule:new()

RHSA_2020_1331 = RHSA_2020_1331_Rule:new{
PatchId = "RHSA-2020:1331",
CVEId = "CVE-2020-5208",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "ipmitool",Version = "1.8.15-3.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1331)

RHSA_2020_1335_Rule = VulRule:new()

RHSA_2020_1335 = RHSA_2020_1335_Rule:new{
PatchId = "RHSA-2020:1335",
CVEId = "CVE-2020-10188",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "telnet-server",Version = "0.17-49.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "krb5-appl-servers",Version = "1.0.1-10.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1335)

RHSA_2020_1339_Rule = VulRule:new()

RHSA_2020_1339 = RHSA_2020_1339_Rule:new{
PatchId = "RHSA-2020:1339",
CVEId = "CVE-2020-6820",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "68.6.1-1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1339)

RHSA_2020_1403_Rule = VulRule:new()

RHSA_2020_1403 = RHSA_2020_1403_Rule:new{
PatchId = "RHSA-2020:1403",
CVEId = "CVE-2020-8608",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-guest-agent",Version = "0.12.1.2-2.506.el6_10.7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-img",Version = "0.12.1.2-2.506.el6_10.7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm",Version = "0.12.1.2-2.506.el6_10.7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-tools",Version = "0.12.1.2-2.506.el6_10.7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1403)

RHSA_2020_1429_Rule = VulRule:new()

RHSA_2020_1429 = RHSA_2020_1429_Rule:new{
PatchId = "RHSA-2020:1429",
CVEId = "CVE-2020-6825",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "68.7.0-2.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1429)

RHSA_2020_1488_Rule = VulRule:new()

RHSA_2020_1488 = RHSA_2020_1488_Rule:new{
PatchId = "RHSA-2020:1488",
CVEId = "CVE-2020-6822",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "68.7.0-1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1488)

RHSA_2020_1506_Rule = VulRule:new()

RHSA_2020_1506 = RHSA_2020_1506_Rule:new{
PatchId = "RHSA-2020:1506",
CVEId = "CVE-2020-2830",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk",Version = "1.8.0.252.b09-2.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-debug",Version = "1.8.0.252.b09-2.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-demo",Version = "1.8.0.252.b09-2.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-demo-debug",Version = "1.8.0.252.b09-2.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-devel",Version = "1.8.0.252.b09-2.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-devel-debug",Version = "1.8.0.252.b09-2.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-headless",Version = "1.8.0.252.b09-2.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-headless-debug",Version = "1.8.0.252.b09-2.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-javadoc",Version = "1.8.0.252.b09-2.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-javadoc-debug",Version = "1.8.0.252.b09-2.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-src",Version = "1.8.0.252.b09-2.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-src-debug",Version = "1.8.0.252.b09-2.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1506)

RHSA_2020_1508_Rule = VulRule:new()

RHSA_2020_1508 = RHSA_2020_1508_Rule:new{
PatchId = "RHSA-2020:1508",
CVEId = "CVE-2020-2805",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.0-openjdk",Version = "1.7.0.261-2.6.22.1.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.0-openjdk-demo",Version = "1.7.0.261-2.6.22.1.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.0-openjdk-devel",Version = "1.7.0.261-2.6.22.1.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.0-openjdk-javadoc",Version = "1.7.0.261-2.6.22.1.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.7.0-openjdk-src",Version = "1.7.0.261-2.6.22.1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1508)

RHSA_2020_1524_Rule = VulRule:new()

RHSA_2020_1524 = RHSA_2020_1524_Rule:new{
PatchId = "RHSA-2020:1524",
CVEId = "CVE-2019-17666",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-bootwrapper",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-firmware",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump-devel",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python-perf",Version = "2.6.32-754.29.1.el6",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1524)

RHSA_2020_1962_Rule = VulRule:new()

RHSA_2020_1962 = RHSA_2020_1962_Rule:new{
PatchId = "RHSA-2020:1962",
CVEId = "CVE-2020-10108",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "python-twisted-web",Version = "8.2.0-6.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_1962)

RHSA_2020_2036_Rule = VulRule:new()

RHSA_2020_2036 = RHSA_2020_2036_Rule:new{
PatchId = "RHSA-2020:2036",
CVEId = "CVE-2020-6831",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "68.8.0-1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2036)

RHSA_2020_2049_Rule = VulRule:new()

RHSA_2020_2049 = RHSA_2020_2049_Rule:new{
PatchId = "RHSA-2020:2049",
CVEId = "CVE-2020-12397",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "68.8.0-1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2049)

RHSA_2020_2103_Rule = VulRule:new()

RHSA_2020_2103 = RHSA_2020_2103_Rule:new{
PatchId = "RHSA-2020:2103",
CVEId = "CVE-2020-10711",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-bootwrapper",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-firmware",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump-devel",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python-perf",Version = "2.6.32-754.29.2.el6",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2103)

RHSA_2020_2378_Rule = VulRule:new()

RHSA_2020_2378 = RHSA_2020_2378_Rule:new{
PatchId = "RHSA-2020:2378",
CVEId = "CVE-2020-12410",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "68.9.0-1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2378)

RHSA_2020_2383_Rule = VulRule:new()

RHSA_2020_2383 = RHSA_2020_2383_Rule:new{
PatchId = "RHSA-2020:2383",
CVEId = "CVE-2020-8617",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "bind",Version = "9.8.2-0.68.rc1.el6_10.7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-chroot",Version = "9.8.2-0.68.rc1.el6_10.7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-devel",Version = "9.8.2-0.68.rc1.el6_10.7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-libs",Version = "9.8.2-0.68.rc1.el6_10.7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-sdb",Version = "9.8.2-0.68.rc1.el6_10.7",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-utils",Version = "9.8.2-0.68.rc1.el6_10.7",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2383)

RHSA_2020_2406_Rule = VulRule:new()

RHSA_2020_2406 = RHSA_2020_2406_Rule:new{
PatchId = "RHSA-2020:2406",
CVEId = "CVE-2020-13398",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "freerdp",Version = "1.0.2-7.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "freerdp-devel",Version = "1.0.2-7.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "freerdp-libs",Version = "1.0.2-7.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "freerdp-plugins",Version = "1.0.2-7.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2406)

RHSA_2020_2430_Rule = VulRule:new()

RHSA_2020_2430 = RHSA_2020_2430_Rule:new{
PatchId = "RHSA-2020:2430",
CVEId = "CVE-2017-12192",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-bootwrapper",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-firmware",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump-devel",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python-perf",Version = "2.6.32-754.30.2.el6",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2430)

RHSA_2020_2433_Rule = VulRule:new()

RHSA_2020_2433 = RHSA_2020_2433_Rule:new{
PatchId = "RHSA-2020:2433",
CVEId = "CVE-2020-0549",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "microcode_ctl",Version = "1.17-33.26.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2433)

RHSA_2020_2516_Rule = VulRule:new()

RHSA_2020_2516 = RHSA_2020_2516_Rule:new{
PatchId = "RHSA-2020:2516",
CVEId = "CVE-2020-13112",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "libexif",Version = "0.6.21-6.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "libexif-devel",Version = "0.6.21-6.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2516)

RHSA_2020_2529_Rule = VulRule:new()

RHSA_2020_2529 = RHSA_2020_2529_Rule:new{
PatchId = "RHSA-2020:2529",
CVEId = "CVE-2020-9484",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat6",Version = "6.0.24-115.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat6-admin-webapps",Version = "6.0.24-115.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat6-docs-webapp",Version = "6.0.24-115.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat6-el-2.1-api",Version = "6.0.24-115.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat6-javadoc",Version = "6.0.24-115.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat6-jsp-2.1-api",Version = "6.0.24-115.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat6-lib",Version = "6.0.24-115.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat6-servlet-2.5-api",Version = "6.0.24-115.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "tomcat6-webapps",Version = "6.0.24-115.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2529)

RHSA_2020_2613_Rule = VulRule:new()

RHSA_2020_2613 = RHSA_2020_2613_Rule:new{
PatchId = "RHSA-2020:2613",
CVEId = "CVE-2020-12406",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "68.9.0-1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2613)

RHSA_2020_2640_Rule = VulRule:new()

RHSA_2020_2640 = RHSA_2020_2640_Rule:new{
PatchId = "RHSA-2020:2640",
CVEId = "CVE-2020-12663",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "unbound",Version = "1.4.20-29.el6_10.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "unbound-devel",Version = "1.4.20-29.el6_10.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "unbound-libs",Version = "1.4.20-29.el6_10.1",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "unbound-python",Version = "1.4.20-29.el6_10.1",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2640)

RHSA_2020_2824_Rule = VulRule:new()

RHSA_2020_2824 = RHSA_2020_2824_Rule:new{
PatchId = "RHSA-2020:2824",
CVEId = "CVE-2020-12421",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "68.10.0-1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2824)

RHSA_2020_2933_Rule = VulRule:new()

RHSA_2020_2933 = RHSA_2020_2933_Rule:new{
PatchId = "RHSA-2020:2933",
CVEId = "CVE-2019-18660",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-bootwrapper",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-firmware",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump-devel",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python-perf",Version = "2.6.32-754.31.1.el6",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2933)

RHSA_2020_2966_Rule = VulRule:new()

RHSA_2020_2966 = RHSA_2020_2966_Rule:new{
PatchId = "RHSA-2020:2966",
CVEId = "CVE-2020-15646",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "68.10.0-1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2966)

RHSA_2020_2985_Rule = VulRule:new()

RHSA_2020_2985 = RHSA_2020_2985_Rule:new{
PatchId = "RHSA-2020:2985",
CVEId = "CVE-2020-14621",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk",Version = "1.8.0.262.b10-0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-debug",Version = "1.8.0.262.b10-0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-demo",Version = "1.8.0.262.b10-0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-demo-debug",Version = "1.8.0.262.b10-0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-devel",Version = "1.8.0.262.b10-0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-devel-debug",Version = "1.8.0.262.b10-0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-headless",Version = "1.8.0.262.b10-0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-headless-debug",Version = "1.8.0.262.b10-0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-javadoc",Version = "1.8.0.262.b10-0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-javadoc-debug",Version = "1.8.0.262.b10-0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-src",Version = "1.8.0.262.b10-0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-src-debug",Version = "1.8.0.262.b10-0.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_2985)

RHSA_2020_3233_Rule = VulRule:new()

RHSA_2020_3233 = RHSA_2020_3233_Rule:new{
PatchId = "RHSA-2020:3233",
CVEId = "CVE-2020-6514",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "68.11.0-1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3233)

RHSA_2020_3284_Rule = VulRule:new()

RHSA_2020_3284 = RHSA_2020_3284_Rule:new{
PatchId = "RHSA-2020:3284",
CVEId = "CVE-2020-13692",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "postgresql-jdbc",Version = "8.4.704-4.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3284)

RHSA_2020_3345_Rule = VulRule:new()

RHSA_2020_3345 = RHSA_2020_3345_Rule:new{
PatchId = "RHSA-2020:3345",
CVEId = "CVE-2020-6463",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "68.11.0-1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3345)

RHSA_2020_3548_Rule = VulRule:new()

RHSA_2020_3548 = RHSA_2020_3548_Rule:new{
PatchId = "RHSA-2020:3548",
CVEId = "CVE-2019-14896",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-bootwrapper",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-firmware",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump-devel",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python-perf",Version = "2.6.32-754.33.1.el6",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3548)

RHSA_2020_3558_Rule = VulRule:new()

RHSA_2020_3558 = RHSA_2020_3558_Rule:new{
PatchId = "RHSA-2020:3558",
CVEId = "CVE-2020-15669",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "68.12.0-1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3558)

RHSA_2020_3643_Rule = VulRule:new()

RHSA_2020_3643 = RHSA_2020_3643_Rule:new{
PatchId = "RHSA-2020:3643",
CVEId = "CVE-2020-15664",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "68.12.0-1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3643)

RHSA_2020_3835_Rule = VulRule:new()

RHSA_2020_3835 = RHSA_2020_3835_Rule:new{
PatchId = "RHSA-2020:3835",
CVEId = "CVE-2020-15678",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "78.3.0-1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_3835)

RHSA_2020_4056_Rule = VulRule:new()

RHSA_2020_4056 = RHSA_2020_4056_Rule:new{
PatchId = "RHSA-2020:4056",
CVEId = "CVE-2020-14364",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-guest-agent",Version = "0.12.1.2-2.506.el6_10.8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-img",Version = "0.12.1.2-2.506.el6_10.8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm",Version = "0.12.1.2-2.506.el6_10.8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "qemu-kvm-tools",Version = "0.12.1.2-2.506.el6_10.8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4056)

RHSA_2020_4158_Rule = VulRule:new()

RHSA_2020_4158 = RHSA_2020_4158_Rule:new{
PatchId = "RHSA-2020:4158",
CVEId = "CVE-2020-15677",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "78.3.1-1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4158)

RHSA_2020_4182_Rule = VulRule:new()

RHSA_2020_4182 = RHSA_2020_4182_Rule:new{
PatchId = "RHSA-2020:4182",
CVEId = "CVE-2019-11487",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.35.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "2.6.32-754.35.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.35.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "2.6.32-754.35.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.35.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "2.6.32-754.35.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.35.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump",Version = "2.6.32-754.35.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.35.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump-devel",Version = "2.6.32-754.35.1.el6",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4182)

RHSA_2020_4183_Rule = VulRule:new()

RHSA_2020_4183 = RHSA_2020_4183_Rule:new{
PatchId = "RHSA-2020:4183",
CVEId = "CVE-2020-8622",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "bind",Version = "9.8.2-0.68.rc1.el6_10.8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-chroot",Version = "9.8.2-0.68.rc1.el6_10.8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-devel",Version = "9.8.2-0.68.rc1.el6_10.8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-libs",Version = "9.8.2-0.68.rc1.el6_10.8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-sdb",Version = "9.8.2-0.68.rc1.el6_10.8",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-utils",Version = "9.8.2-0.68.rc1.el6_10.8",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4183)

RHSA_2020_4330_Rule = VulRule:new()

RHSA_2020_4330 = RHSA_2020_4330_Rule:new{
PatchId = "RHSA-2020:4330",
CVEId = "CVE-2020-15969",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "78.4.0-2.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4330)

RHSA_2020_4348_Rule = VulRule:new()

RHSA_2020_4348 = RHSA_2020_4348_Rule:new{
PatchId = "RHSA-2020:4348",
CVEId = "CVE-2020-14803",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk",Version = "1.8.0.272.b10-0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-debug",Version = "1.8.0.272.b10-0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-demo",Version = "1.8.0.272.b10-0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-demo-debug",Version = "1.8.0.272.b10-0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-devel",Version = "1.8.0.272.b10-0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-devel-debug",Version = "1.8.0.272.b10-0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-headless",Version = "1.8.0.272.b10-0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-headless-debug",Version = "1.8.0.272.b10-0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-javadoc",Version = "1.8.0.272.b10-0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-javadoc-debug",Version = "1.8.0.272.b10-0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-src",Version = "1.8.0.272.b10-0.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "java-1.8.0-openjdk-src-debug",Version = "1.8.0.272.b10-0.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4348)

RHSA_2020_4946_Rule = VulRule:new()

RHSA_2020_4946 = RHSA_2020_4946_Rule:new{
PatchId = "RHSA-2020:4946",
CVEId = "CVE-2020-14363",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "libX11",Version = "1.6.4-4.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "libX11-common",Version = "1.6.4-4.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "libX11-devel",Version = "1.6.4-4.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4946)

RHSA_2020_4947_Rule = VulRule:new()

RHSA_2020_4947 = RHSA_2020_4947_Rule:new{
PatchId = "RHSA-2020:4947",
CVEId = "CVE-2020-15683",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "78.4.0-1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4947)

RHSA_2020_4953_Rule = VulRule:new()

RHSA_2020_4953 = RHSA_2020_4953_Rule:new{
PatchId = "RHSA-2020:4953",
CVEId = "CVE-2020-14362",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-Xdmx",Version = "1.17.4-18.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-Xephyr",Version = "1.17.4-18.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-Xnest",Version = "1.17.4-18.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-Xorg",Version = "1.17.4-18.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-Xvfb",Version = "1.17.4-18.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-common",Version = "1.17.4-18.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-devel",Version = "1.17.4-18.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "xorg-x11-server-source",Version = "1.17.4-18.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_4953)

RHSA_2020_5084_Rule = VulRule:new()

RHSA_2020_5084 = RHSA_2020_5084_Rule:new{
PatchId = "RHSA-2020:5084",
CVEId = "CVE-2020-8698",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "microcode_ctl",Version = "1.17-33.31.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5084)

RHSA_2020_5104_Rule = VulRule:new()

RHSA_2020_5104 = RHSA_2020_5104_Rule:new{
PatchId = "RHSA-2020:5104",
CVEId = "CVE-2020-26950",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "78.4.1-1.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "78.4.3-1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5104)

RHSA_2020_5129_Rule = VulRule:new()

RHSA_2020_5129 = RHSA_2020_5129_Rule:new{
PatchId = "RHSA-2020:5129",
CVEId = "CVE-2020-15862",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp",Version = "5.5-60.el6_10.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-devel",Version = "5.5-60.el6_10.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-libs",Version = "5.5-60.el6_10.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-perl",Version = "5.5-60.el6_10.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-python",Version = "5.5-60.el6_10.2",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "net-snmp-utils",Version = "5.5-60.el6_10.2",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5129)

RHSA_2020_5238_Rule = VulRule:new()

RHSA_2020_5238 = RHSA_2020_5238_Rule:new{
PatchId = "RHSA-2020:5238",
CVEId = "CVE-2020-26968",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "thunderbird",Version = "78.5.0-1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5238)

RHSA_2020_5257_Rule = VulRule:new()

RHSA_2020_5257 = RHSA_2020_5257_Rule:new{
PatchId = "RHSA-2020:5257",
CVEId = "CVE-2020-26965",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "firefox",Version = "78.5.0-1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2020_5257)

RHSA_2021_0056_Rule = VulRule:new()

RHSA_2021_0056 = RHSA_2021_0056_Rule:new{
PatchId = "RHSA-2021:0056",
CVEId = "CVE-2020-1971",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl",Version = "1.0.1e-59.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl-devel",Version = "1.0.1e-59.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl-perl",Version = "1.0.1e-59.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "openssl-static",Version = "1.0.1e-59.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0056)

RHSA_2021_0181_Rule = VulRule:new()

RHSA_2021_0181 = RHSA_2021_0181_Rule:new{
PatchId = "RHSA-2021:0181",
CVEId = "CVE-2014-4508",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-bootwrapper",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-firmware",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump-devel",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python-perf",Version = "2.6.32-754.36.1.el6",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0181)

RHSA_2021_0227_Rule = VulRule:new()

RHSA_2021_0227 = RHSA_2021_0227_Rule:new{
PatchId = "RHSA-2021:0227",
CVEId = "CVE-2021-3156",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "sudo",Version = "1.8.6p3-29.el6_10.4",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "sudo-devel",Version = "1.8.6p3-29.el6_10.4",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0227)

RHSA_2021_0672_Rule = VulRule:new()

RHSA_2021_0672 = RHSA_2021_0672_Rule:new{
PatchId = "RHSA-2021:0672",
CVEId = "CVE-2020-8625",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "bind",Version = "9.8.2-0.68.rc1.el6_10.10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-chroot",Version = "9.8.2-0.68.rc1.el6_10.10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-devel",Version = "9.8.2-0.68.rc1.el6_10.10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-libs",Version = "9.8.2-0.68.rc1.el6_10.10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-sdb",Version = "9.8.2-0.68.rc1.el6_10.10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-utils",Version = "9.8.2-0.68.rc1.el6_10.10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_0672)

RHSA_2021_1288_Rule = VulRule:new()

RHSA_2021_1288 = RHSA_2021_1288_Rule:new{
PatchId = "RHSA-2021:1288",
CVEId = "CVE-2021-27365",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.39.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "2.6.32-754.39.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.39.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "2.6.32-754.39.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.39.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "2.6.32-754.39.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.39.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "2.6.32-754.39.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.39.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "2.6.32-754.39.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.39.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "2.6.32-754.39.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.39.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-firmware",Version = "2.6.32-754.39.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.39.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-headers",Version = "2.6.32-754.39.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.39.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump",Version = "2.6.32-754.39.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.39.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump-devel",Version = "2.6.32-754.39.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.39.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "2.6.32-754.39.1.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.39.1.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python-perf",Version = "2.6.32-754.39.1.el6",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1288)

RHSA_2021_1468_Rule = VulRule:new()

RHSA_2021_1468 = RHSA_2021_1468_Rule:new{
PatchId = "RHSA-2021:1468",
CVEId = "CVE-2021-25215",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "bind",Version = "9.8.2-0.68.rc1.el6_10.11",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-chroot",Version = "9.8.2-0.68.rc1.el6_10.11",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-devel",Version = "9.8.2-0.68.rc1.el6_10.11",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-libs",Version = "9.8.2-0.68.rc1.el6_10.11",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-sdb",Version = "9.8.2-0.68.rc1.el6_10.11",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "bind-utils",Version = "9.8.2-0.68.rc1.el6_10.11",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_1468)

RHSA_2021_2299_Rule = VulRule:new()

RHSA_2021_2299 = RHSA_2021_2299_Rule:new{
PatchId = "RHSA-2021:2299",
CVEId = "CVE-2020-24513",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "microcode_ctl",Version = "1.17-33.33.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2299)

RHSA_2021_2419_Rule = VulRule:new()

RHSA_2021_2419 = RHSA_2021_2419_Rule:new{
PatchId = "RHSA-2021:2419",
CVEId = "CVE-2021-25217",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "dhclient",Version = "4.1.1-64.P1.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "dhcp",Version = "4.1.1-64.P1.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "dhcp-common",Version = "4.1.1-64.P1.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "dhcp-devel",Version = "4.1.1-64.P1.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2419)

RHSA_2021_2467_Rule = VulRule:new()

RHSA_2021_2467 = RHSA_2021_2467_Rule:new{
PatchId = "RHSA-2021:2467",
CVEId = "CVE-2021-27219",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2",Version = "2.28.8-11.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-devel",Version = "2.28.8-11.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-doc",Version = "2.28.8-11.el6_10",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.linux_kernel,filename = "glib2-static",Version = "2.28.8-11.el6_10",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2467)

RHSA_2021_2735_Rule = VulRule:new()

RHSA_2021_2735 = RHSA_2021_2735_Rule:new{
PatchId = "RHSA-2021:2735",
CVEId = "CVE-2021-33909",
criteria = {
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.41.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel",Version = "2.6.32-754.41.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.41.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-abi-whitelists",Version = "2.6.32-754.41.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.41.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug",Version = "2.6.32-754.41.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.41.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-debug-devel",Version = "2.6.32-754.41.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.41.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-devel",Version = "2.6.32-754.41.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.41.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-doc",Version = "2.6.32-754.41.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.41.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-firmware",Version = "2.6.32-754.41.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.41.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump",Version = "2.6.32-754.41.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.41.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "kernel-kdump-devel",Version = "2.6.32-754.41.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.41.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "perf",Version = "2.6.32-754.41.2.el6",Oper = BaseOper.lessthan}}},
{OS = BaseOS.Rhel6,
logic = {
{Type = BaseType.kernel_running,filename = "kernel",Version = "2.6.32-754.41.2.el6",Oper = BaseOper.lessthan},
{Type = BaseType.linux_kernel,filename = "python-perf",Version = "2.6.32-754.41.2.el6",Oper = BaseOper.lessthan}}}}
}

AddModule(RHSA_2021_2735)





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
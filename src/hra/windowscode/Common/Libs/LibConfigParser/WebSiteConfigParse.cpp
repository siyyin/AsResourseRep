#include "WebSiteConfigParse.h"
#include <fstream>
#include "utility/Logger.h"
#include "utility/HraUtils.h"
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

void ConfigTree::ConfigTreeInit(TreeNode* root)
{
    this->root = root;
}

void ConfigTree::PutChild(const std::string& key, const std::string& value, TreeNode* node, TreeNode* parent)
{
    if (node == NULL)
    {
        return;
    }
    node->key   = key;
    node->value = value;
    if (parent != NULL)
    {
        parent->children.push_back(node);
    }
    node->Parent = parent;
}

TreeNode* ConfigTree::GetParent(TreeNode* node)
{
    if (node == NULL)
    {
        LOG_WARN("A serious Syntax error occurred in nginx parsing!");
        return NULL;
    }
    return node->Parent;
}

std::string JoinValue(const std::vector<std::string>& vec, const std::string& strType)
{
    std::string strValue = "";
    if (vec.empty())
    {
        return strValue;
    }
    for (int i = 1; i < vec.size(); i++)
    {
        strValue += vec[i] + " ";
    }
    if (APACHETYPE == strType)
    {
        replace(strValue.begin(), strValue.end(), '>', ' ');
    }
    // strValue = UtilsTrimStr(strValue);
    strValue = UtilsTrim(strValue);
    strValue = UtilsTrim(strValue, "\"");
    return strValue;
}

TreeNode* ConfigParse(const std::string& strConfigfile, const std::string& strType, const std::string& strPrefix)
{
    if (strConfigfile.empty())
    {
        LOG_WARN("current file is empty");
        return NULL;
    }
    std::ifstream fInStream(strConfigfile);
    if (!fInStream.is_open())
    {
        LOG_WARN("current file:%s cannot be open!", strConfigfile.c_str());
        return NULL;
    }

    std::string commentRegex = "^\\s*#.*";
    std::string directiveRegex;
    std::string sectionOpenRegex;
    std::string sectionCloseRegex;
    std::string NginxsectionOpenRegexEX;
    if (APACHETYPE == strType)
    {
        directiveRegex    = "([^\\s])\\s*(.+)";
        sectionOpenRegex  = "\\s*<([^/\\s>]+)\\s*([^>]+)?>";
        sectionCloseRegex = "\\s*</([^\\s>]+)\\s*([^>]+)?>";
    }
    else if (NGINXTYPE == strType)
    {
        directiveRegex    = "\\s*([^\\s]+)\\s*(.+);\\s*([#]*)";
        sectionOpenRegex  = "\\s*([^\\s])\\s*(.*)\\s*\\{\\s*([#]*.*)$";
        NginxsectionOpenRegexEX = "^\\s*\\{\\s*$";
        sectionCloseRegex = "^\\s*\\}";
    }

    TreeNode* root = new (std::nothrow) TreeNode;
    if (root == NULL)
    {
        LOG_WARN("new constructor TreeNode failed!");
        return NULL;
    }
    ConfigTree tree;
    tree.ConfigTreeInit(root);

    std::string strContext, strPreValue;
    while (!fInStream.eof())
    { // 文件不结束时,逐行读取
        std::getline(fInStream, strContext);

        if (UtilsMatchRegex(commentRegex.c_str(), strContext.c_str()) == true)
        {
            continue;
        }
        else if ((strType == APACHETYPE) && UtilsMatchRegex(sectionOpenRegex.c_str(), strContext.c_str()) == true)
        {
            std::string strLine = UtilsTrim(strContext);
            std::vector<std::string> vec;
            vec = UtilsStringSplit(strLine, " ");
            if (vec.empty())
            {
                vec.push_back(strLine);
            }
            std::replace(vec[0].begin(), vec[0].end(), '<', ' ');
            std::string key   = UtilsTrim(vec[0]);
            std::string value = JoinValue(vec, strType);
            TreeNode* node    = new TreeNode;
            tree.PutChild(key, value, node, root);
            root = node;
        }
        else if (UtilsMatchRegex(sectionCloseRegex.c_str(), strContext.c_str()) == true)
        {
            root = tree.GetParent(root);
        }
        else if (UtilsMatchRegex(directiveRegex.c_str(), strContext.c_str()) == true)
        {
            std::string strLine = UtilsTrim(strContext);
            if (APACHETYPE == strType)
            {
                if (strLine[0] == '<')
                {
                    continue;
                }
                std::vector<std::string> vec;
                vec = UtilsStringSplit(strLine, " ");
                if (vec.empty())
                {
                    vec.push_back(strLine);
                }
                std::string key   = vec[0];
                std::string value = JoinValue(vec, strType);

                TreeNode* node = new TreeNode;
                tree.PutChild(key, value, node, root);
            }
            else if (NGINXTYPE == strType)
            {
                size_t indexTmp = strLine.find_first_of(";");
                strLine         = strLine.substr(0, indexTmp);
                std::vector<std::string> vec;
                vec = UtilsStringSplit(strLine, " ");
                if (vec.empty())
                {
                    vec.push_back(strLine);
                }
                if (vec.size() > 0 && _stricmp(vec.at(0).c_str(), "include") == 0)
                {
                    if (vec.size() <= 1)
                    {
                        continue;
                    }
                    std::string strPath = vec.at(1);
                    if (strPath.find(".conf") == std::string::npos)
                    {
                        continue;
                    }
                    if (PathIsRelativeA(strPath.c_str()))
                    {
                        strPath = strPrefix + strPath;
                    }

                    size_t indexTmp = strPath.find_last_of("*?[");
                    if (indexTmp == std::string::npos)
                    {
                        TreeNode* subRoot               = ConfigParse(strPath, NGINXTYPE, strPrefix);
                        if (subRoot == NULL)
                        {
                            continue;
                        }
                        std::vector<TreeNode*> subNodes = subRoot->children;
                        for (int i = 0; i < subNodes.size(); ++i)
                        {
                            if (subNodes[i] == NULL)
                            {
                                continue;
                            }
                            root->children.push_back(subNodes[i]);
                            subNodes[i]->Parent = root;
                        }
                        delete subRoot;
                        subRoot = NULL;
                    }
                    else
                    {
                        std::vector<std::string> vecWildPath;
                        ExtractWildCardPath(vecWildPath, strPath);
                        for (auto it = vecWildPath.begin(); it != vecWildPath.end(); ++it)
                        {
                            LOG_DEBUG("ExtractWildCardPath() extract current subPath:%s", it->c_str());
                            TreeNode* subRoot               = ConfigParse(it->c_str(), NGINXTYPE, strPrefix);
                            if (subRoot == NULL)
                            {
                                continue;
                            }
                            std::vector<TreeNode*> subNodes = subRoot->children;
                            for (int i = 0; i < subNodes.size(); ++i)
                            {
                                if (subNodes[i] == NULL)
                                {
                                    continue;
                                }
                                root->children.push_back(subNodes[i]);
                                subNodes[i]->Parent = root;
                            }
                            delete subRoot;
                            subRoot = NULL;
                        }
                    }
                }
                else
                {
                    std::string key;
                    if (vec.size() > 0)
                    {
                        key = vec[0];
                    }
                    std::string value = JoinValue(vec, NGINXTYPE);
                    TreeNode* node    = new TreeNode;
                    tree.PutChild(key, value, node, root);
                }
            }
        }
        else if ((strType == NGINXTYPE) && UtilsMatchRegex(sectionOpenRegex.c_str(), strContext.c_str()) == true)
        {
            std::string strLine = UtilsTrim(strContext);
            std::vector<std::string> vec;
            size_t indexTmp = strLine.find_first_of("{");
            strLine         = strLine.substr(0, indexTmp);
            vec             = UtilsStringSplit(strLine, " ");
            if (vec.empty())
            {
                vec.push_back(strLine);
            }
            std::string key   = UtilsTrim(vec[0]);
            std::string value = JoinValue(vec, strType);
            TreeNode* node    = new TreeNode;
            tree.PutChild(key, value, node, root);
            root = node;
        }
        else if ((strType == NGINXTYPE) && UtilsMatchRegex(NginxsectionOpenRegexEX.c_str(), strContext.c_str()) == true)
        {
            std::string strLine = UtilsTrim(strContext);
            std::vector<std::string> vec;
            vec.push_back(strLine);
            std::string key   = UtilsTrim(vec[0]);
            std::string value = JoinValue(vec, strType);
            TreeNode* node    = new TreeNode;
            tree.PutChild(key, value, node, root);
            root = node;
        }
        else
        {
            strPreValue.assign(strContext.c_str(), strContext.size());
            continue;
        }
    }

    fInStream.close();
    return root;
}

void TreeFindInclude(TreeNode* root, std::vector<std::string>& vecPath)
{
    if (root == NULL)
    {
        return;
    }
    std::vector<TreeNode*> nodes = root->children;
    for (int i = 0; i < nodes.size(); ++i)
    {
        if (nodes[i]->children.size() > 0)
        {
            TreeFindInclude(nodes[i], vecPath);
        }
        else if (_stricmp(nodes[i]->key.c_str(), "Include") == 0 ||
                 _stricmp(nodes[i]->key.c_str(), "IncludeOptional") == 0)
        {
            std::string strPath = UtilsTrim(nodes[i]->value, "\"");
            vecPath.push_back(strPath);
        }
    }
}

void FreeNode(TreeNode* root)
{
    if (root == NULL)
    {
        return;
    }
    std::vector<TreeNode*> nodes = root->children;
    for (int i = 0; i < nodes.size(); ++i)
    {
        if (nodes[i] == NULL)
        {
            continue;
        }
        if (nodes[i]->children.size() > 0)
        {
            FreeNode(nodes[i]);
        }
        else
        {
            if (nodes[i])
            {
                delete nodes[i];
                nodes[i] = NULL;
            }
        }
    }
    if (root)
    {
        delete root;
        root = NULL;
    }
}

void TranverseTree(TreeNode* root)
{
    if (root == NULL)
    {
        LOG_WARN("start TranverseTree, but root = NULL");
        return;
    }
    std::vector<TreeNode*> nodes = root->children;
    LOG_DEBUG("child size:[%u]", (unsigned int)(nodes.size()));
    for (int i = 0; i < nodes.size(); ++i)
    {
        if (nodes[i]->children.size() > 0)
        {
            TranverseTree(nodes[i]);
        }
        else
        {
            LOG_DEBUG("%d name[%s]<--> value[%s]", i + 1, nodes[i]->key.c_str(), nodes[i]->value.c_str());
        }
    }
    LOG_DEBUG("root->key:[%s]<-->root->value:[%s]", root->key.c_str(), root->value.c_str());
}

void ExtractWildCardPath(std::vector<std::string>& vecPath, const std::string& strPath)
{
    vecPath.clear();
    HANDLE hdFile;
    WIN32_FIND_DATAA findData;
    hdFile = FindFirstFileA(strPath.c_str(), &findData);
    if (INVALID_HANDLE_VALUE == hdFile)
    {
        LOG_WARN("FindFirstFileA(%s) failed, errorCode:%lu", strPath.c_str(), GetLastError());
        return;
    }
    size_t indexTmp         = strPath.find_last_of("\\/");
    std::string strHomePath = strPath.substr(0, indexTmp + 1);
    do
    {
        if ((_stricmp(findData.cFileName, "..") == 0) || (_stricmp(findData.cFileName, ".") == 0))
        {
            continue;
        }
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            continue;
        }
        vecPath.push_back(strHomePath + findData.cFileName);
    } while (FindNextFileA(hdFile, &findData));
    FindClose(hdFile);
}
/////////////////////////////////////////////////////////////////////
/// Apache Nginx配置文件解析
/////////////////////////////////////////////////////////////////////
#pragma once
#include <string>
#include <vector>
#include <algorithm>

#ifndef APACHETYPE
#define APACHETYPE "Apache"
#endif // !APACHETYPE
#ifndef NGINXTYPE
#define NGINXTYPE "Nginx"
#endif // !NGINXTYPE

// 单个节点
typedef struct TreeNode
{
    std::string key;
    std::string value;
    std::vector<TreeNode*> children;
    TreeNode* Parent;
    TreeNode()
    {
        //MNodeClear();
        key.clear();
        value.clear();
        children.clear();
        Parent = NULL;
    }
    //void MNodeClear()
    //{
    //    key.clear();
    //    value.clear();
    //    children.clear();
    //    Parent = NULL;
    //}
} TreeNode;

class ConfigTree
{
public:
    ConfigTree()
        : root(NULL){};
    void ConfigTreeInit(TreeNode* root);
    void PutChild(const std::string& key, const std::string& value, TreeNode* node, TreeNode* parent);
    TreeNode* GetParent(TreeNode* node);

private:
    TreeNode* root;

};

// 拼接value数据
std::string JoinValue(const std::vector<std::string>& vec, const std::string& strType);

// 解析apache配置文件
TreeNode* ConfigParse(const std::string& strConfigfile, const std::string& strType, const std::string& strPrefix);

// 从已解析的节点中查找include或includeOptional指令;
void TreeFindInclude(TreeNode* root, std::vector<std::string>& vecPath);

// 释放每一个节点的内存
void FreeNode(TreeNode* root);

// 遍历树
void TranverseTree(TreeNode* root);

// include包含的路径中可能含有wildcard; 提取精确路径,放入vecPath中;  
void ExtractWildCardPath(std::vector<std::string>& vecPath, const std::string& strPath);

#!/usr/bin/env python
# -*- encoding: utf-8 -*-

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

criterias_info = []
NAME_SPACE = '{http://oval.mitre.org/XMLSchema/oval-definitions-5}'

class GenOracleTuple(object):
    def __init__(self, ovalXml):
        self.ovalXml = ovalXml

    def get_os_type(self,cve_entry):
        os_type=''
        if cve_entry.iter(NAME_SPACE+'platform'):
            for item in cve_entry.iter(NAME_SPACE+'platform'):
                #print(item.text)
                platform_info=item.text
            platform="'"+platform_info+"'"
            #print(platform)
            if 'Oracle Linux 5' in platform:
                os_type="Oracle5"
            elif 'Oracle Linux 6' in platform:
                os_type = "Oracle6"
            elif 'Oracle Linux 7' in platform:
                os_type = "Oracle7"
            elif 'Oracle Linux 8' in platform:
                os_type = "Oracle8"
            return os_type
        else:
            print("other os_type")

    def comment_deal(self, comment, os_type):    # comment处理逻辑
        base_type = 'linux_kernel'
        file_name = ''
        version = ''
        oper = 'lessthan'
        item_list = []
        criterion_str = comment

        if 'Oracle Linux' in criterion_str \
            or 'ksplice-based' in criterion_str\
            or 'fips patched' in criterion_str:
            pass
        else:
            if 'is currently running' in criterion_str:
                base_type = 'kernel_running'
                file_name = '"'+criterion_str.split(' 0')[0]+'"'
                version = '"'+criterion_str.split(':')[1].split(' is')[0]+'"'

            elif 'equals' in criterion_str:
                file_name = '"'+criterion_str.split(' equals')[0]+'"'
                version = '"'+criterion_str.split(':')[1]+'"'
            elif 'installed' in criterion_str:
                file_name = '"'+criterion_str.split(' not')[0]+'"'
                version = '"'+criterion_str.split(':')[1]+'"'
            else:
                file_name = '"'+criterion_str.split(' is')[0]+'"'
                version = '"'+criterion_str.split(':')[1]+'"'

            if 'equals' in criterion_str:
                oper = 'equalto'
            elif 'is greater than' in criterion_str:
                oper = 'greaterthan'
            elif 'not installed' in criterion_str:
                oper = 'notinstalled'
            else:
                pass

            item_list.append(os_type)
            item_list.append(base_type)
            item_list.append(file_name)
            item_list.append(version)
            item_list.append(oper)

            return tuple(item_list)

    def get_comment(self, criteria, current_operator, os_type):
        criteria_list = []
        if current_operator == 'AND':
            if criteria.findall(NAME_SPACE+'criterion'):
                criterions = criteria.findall(NAME_SPACE+'criterion')
                for i in range(0, len(criterions)):
                    current_comment = criterions[i].get("comment")
                    if type(self.comment_deal(current_comment,os_type)) == tuple:
                        criteria_list.append(self.comment_deal(current_comment,os_type))
                    else:
                        pass
                criterias_info.append(criteria_list)
        elif current_operator == 'OR':
            if criteria.findall(NAME_SPACE+'criterion'):
                criterions = criteria.findall(NAME_SPACE+'criterion')
                for i in range(0, len(criterions)):
                    current_comment = criterions[i].get("comment")
                    if type(self.comment_deal(current_comment,os_type)) == tuple:
                        criteria_list = [self.comment_deal(current_comment,os_type)]
                        criterias_info.append(criteria_list)
                    else:
                        pass
    
    def get_criteria(self, criteria,os_type):
        if criteria.findall(NAME_SPACE+'criteria'):
            criteria_children = criteria.findall(NAME_SPACE+'criteria')
            for criteria_child in criteria_children:
                self.get_criteria(criteria_child,os_type)
        else:
            current_operator = criteria.get('operator')
            self.get_comment(criteria, current_operator,os_type)
    
    def get_oracle_tuple(self):
        xml_data = ET.parse(self.ovalXml)
        root = xml_data.getroot()
        cve_entrys = []
        oracle5_list = []
        oracle6_list = []
        oracle7_list = []
        oracle8_list = []
        for definition in root.iter(NAME_SPACE+'definition'):
            cve_entrys.append(definition)
        print("LEN_ENTRY:", len(cve_entrys))
        for cve_entry in cve_entrys:
            reference_lists = []
            item_dict = {
                'rule': '',
                'rule_item': '',
                'patch_id': '',
                'cve_id': '',
                'criteria': (
                )
            }

            for reference in cve_entry.iter(NAME_SPACE+'reference'):
                reference_lists.append(reference.get('ref_id'))
            if len(reference_lists) <= 1:
                continue

            if '-2020-' in str(reference_lists[0]) \
                    or '-2021-' in str(reference_lists[0])\
                    or '-2022-' in str(reference_lists[0]):
                rule_str = reference_lists[0].replace("-", "_")+"_Rule"
                rule_item_str = reference_lists[0].replace("-", "_")
                patch_id_str = '"' + reference_lists[0]+'"'
                cve_id_str = '"' + reference_lists[1]+ '"' 
            else:
                continue

            os_type=self.get_os_type(cve_entry)
            self.get_criteria(cve_entry,os_type)


            item_dict.update(rule=rule_str)
            item_dict.update(rule_item=rule_item_str)
            item_dict.update(patch_id=patch_id_str)
            item_dict.update(cve_id=cve_id_str)
            item_dict.update(criteria=tuple(criterias_info))
            
            if 'Oracle5' == os_type:
                oracle5_list.append(item_dict)
            elif 'Oracle6' == os_type:
                oracle6_list.append(item_dict)
            elif 'Oracle7' == os_type:
                oracle7_list.append(item_dict)
            elif 'Oracle8' == os_type:
                oracle8_list.append(item_dict)
            else:
                print('!!!os type error!!!')
            
            criterias_info.clear()

        return tuple(oracle5_list),tuple(oracle6_list),tuple(oracle7_list),tuple(oracle8_list)


if __name__ == "__main__":

    genOracleTuple = GenOracleTuple('../oval/com.oracle.elsa-all.xml')
    oracle5_tuple,oracle6_tuple,oracle7_tuple,oracle8_tuple = genOracleTuple.get_oracle_tuple()
    #print(oracle8_tuple)

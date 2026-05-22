#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@Description:       :
@Date     :2022/01/12 16:58:30
@Author      :luo.xintao
@version      :1.0
'''

import re
try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

criterias_info_list = []

NAME_SPACE = '{http://oval.mitre.org/XMLSchema/oval-definitions-5}'

class GenSuseTuple(object):
    def __init__(self, ovalXml):
        self.ovalXml = ovalXml


    def suse_comment_deal(self, comment):
        deal_str = comment.split(' ')[0]
        file_name = ''
        version = ''
        deal_list = deal_str.split('-')
        my_re = re.compile(r'[A-Za-z]',re.S)
        for i in range(1, len(deal_list)): 
            if len(re.findall(my_re, deal_list[i])):
                file_name = file_name + '-' + deal_list[i]
            else:
                break
        file_name = '"' + deal_list[0] + file_name  + '"'
        deal_str = deal_str.replace(file_name.replace('"',''), '')
        version = '"' + deal_str[1:]+ '"'
        return file_name, version

    
    def suse_os_comment_deal(self, os_comment):
        if '15' in os_comment :
            if 'SP1' in os_comment:
                return 'Suse15_sp1'
            elif 'SP2' in os_comment:
                return 'Suse15_sp2'
            elif 'SP3' in os_comment:
                return 'Suse15_sp3'
            else:
                return 'Suse15'
        elif '12' in os_comment:
            if 'SP1' in os_comment:
                return 'Suse12_sp1'
            elif 'SP2' in os_comment:
                return 'Suse12_sp2'
            elif 'SP3' in os_comment:
                return 'Suse12_sp3'
            elif 'SP4' in os_comment:
                return 'Suse12_sp4'
            elif 'SP5' in os_comment:
                return 'Suse12_sp5'
            else:
                return 'Suse12'
        else:
            print('!!!os type error!!!')
    
    #<criteria operator="AND">
    #	<criterion test_ref="oval:org.opensuse.security:tst:2009254629" comment="SUSE Linux Enterprise Module for Basesystem 15 SP1 is installed"/>
    #	<criterion test_ref="oval:org.opensuse.security:tst:2009481537" comment="libwireshark9-2.4.14-3.25.2 is installed"/>	
    #</criteria>
    def suse_critertion_deal_have_0_criteria(self, criteria):
        critertions = criteria.findall(NAME_SPACE+'criterion')
        operator = criteria.get('operator')
        criteria_list = []
        #print(len(critertions))
        os_comment = critertions[0].get('comment')
        os_type = self.suse_os_comment_deal(os_comment)
        for i in range(1, len(critertions)):
            app_comment = critertions[i].get('comment')
            if 'is not affected' in app_comment:
                continue
            item_list = []
            file_name, version = self.suse_comment_deal(app_comment)
            item_list.append(os_type)
            item_list.append('linux_kernel')
            item_list.append(file_name)
            item_list.append(version)
            item_list.append('lessthan')
            
            criteria_list.append(tuple(item_list))
        if len(criteria_list) != 0:
            #print(criteria_list)
            return criteria_list, operator
        else:
            return '',''

    
    # <criteria operator="AND">
	# 	<criterion test_ref="oval:org.opensuse.security:tst:2009281315" comment="SUSE Linux Enterprise Module for Basesystem 15 SP2 is installed"/>
	# 	<criteria operator="OR">
	# 		<criterion test_ref="oval:org.opensuse.security:tst:2009482452" comment="libwireshark13-3.2.2-3.35.2 is installed"/>
	# 		<criterion test_ref="oval:org.opensuse.security:tst:2009482453" comment="libwiretap10-3.2.2-3.35.2 is installed"/>
	# 	</criteria>
	# </criteria>
    # 或者
    # <criteria operator="AND">
	# 	<criteria operator="OR">
	# 		<criterion test_ref="oval:org.opensuse.security:tst:2009282574" comment="SUSE Linux Enterprise Module for additional PackageHub packages 15 SP2 is installed"/>
	# 		<criterion test_ref="oval:org.opensuse.security:tst:2009340376" comment="SUSE Linux Enterprise Module for additional PackageHub packages 15 SP3 is installed"/>
	# 	</criteria>
	# 		<criterion test_ref="oval:org.opensuse.security:tst:2009630116" comment="vpx-tools-1.6.1-6.6.8 is installed"/>
	# </criteria>
    def suse_critertion_deal_have_1_criteria(self, criteria):
        if criteria.findall(NAME_SPACE+'criterion'):
            critertions = criteria.findall(NAME_SPACE+'criterion')
            criteria_list = []
            #print(len(critertions))
            comment = critertions[0].get('comment')
            criteria_children = criteria.findall(NAME_SPACE+'criteria')
            critertions_children = criteria_children[0].findall(NAME_SPACE+'criterion')
            operator = criteria_children[0].get('operator')
            if 'SUSE Linux' in comment:
                os_type = self.suse_os_comment_deal(comment)
                for i in range(0, len(critertions_children)):
                    app_comment = critertions_children[i].get('comment')
                    if 'is not affected' in app_comment:
                        continue
                    item_list = []
                    file_name, version = self.suse_comment_deal(app_comment)
                    item_list.append(os_type)
                    item_list.append('linux_kernel')
                    item_list.append(file_name)
                    item_list.append(version)
                    item_list.append('lessthan')
                    criteria_list.append(tuple(item_list))
            else:
                if 'is not affected' in comment:
                    return '',''
                else:
                    file_name, version = self.suse_comment_deal(comment)
                    os_list = []
                    for i in range(0, len(critertions_children)):
                        os_comment = critertions_children[i].get('comment')
                        os_type = self.suse_os_comment_deal(os_comment)
                        os_list.append(os_type)

                    os_list = list(set(os_list)) #去重
                    for os_type in os_list:
                        item_list = []
                        item_list.append(os_type)
                        item_list.append('linux_kernel')
                        item_list.append(file_name)
                        item_list.append(version)
                        item_list.append('lessthan')
                        criteria_list.append(tuple(item_list))
            if len(criteria_list) != 0:
                #print(criteria_list)
                return criteria_list, operator
            else:
                return '',''
        else:
            return '',''
            
    # <criteria operator="AND">
	# 	<criteria operator="OR">
	# 		<criterion test_ref="oval:org.opensuse.security:tst:2009223735" comment="SUSE Linux Enterprise Module for Basesystem 15 is installed"/>
	# 		<criterion test_ref="oval:org.opensuse.security:tst:2009223735" comment="SUSE Linux Enterprise Module for Basesystem 15 SP1 is installed"/>
	# 	</criteria>
	# 	<criteria operator="OR"/"AND">
	# 		<criterion test_ref="oval:org.opensuse.security:tst:2009480781" comment="libwireshark9-2.4.6-1.31 is installed"/>
	# 		<criterion test_ref="oval:org.opensuse.security:tst:2009480782" comment="libwiretap7-2.4.6-1.31 is installed"/>
	# 	</criteria>
	# </criteria>
    def suse_critertion_deal_have_2_criteria(self, criteria):
        criteria_children = criteria.findall(NAME_SPACE+'criteria')
        criteria_list = []
        #print(len(criteria_children))
        os_list = criteria_children[0].findall(NAME_SPACE+'criterion')
        os_type_list = []
        for i in range(0, len(os_list)):
            os_comment = os_list[i].get('comment')
            os_type = self.suse_os_comment_deal(os_comment)
            os_type_list.append(os_type)
        os_type_list = list(set(os_type_list)) #去重
        operator = criteria_children[1].get('operator')
        app_list = criteria_children[1].findall(NAME_SPACE+'criterion')
        for i in range(0, len(app_list)):
            app_comment = app_list[i].get('comment')
            if 'is not affected' in app_comment:
                continue
            file_name, version = self.suse_comment_deal(app_comment)
            for os in os_type_list:
                item_list = []
                item_list.append(os)
                item_list.append('linux_kernel')
                item_list.append(file_name)
                item_list.append(version)
                item_list.append('lessthan')
                criteria_list.append(tuple(item_list))
        if len(criteria_list) != 0:
            #print(criteria_list)
            return criteria_list, operator
        else:
            return '', ''

    def suse_gen_criterias_info(self, criteria_list, operator):
        if 'AND' == operator:
            criterias_info_list.append(criteria_list)
        elif 'OR' == operator:
            for item_tuple in criteria_list:
                criterias_info_list.append([item_tuple])
        
    
    def suse_critertion_deal(self, criteria):
        criteria_children = criteria.findall(NAME_SPACE+'criteria')
        lenth = len(criteria_children)
        operator = ''
        criteria_list = []
        #print(lenth)
        if 0 == lenth:
            criteria_list, operator = self.suse_critertion_deal_have_0_criteria(criteria)
        elif 1 == lenth:
            criteria_list, operator = self.suse_critertion_deal_have_1_criteria(criteria)
        elif 2 == lenth:
            criteria_list, operator = self.suse_critertion_deal_have_2_criteria(criteria)
        else:
            print('error')
        self.suse_gen_criterias_info(criteria_list, operator)
        

    def suse_criteria_deal(self, criteria):
        criteria_children = criteria.findall(NAME_SPACE+'criteria') 
        criteria_child = criteria_children[0].findall(NAME_SPACE+'criteria')
        #print(len(criteria_child))
        operator = ''
        criteria_list = []
        if 0 == len(criteria_child) or 1 == len(criteria_child):
            self.suse_critertion_deal(criteria_children[0])
        elif 2 == len(criteria_child) and 'OR' == criteria_child[0].get('operator'):
            criteria_list, operator = self.suse_critertion_deal_have_2_criteria(criteria_children[0])
        else:
            for criteria_son in criteria_child:
                self.suse_critertion_deal(criteria_son)
        if(0 != len(criteria_list)):
            self.suse_gen_criterias_info(criteria_list, operator)
    
    def get_suse_tuple(self):
        xml_data = ET.parse(self.ovalXml)
        root = xml_data.getroot()
        cve_entrys = []
        suse_list = []

        for definitions in root.iter(NAME_SPACE+'definitions'):
            for definition in definitions.iter(NAME_SPACE+'definition'):
                cve_entrys.append(definition)

        print("LEN_ENTRY:", len(cve_entrys))
        for cve_entry in cve_entrys:
            item_dict = {
            'rule': '',
            'rule_item': '',
            'patch_id': '',
            'cve_id': '',
            'criteria': (
            )}

            for title in cve_entry.iter(NAME_SPACE+'title'):
                cve_id = title.text
                
            if '-2020-' in cve_id or '-2021-' in cve_id or '-2022-' in cve_id:
                rule = cve_id.replace("CVE","SUSEBA").replace("-","_") + '_Rule'
                rule_item = cve_id.replace("CVE","SUSEBA").replace("-","_")
            else:
                continue
            self.suse_criteria_deal(cve_entry)
            #print(criterias_info_list)

            item_dict.update(rule=rule)
            item_dict.update(rule_item=rule_item)
            item_dict.update(patch_id='"'+cve_id+'"')
            item_dict.update(cve_id='"'+cve_id+'"')
            item_dict.update(criteria=tuple(criterias_info_list))
            if 0 != len(criterias_info_list):
                suse_list.append(item_dict)
            criterias_info_list.clear()
        suse_tuple = tuple(suse_list)
        return suse_tuple


if __name__ == "__main__":
    genSuseTuple = GenSuseTuple('../oval/suse.linux.enterprise.server.12.xml')
    suse_tuple = genSuseTuple.get_suse_tuple()
    #print(suse_tuple)


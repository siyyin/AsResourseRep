#!/usr/bin/env python
# -*- encoding: utf-8 -*-

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

criterias_info_list = []
NAME_SPACE = '{http://oval.mitre.org/XMLSchema/oval-definitions-5}'
NAME_SPACE_LINUX = '{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}'
NAME_SPACE_IND = '{http://oval.mitre.org/XMLSchema/oval-definitions-5#independent}'

class GenUbuntuTuple(object):
    def __init__(self, ovalXml, platForm):
        self.ovalXml = ovalXml
        self.platForm = platForm
    
    def ubuntu_file_name_deal(self, filename):
        return '"'+filename.split('\s')[0][1:]+'"'

    def ubuntu_get_version(self, state):
        if self.platForm == 'Ubuntu16' or self.platForm == 'Ubuntu18':
            namespace = NAME_SPACE_LINUX+'evr'
        elif self.platForm == 'Ubuntu20':
            namespace = NAME_SPACE_IND+'subexpression'
        for evr in  state.iter(namespace):
            return '"'+evr.text+'"'

    def ubuntu_get_file_name(self, variale):
        file_name_list = []
        for file_name in variale.iter(NAME_SPACE+'value'):
            if self.platForm == 'Ubuntu16' or self.platForm == 'Ubuntu18':
                file_name_list.append('"'+file_name.text+'"')
            elif self.platForm == 'Ubuntu20':
                file_name_list.append(self.ubuntu_file_name_deal(file_name.text))       
        return file_name_list
    
    def ubuntu_variales_deal(self, app_id, variales):
        for variale in variales:
            if app_id in variale.get('id'):
                return self.ubuntu_get_file_name(variale)
    
    def ubuntu_states_deal(self, app_id, states):
        for state in states:
            if app_id in state.get('id'):
                version = self.ubuntu_get_version(state)
                return version
  
    def ubuntu_gen_criterias_info(self, criteria_list):
        for item_tuple in criteria_list:
            criterias_info_list.append([item_tuple])
            
    
    def ubuntu_critertion_deal(self, critertions, states, variales):
        if(0 == len(critertions)):
            print('have no critertion')
            return
        criteria_list = []
        #print(len(critertions))
        for critertion in critertions:
            test_ref = critertion.get('test_ref')
            test_ref_list = test_ref.split(':')
            app_id = test_ref_list[len(test_ref_list)-1]
            #print(app_id)
            version = self.ubuntu_states_deal(app_id, states)
            file_name_list = self.ubuntu_variales_deal(app_id, variales)
            for file_name in file_name_list:
                item_list = []
                item_list.append(self.platForm)
                item_list.append('linux_kernel')
                item_list.append(file_name)
                item_list.append(version)
                item_list.append('lessthan')
                criteria_list.append(tuple(item_list))

        self.ubuntu_gen_criterias_info(criteria_list)
    
    def ubuntu_criteria_deal(self, criteria, states, variales):
        criteria_children = criteria.findall(NAME_SPACE+'criteria')
        critertions = criteria_children[0].findall(NAME_SPACE+'criterion')
        self.ubuntu_critertion_deal(critertions, states, variales)
        
    def get_ubuntu_tuple(self):
        xml_data = ET.parse(self.ovalXml)
        root = xml_data.getroot()
        cve_entrys = []
        state_entrys = []
        variables_entrys = []
        ubuntu_list = []

        for definition in root.iter(NAME_SPACE+'definition'):
            cve_entrys.append(definition)
        #去除第一个definition
        cve_entrys = cve_entrys[1:]
        
        if self.platForm == 'Ubuntu16' or self.platForm == 'Ubuntu18':
            for state in root.iter(NAME_SPACE_LINUX+'dpkginfo_state'):
                state_entrys.append(state)
        elif self.platForm == 'Ubuntu20':
            for state in root.iter(NAME_SPACE_IND+'textfilecontent54_state'):
                state_entrys.append(state)

        for variable in root.iter(NAME_SPACE+'constant_variable'):
            variables_entrys.append(variable)

        print('CVE_ENTRY:', len(cve_entrys))
        print('STATE_ENTRY:', len(state_entrys))
        print('VARIABLES_ENTRY', len(variables_entrys))
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

            if '-2020-' in str(reference_lists[1]) \
                    or '-2021-' in str(reference_lists[1])\
                    or '-2022-' in str(reference_lists[1]):
                rule_str = reference_lists[0].replace("-", "_")+"_Rule"
                rule_item_str = reference_lists[0].replace("-", "_")
                patch_id_str = '"' + reference_lists[0]+'"'
                cve_id_str = '"' + reference_lists[1]+ '"' 
            else:
                continue

            self.ubuntu_criteria_deal(cve_entry, state_entrys, variables_entrys)

            item_dict.update(rule=rule_str)
            item_dict.update(rule_item=rule_item_str)
            item_dict.update(patch_id=patch_id_str)
            item_dict.update(cve_id=cve_id_str)
            item_dict.update(criteria=tuple(criterias_info_list))
            ubuntu_list.append(item_dict)

            criterias_info_list.clear()

        return tuple(ubuntu_list)

if __name__ == "__main__":

    genUbuntu16Tuple = GenUbuntuTuple('../oval/com.ubuntu.xenial.usn.oval-ubuntu16.xml', 'Ubuntu16')
    ubuntu16_tuple = genUbuntu16Tuple.get_ubuntu_tuple()
    #print(ubuntu16_tuple)

    genUbuntu18Tuple = GenUbuntuTuple('../oval/com.ubuntu.bionic.usn.oval-ubuntu18.xml', 'Ubuntu18')
    ubuntu18_tuple = genUbuntu18Tuple.get_ubuntu_tuple()
    #print(ubuntu18_tuple)

    genUbuntu20Tuple = GenUbuntuTuple('../oval/oci.com.ubuntu.focal.usn.oval-ubuntu20.xml', 'Ubuntu20')
    ubuntu20_tuple = genUbuntu20Tuple.get_ubuntu_tuple()
    #print(ubuntu20_tuple)

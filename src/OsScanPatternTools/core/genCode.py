#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@Description:       :
@Date     :2022/01/12 16:58:35
@Author      :luo.xintao
@version      :1.0
'''

import sys
from mako.lookup import TemplateLookup
from mako import exceptions
from genOracleTuple import GenOracleTuple
from genSuseTuple import GenSuseTuple
from genUbuntuTuple import GenUbuntuTuple

class GenCode(object):
    
    def __init__(self, templateDir, templateFileName, patterName):
        self.templateDir = templateDir
        self.templateFileName = templateFileName
        self.patterName = patterName

    def gen_code(self, *args, **kwargc):
        """
        @description  :
        ---------
        @param  :
        -------
        @Returns  :
        -------
        """
        
        try:
            lookup = TemplateLookup(directories=[self.templateDir],
                input_encoding='utf-8',default_filters=['decode.utf8'],encoding_errors='replace')
            commTemplate = lookup.get_template(self.templateFileName)
            pattren = commTemplate.render(*args, **kwargc)
        except:
            print(exceptions.text_error_template().render())
        with open('../pattern/'+self.patterName, 'w') as f:
            f.writelines(pattren)
            f.close()



if __name__ == "__main__":
    if len(sys.argv) != 2:
        print('Usage: python3 genCode.py version')
        exit(1)
    pattern_version = '"' + sys.argv[1] + '"'

    genOracleTuple = GenOracleTuple('../oval/com.oracle.elsa-all.xml')
    oracle5_tuple,oracle6_tuple,oracle7_tuple,oracle8_tuple = genOracleTuple.get_oracle_tuple()
    oracle_dict = {
        'ver': pattern_version,
        'patch_url':'"https://linux.oracle.com/errata/"',
        'cve_url':'"https://linux.oracle.com/cve/"'
    }

    genSuse15Tuple = GenSuseTuple('../oval/suse.linux.enterprise.server.15.xml')
    suse15_tuple = genSuse15Tuple.get_suse_tuple()

    genSuse12Tuple = GenSuseTuple('../oval/suse.linux.enterprise.server.12.xml')
    suse12_tuple = genSuse12Tuple.get_suse_tuple()
    suse_dict = {
        'ver': pattern_version,
        'patch_url':'"https://scc.suse.com/patches/"',
        'cve_url':'"https://www.suse.com/security/cve/"'
    }

    genUbuntu16Tuple = GenUbuntuTuple('../oval/com.ubuntu.xenial.usn.oval-ubuntu16.xml', 'Ubuntu16')
    ubuntu16_tuple = genUbuntu16Tuple.get_ubuntu_tuple()

    genUbuntu18Tuple = GenUbuntuTuple('../oval/com.ubuntu.bionic.usn.oval-ubuntu18.xml', 'Ubuntu18')
    ubuntu18_tuple = genUbuntu18Tuple.get_ubuntu_tuple()

    genUbuntu20Tuple = GenUbuntuTuple('../oval/oci.com.ubuntu.focal.usn.oval-ubuntu20.xml', 'Ubuntu20')
    ubuntu20_tuple = genUbuntu20Tuple.get_ubuntu_tuple()
    ubuntu_dict = {
        'ver': pattern_version,
        'patch_url':'"https://ubuntu.com/security/notices/"',
        'cve_url':'"https://ubuntu.com/security/"'
    }

    genCode = GenCode('../makotemplate', 'makoT.txt', 'vaoracle6p.lua')
    genCode.gen_code(mytuple=oracle6_tuple, mydict=oracle_dict)

    genCode = GenCode('../makotemplate', 'makoT.txt', 'vaoracle7p.lua')
    genCode.gen_code(mytuple=oracle7_tuple, mydict=oracle_dict)

    genCode = GenCode('../makotemplate', 'makoT.txt', 'vaoracle8p.lua')
    genCode.gen_code(mytuple=oracle8_tuple, mydict=oracle_dict)


    genCode = GenCode('../makotemplate', 'makoT.txt', 'vasuse15p.lua')
    genCode.gen_code(mytuple=suse15_tuple, mydict=suse_dict)

    genCode = GenCode('../makotemplate', 'makoT.txt', 'vasuse12p.lua')
    genCode.gen_code(mytuple=suse12_tuple, mydict=suse_dict)

    genCode = GenCode('../makotemplate', 'makoT.txt', 'vaubuntu16p.lua')
    genCode.gen_code(mytuple=ubuntu16_tuple, mydict=ubuntu_dict)

    genCode = GenCode('../makotemplate', 'makoT.txt', 'vaubuntu18p.lua')
    genCode.gen_code(mytuple=ubuntu18_tuple, mydict=ubuntu_dict)

    genCode = GenCode('../makotemplate', 'makoT.txt', 'vaubuntu20p.lua')
    genCode.gen_code(mytuple=ubuntu20_tuple, mydict=ubuntu_dict)






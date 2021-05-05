import re
import os

# From the named script import the functions to be tested
from main import create_fw_dict
from asa import format_acl
from ckp import format_acl
from .example_acls import ckp_acl



# INPUT_DATA: Tests that the input file of FWs is converted into corretc data-model format
def test_data_model():
    my_vars = dict(user='glob_user', pword='glob_pword',
                asa=dict(user='asa_user', pword='asa_pword', fw=[dict(ip_name='10.10.10.1', user='fw_user', pword='fw_pword'), dict(ip_name='10.10.10.2')]),
                ckp=dict(fw=[dict(ip_name='10.10.20.1', user='fw_user', pword='fw_pword'), dict(ip_name='10.10.20.2')]))
    fw_type = []    # Required to stop errors
    assert dict(create_fw_dict(my_vars, 'asa')) == {'asa': [{'10.10.10.1': ('fw_user', 'fw_pword')}, {'10.10.10.2': ('asa_user', 'asa_pword')}]}
    assert dict(create_fw_dict(my_vars, 'ckp')) == {'ckp': [{'10.10.20.1': ('fw_user', 'fw_pword')}, {'10.10.20.2': ('glob_user', 'glob_pword')}]}

# ASA_FORMAT: Loads test ACLs and ensures that the ACL and Expanded ACL are output in the correct formated
def test_asa_format_data():
    # Load the files and remove blanks from acl_brief (cant do in script as in function that requires device connectivity)
    with open(os.path.join(os.path.dirname(__file__), 'example_acls', 'asa_acl_brief.txt')) as file_content:
        acl_brief_temp = file_content.read()
    with open(os.path.join(os.path.dirname(__file__), 'example_acls', 'asa_acl_expanded.txt')) as file_content:
        acl_expanded = file_content.read()
    acl_brief = []
    for item in acl_brief_temp:
        for line in item.splitlines():
            if re.match(r"^\S{8}\s\S{8}\s", line):
                acl_brief.append(line)

    acl = format_acl('1.1.1.1', acl_brief, acl_expanded)
    assert acl['1.1.1.1_acl'] == [['stecap', '1', 'permit', 'ip', 'any', 'any_port', 'any', 'any_port', '0', '', '', ''] ,
                                  ['stecap', '2', 'permit', 'tcp', '10.10.10.0/32', 'any_port', 'any', '443', '0', '', '', ''] ,
                                  ['mgmt', '2', 'permit', 'icmp', 'any', 'any_port', 'any', 'echo', '13759', '', '', ''] ,
                                  ['mgmt', '3', 'permit', 'icmp', '1.1.1.1/32', 'any_port', 'any', 'echo-reply', '0', '', '', ''] ,
                                  ['mgmt', '4', 'permit', 'icmp', 'any', 'any_port', '2.2.2.2/32', 'unreachable', '3028', '', '', ''] ,
                                  ['mgmt', '5', 'permit', 'icmp', '10.10.10.0/24', 'any_port', 'any', 'time-exceeded', '0', '', '', ''] ,
                                  ['mgmt', '6', 'deny', 'icmp', 'any', 'any_port', 'any', 'any_port', '0', '', '', ''] ,
                                  ['mgmt', '9', 'permit', 'tcp', '10.10.10.1/32', 'any_port', 'obj_67-68', 'any_port', '0', '', '', 'inactive'] ,
                                  ['mgmt', '10', 'permit', 'tcp', 'any', '22', '20.20.20.0/24', '67-68', '9222', '', '', ''] ,
                                  ['mgmt', '11', 'permit', 'tcp', '10.10.10.1/32', 'any_port', 'obj_67-68', 'any_port', '0', '', '', ''] ,
                                  ['mgmt', '12', 'permit', 'tcp', '20.20.20.0/24', '22', 'any', '22', '1227', '', '', ''] ,
                                  ['Outside_mpc', '1', 'permit', 'icmp', 'any', 'any_port', 'any', 'echo-reply', '30', '', '', ''] ,
                                  ['Outside_mpc', '2', 'permit', 'ip', 'any', 'any_port', '185.4.167.128/28', 'any_port', '0', '', '', 'inactive'] ,
                                  ['Outside_mpc', '3', 'permit', 'tcp', 'any', 'any_port', 'obj_dc1dmznpgp03', 'any_port', '114382', '', '', ''] ,
                                  ['Outside_mpc', '4', 'permit', 'udp', 'obj_dc1dmznpgp03', 'any_port', 'obj_dc2dmzdns03', '53', '114382', '', '', ''] ,
                                  ['Outside_mpc', '5', 'permit', 'svc-grp_TCPUDP', 'intf_Outside_mpc', 'any_port', 'grp_UMB_DNS', 'domain', '0', '', '', ''] ,
                                  ['Outside_mpc', '6', 'deny', 'icmp', 'any', 'any_port', 'any', 'any_port', '0', '', '', ''] ,
                                  ['outside', '2', 'deny', 'tcp', 'any', 'any_port', 'grp_HTTP_HTTPS', 'any_port', '0', '', '', ''] ,
                                  ['outside', '3', 'deny', 'ip', 'any', 'any_port', 'grp_LOCAL_NETWORKS', 'any_port', '24876', '', '', '']]

    assert acl['1.1.1.1_exp_acl'] == [['stecap', '1', 'permit', 'ip', 'any', 'any_port', 'any', 'any_port', '0', '', '', ''] ,
                                      ['stecap', '2', 'permit', 'tcp', '10.10.10.0/32', 'any_port', 'any', '443', '0', '', '', ''] ,
                                      ['stecap', '2', 'permit', 'tcp', 'any', 'any_port', '10.10.10.0/24', '443', '0', '', '', ''] ,
                                      ['mgmt', '2', 'permit', 'icmp', 'any', 'any_port', 'any', 'echo', '13759', '', '', ''] ,
                                      ['mgmt', '3', 'permit', 'icmp', '1.1.1.1/32', 'any_port', 'any', 'echo-reply', '0', '', '', ''] ,
                                      ['mgmt', '4', 'permit', 'icmp', 'any', 'any_port', '2.2.2.2/32', 'unreachable', '3028', '', '', ''] ,
                                      ['mgmt', '5', 'permit', 'icmp', '10.10.10.0/24', 'any_port', 'any', 'time-exceeded', '0', '', '', ''] ,
                                      ['mgmt', '5', 'permit', 'icmp', 'any', 'any_port', '10.10.10.0/24', 'time-exceeded', '0', '', '', ''] ,
                                      ['mgmt', '6', 'deny', 'icmp', 'any', 'any_port', 'any', 'any_port', '0', '', '', ''] ,
                                      ['mgmt', '10', 'permit', 'tcp', 'any', '22', '20.20.20.0/24', '67-68', '9222', '', '', ''] ,
                                      ['mgmt', '12', 'permit', 'tcp', '20.20.20.0/24', '22', 'any', '22', '1227', '', '', ''] ,
                                      ['Outside_mpc', '1', 'permit', 'icmp', 'any', 'any_port', 'any', 'echo-reply', '30', '', '', ''] ,
                                      ['Outside_mpc', '2', 'permit', 'ip', 'any', 'any_port', '185.4.167.128/28', 'any_port', '0', '', '', 'inactive'] ,
                                      ['Outside_mpc', '3', 'permit', 'tcp', 'any', 'any_port', '10.255.111.85/32', 'https', '96119', '', '', ''] ,
                                      ['Outside_mpc', '3', 'permit', 'tcp', 'any', 'any_port', '10.255.111.85/32', 'ldaps', '15681', '', '', ''] ,
                                      ['Outside_mpc', '3', 'permit', 'tcp', 'any', 'any_port', '10.255.111.85/32', 'ldap', '2582', '', '', ''] ,
                                      ['Outside_mpc', '4', 'permit', 'udp', '10.255.111.85/32', 'any_port', '10.255.211.211/32', '53', '114382', '', '', ''] ,
                                      ['Outside_mpc', '5', 'permit', 'udp', 'intf_Outside_mpc', 'any_port', '10.255.120.14/32', 'domain', '0', '', '', ''] ,
                                      ['Outside_mpc', '5', 'permit', 'tcp', 'intf_Outside_mpc', 'any_port', '10.255.120.14/32', 'domain', '0', '', '', ''] ,
                                      ['Outside_mpc', '6', 'deny', 'icmp', 'any', 'any_port', 'any', 'any_port', '0', '', '', ''] ,
                                      ['outside', '2', 'deny', 'tcp', 'any', 'www', 'any', 'any_port', '0', '', '', ''] ,
                                      ['outside', '2', 'deny', 'tcp', 'any', 'https', 'any', 'any_port', '0', '', '', ''] ,
                                      ['outside', '3', 'deny', 'ip', 'any', 'any_port', '10.10.10.0/24', 'any_port', '24876', '', '', ''] ,
                                      ['outside', '3', 'deny', 'ip', 'any', 'any_port', '10.10.20.0/24', 'any_port', '0', '', '', '']]

# CKP_FORMAT: Loads test ACLs and ensures that the ACL and Expanded ACL are output in the correct formated
def test_ckp_format_data():
    acl_brief =  ckp_acl.acl_brief
    acl_expanded = ckp_acl.acl_expanded
    acl = format_acl('1.1.1.1', acl_brief, acl_expanded)
    assert acl['1.1.1.1_acl'] == []
    assert acl['1.1.1.1_exp_acl'] == []

#!/usr/bin/env python
from netmiko import Netmiko
import re
from ipaddress import IPv4Network
from datetime import datetime
from copy import deepcopy


###################################### 1. Login and logoff ######################################
# 1a. Attempt logon to ASA and create sessions
def login(fw, user, pword):
    try:
        net_conn = Netmiko(host=fw, username=user, password=pword, device_type='cisco_asa')
        net_conn.find_prompt()
        return (True, net_conn)
    except Exception as e:
        return (False, "\u26A0\uFE0F  [yellow]WARNING[/yellow] - '{}'".format(e).splitlines()[0])
# Used to close all sessions
def logoff(fw, sid):
    sid.disconnect()


################################## 2. Gather ACLs from ASAs ##################################
def get_acls(fw, sid):
    asa_all_acls, acl_brief, acl_brief_temp = ([] for i in range(3))

    # 2a. Gets the name of all ACLs to be used in the show acl name brief cmd
    asa_acl = sid.send_command('show run access-group')
    ra_vpn_acl = sid.send_command('show run | in split-tunnel-network-list')
    sts_vpn_acl = sid.send_command('show run | in match address')
    for ace in asa_acl.splitlines():
        asa_all_acls.append(ace.split(' ')[1])
    for ace in ra_vpn_acl.splitlines():
        asa_all_acls.append(ace.split('value ')[1])
    for ace in sts_vpn_acl.splitlines():
        asa_all_acls.append(ace.split('address ')[1])

    # 2b. Gathers show ACL (as a string) and show ACL brief (as a list) output for all the ACLs
    for ace in set(asa_all_acls):
        acl_brief_temp.append(sid.send_command('show access-list {} brief'.format(ace)))
    acl_expanded = sid.send_command('show access-list | ex elements|cached|alert-interval|remark')

    # 2c. Creates new ACL brief list of all lines that have a timestamp (matching 8 characters, space, 8 characters)
    for item in acl_brief_temp:
        for line in item.splitlines():
            if re.match(r"^\S{8}\s\S{8}\s", line):
                acl_brief.append(line)
    return acl_brief, acl_expanded


################################## DRY filters run by the main Sanitize method (format_acl) ##################################
# CATEG_OBJ: If it is an object or object-group remove that and add an identifier to its name and padout with any1
def categorize_obj(ele1, ele2):
    if ele1 == 'object-group':
        return ['grp_' + ele2, 'any1']
    elif ele1 == 'object':
        return ['obj_' + ele2, 'any1']
    elif ele1 == 'fqdn':
        return ['fqdn_' + ele2, 'any1']
    # matches object ranges
    else:
        return ['obj_' + ele1 + '-' + ele2, 'any1']

# NORM_SVC: Normalise src and dst ports so that are ranges joined and the identifiers (eq or range) removed
def normalize_svc(ace, ele):
    # If has a source range of ports replace "range" with "start-end" port numbers
    if ace[ele] == 'range':
        start = ace.pop(ele +1)
        end = ace.pop(ele +1)
        ace[ele] = start + '-' + end
    # If has a single source port delete eq or add extra identifier for not, less than or greater than
    elif ace[ele] == 'eq':
        del ace[ele]
    elif ace[ele] == 'neq':
        del ace[ele]
        ace[ele] =  'NOT_' + ace[ele]
    elif ace[ele] == 'lt':
        del ace[ele]
        ace[ele] =  'LT_' + ace[ele]
    elif ace[ele] == 'gt':
        del ace[ele]
        ace[ele] =  'GT_' + ace[ele]
    # SRC_SVC: Catch-all ALL - If ICMP (cant have src_port) or has no source port padout with 'any_port'
    elif ele == 6:
        (ace.insert(ele, 'any_port'))
    # DST_SVC: Catch-all Non-ICMP - Any other ACEs that are not ICMP and have no dst_svc are padout with 'any_port'
    elif ele == 9 and 'icmp' not in ace:
        (ace.insert(ele, 'any_port'))
    # DST_SVC: Catch-all ICMP - Any other ICMP that have no dst_svc are padout with 'any_port'
    elif ace[9].isdigit() or ace[9] == 'log':
        (ace.insert(ele, 'any_port'))

# NORM_NET: Convert subnet mask to prefix and padout old mask with 'any1'. If interface name used in ace do same for that
def normalize_net(ace, ele):
    # if it uses interface combines into 1 filed and pads out with any1
    if ace[ele] == 'interface':
        ace[ele] = 'intf_' + ace[ele +1]
        ace[ele +1] = 'any1'
    # Changes subnet mask to a prefix
    else:
        try:                # If it is a valid IP (not 'any' or an object)
            src_pfx = IPv4Network((ace[ele], ace[ele +1])).with_prefixlen	    # Add prefix to the src_IP
            ace[ele] = src_pfx
            ace[ele +1] = 'any1'
        except:             # So script doesn't fail if is not an IP address (an object)
            pass
    del ace[ele +1]                 # Remove the padding ('any1')

# NORM_DATE: Splits date/time into 2 fields and reformats it to be more human readable
def normalize_datetime(acl):
    for ace in acl:
        if ace[10] != '':
            ace[9] = ace[10].strftime('%Y-%m-%d %H:%M:%S').split(' ')[0]
            ace[10] = ace[10].strftime('%Y-%m-%d %H:%M:%S').split(' ')[1]


################################## 3. Sanitize the data - Create ACL structured data ##################################
# 3. ENGINE: Feeds ACL data and uses functions to produce standardized data model of ACL and expanded ACL
def format_acl(fw, acl_brief, acl_expanded):
    acl_exp, acl_date, acl_no_date = ([] for i in range(3))

    # 3a. Pad out 'any' so that the all source and destination are 2 fields (ACL is 1 big string at the moment)
    acl_all_temp1 = acl_expanded.replace('any4', 'any').replace('any', 'any any1')
    # Remove 'hitcnt' text by replacing fields.
    for elem in ['(hitcnt=', ')']:
        acl_all_temp1 = acl_all_temp1.replace(elem, '')

    # 3b. Make string into a list and split the elements in each list at the whitespaces
    for item in acl_all_temp1.splitlines():
        ace = item.strip().split(' ')
        acl_exp.append(ace)

    # Loops though ACL to normalise the data (categorize object names, simplify ranges, remove unneeded fields, etc)
    for ace in acl_exp:
        #3c. If it is a standard ACL pads out protocol and destination to make it same as extended
        if ace[4] == 'standard':
            ace.insert(6, 'ip')
            ace.insert(9, 'any')
            ace.insert(10, 'any1')
        # Deletes first 3 fields (access-list, line and extended/standard)
        for field in [0, 1, 2]:
            del ace[field]

        if ace[4] == 'range':
            del ace[4]
            ace[4:5] = categorize_obj(ace[4], ace.pop(5))
        if ace[6] == 'range':
            del ace[6]
            ace[6:7] = categorize_obj(ace[6], ace.pop(7))

        # 3d. If it is a service object or object-group remove 'object or 'object-group' and add identifer to the name
        if ace[3] == 'object-group':
            ace[3] = 'svc-grp_' + ace.pop(4)
        if ace[3] == 'object':
            ace[3] = 'svc_' + ace.pop(4)
        # If it is an object or object-group remove, add an identifier to its name and padout with any1
        if ace[4] == 'object' or ace[4] == 'object-group' or ace[4] == 'fqdn':
            ace[4:5] = categorize_obj(ace[4], ace.pop(5))
        if ace[6] == 'object' or ace[6] == 'object-group' or ace[6] == 'fqdn':
            ace[6:7] = categorize_obj(ace[6],ace.pop(7))
        # Cleans up src and dst extra field added by FQDN objects
        if '(' in ace[6]:
            del ace[6]
        if '(' in ace[8]:
            del ace[8]

        # 3e. Normalise src and dst ports so that are ranges joined with the identifiers (eq or range) removed
        normalize_svc(ace, 6)
        normalize_svc(ace, 9)

        # 3f. For all host entries delete host and add /32 subnet mask after the IP
        if ace[4] == 'host':						# if src_ip is /32
            del ace[4]
            (ace.insert(5, '255.255.255.255'))
        if ace[7] == 'host':						# if dst_ip is /32
            del ace[7]
            (ace.insert(8, '255.255.255.255'))

        # 3g. Converts subnet mask to prefix and removes the padding (any1)
        normalize_net(ace, 4)
        normalize_net(ace, 6)

        # 3h. If inactive moves 'state' to the last column (also removes '('), if is active adds a blank column)
        if ace[-2] == '(inactive':
            ace.append(ace.pop(-2)[1:])
        else:
            ace.append('')
        # Cleans up any columns between dst_port and hitcnt (logging or time-ranges)
        if len(ace) != 11:
            del ace[8:-3]
        # As FQDN doesn't have a hitcnt adds a blank entry
        if ace[8].isdigit() == False:
            ace.insert(8, '0')

        # 3i. Convert unixtime into human-readable time (is got as hash from last element in show access-list <name> brief)
        ace.insert(10, '')                              # Insert blank column to be used by the time
        for hashes in acl_brief:     				    # Loop through acl_brief
            if hashes.split(' ')[0] in ace[9]:    		# If acl_brief hash matches ace hash
                unix_time = hashes.split(' ')[-1]
                ace[10] = datetime.fromtimestamp(int(unix_time, 16))
        if ace[10] == '':       # If is no matching hashes (no timestamp) removes hashes
            ace[9] = ''

    # CREATE_ACL: Create non-expanded ACL by removing all duplicate ACL_name/acl_num combinations after the first
    acl_temp = deepcopy(acl_exp)        # Creates a separate copy of acl_exp so the new acl list isn't referencing it
    acl = [acl_temp[0]]                 # Creates new list containing only first element (as loop is offset by 1)
    # The loop on 2nd list is one element in front which is what allows to look for duplicates
    for ace_exp, ace in zip(acl_exp, acl_temp[1:]):
        # Skip duplicates and append non-duplicates (always first one due to the offset) to list
        if ace_exp[0:2] == ace[0:2]:
            pass
        else:
            acl.append(ace)

    # GET_ACE_MISSING_DATE: Loop through ACL, get any with hitcnts but no date. Are stored in list as [name, rule_num, hits]
    for ace in acl:
        if ace[8] != '0' and len(ace[9]) == 0:
            acl_no_date.append([ace[0], ace[1], ace[8]])
    # Compare this against acl_exp matching rule and number to get date for all expanded ACEs under the same main ACE
    for ace in acl_no_date:
        acl_exp_date = []
        for ace_exp in acl_exp:
            if ace[0:2] == ace_exp[0:2] and len(ace_exp[9]) !=0:
                acl_exp_date.append(ace_exp[10])
        if len(acl_exp_date) != 0:
            # Add date to ACL missing hits rules. Max() (part of datetime) gets only the latest date from the list of dates
            acl_date.append([ace[0], ace[1], ace[2], max(acl_exp_date)])

    # ACL & ACL_EXP_DATE: Splits date/time into 2 fields and reformats it to be more human readable
    normalize_datetime(acl)
    normalize_datetime(acl_exp)

    # ACL: Adds time/date got from 3k to the ACEs that were missing dates (splits and makes human readable)
    for ace in acl:
        for ace_date in acl_date:
            if ace[:2] == ace_date[:2]:
                ace[9] = ace_date[3].strftime('%Y-%m-%d %H:%M:%S').split(' ')[0]
                ace[10] = ace_date[3].strftime('%Y-%m-%d %H:%M:%S').split(' ')[1]

    # ACL_EXP: Removes all entries that are objects or object groups from the expanded ACL
    for idx, ace in enumerate(acl_exp):
        if 'grp' in ace[3] or 'grp' in ace[4] or 'obj' in ace[4] or 'grp' in ace[6] or 'obj' in ace[6]:
            del acl_exp[idx]

    # OUTPUT: Returns a dictionary of {device_ip_acl: non_expanded_acl, device_ip_exp_acl: expanded_acl} with every line of each being in the format:
    # [name, num, permit/deny, protocol, src_ip/pfx, src_port, dst_ip/pfx, dst_port, hitcnt, last_hit_date, last_hit_time, state]
    return {fw + '_acl': acl, fw + '_exp_acl': acl_exp}

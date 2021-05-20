#!/usr/bin/env python
import json
import requests
import urllib3
from ipaddress import ip_network
from datetime import datetime
import re
urllib3.disable_warnings()


###################################### 1. Login ######################################
# Initial login to get a Session ID (SID) and handling of errors. Based on the the HTTP responce code generates user error messages
def login(fw, user, pword):
    try:
        url = 'https://' + fw + '/web_api/login'
        payload = {'user':user, 'password': pword}
        request_headers = {'Content-Type' : 'application/json'}
        res = requests.post(url,data=json.dumps(payload), headers=request_headers, verify=False)

        # Stops errors by catching any response completely unknown responce not in JSON format as all error messages use it
        try:
            res.json()
            # If the API call is successful the returns the SID which is used in subsequent requests
            if res.status_code == 200:
                return (True, res.json()['sid'])
            # Based on the HTTP response from the Checkpoint feeds back custom error messages to the user
            elif res.status_code == 400:
                print(res.json())
                return (False, "\u26A0\uFE0F  [yellow]WARNING[/yellow] - {} - {} Check username and password is correct for {}".format(res.json()["code"], res.json()["message"], fw))
            elif res.status_code == 403:
                return (False, "\u26A0\uFE0F  [yellow]WARNING[/yellow] - 403 Forbidden: Check API service is enabled or it is not the standby manager {}".format(fw))
            elif res.status_code == 500:
                return (False, "\u26A0\uFE0F  [yellow]WARNING[/yellow] - {} - {}Check username is correct for {}".format(res.json()["code"], res.json()["message"].split('P')[0], fw))
            # Catchall for all other response codes with the generic checkpoint error message
            else:
                return (False, "\u26A0\uFE0F  [yellow]WARNING[/yellow] - {} {} {}".format(res.json()["code"], res.json()["message"], fw))
        # Unknown error which doesnt return JSON
        except:
            error = re.sub(r'<.*?>', '', str(list(res))).replace("b'", "").replace("\\n", " ").replace("[  ", "").replace(".  ']", "")
            return (False, "\u26A0\uFE0F  [yellow]WARNING[/yellow] - {} for {}".format(error, fw))
    # Handles exceptions where the checkpoint is unreachable as wouldn't get a HTTP response status back
    except requests.exceptions.RequestException as e:
        return (False, "\u26A0\uFE0F  [yellow]WARNING[/yellow] - {}".format(e))

# Used to close all sessions
def logoff(fw, sid):
    api_call(fw, "logout", {}, sid)

################################## API Engine ##################################
# The 'API engine' that runs any cmds fed into it (by other methods) against the Checkpoint manager
def api_call(ip_addr, command, json_payload, sid):
    url = 'https://' + ip_addr + '/web_api/' + command
    request_headers = {'Content-Type' : 'application/json', 'X-chkp-sid' : sid}
    # Runs the API call with the supplied payload, must be POST
    res = requests.post(url,data=json.dumps(json_payload), headers=request_headers, verify=False)
    # If a command fails tells the user and stops the script
    if res.status_code != 200:
        print('\n!!! ERROR - {} - {}'.format(res.json()["code"], res.json()["message"]))
        print("-Something went wrong when running the command '{}' and payload '{}' on {}".format(command, json_payload, ip_addr))
        exit()
    # If command successful returns the payload in json format (data)
    else:
        return res.json()

################################## 2. Gather ACLs from CHeckpoints ##################################
def get_acls(dev, sid):
    policy_name, policy_offset, acl_brief, acl_expanded = ([] for i in range(4))

    # 2a. Gather list of all the policies (layers)
    all_policies = api_call(dev, "show-access-layers", {}, sid)
    for policy in all_policies['access-layers']:
        policy_name.append(policy['name'])

    # 2b. Get the total number of rules as can only get in one API call either 20 when expanded (show-as-ranges) or 500 non-expanded so need to use offsets
    for policy in policy_name:
        output = api_call(dev, "show-access-rulebase", {"limit" : 0, "name" : policy}, sid)
        # Create a dict of {name: policy_name, num_rules: total_number_rules_in_policy)
        policy_offset.append(dict(name=policy, num_rules=output['total']))

    # 2c. ACL: Using offset tuple get list of all the rules within each policy (does not expand groups)
    for policy in policy_offset:
        # (Start rule number, total number rules, amount to offset the start by each iteration)
        for offset in range(0, policy['num_rules'], 500):
        # for offset in range(1,4,3):
            # Limit is the max number of rules returned and offset the number of rules to skip. To get just rules 11 to 25 use range(10,25,15) and "limit": 15
            payload = {"offset": offset, "limit": 500, "name": policy['name'], "show-hits": True, "use-object-dictionary": False}
            # payload = {"offset": offset, "limit": 15, "name": policy['name'], "show-hits": True, "use-object-dictionary": False}
            output = api_call(dev , "show-access-rulebase", payload, sid)
            acl_brief.append(output)

    # 2d. ACL_EXP: Using offset tuple get list of all the rules within each policy, with all groups and objects expanded as ranges
    for policy in policy_offset:
        # for offset in range(1,4,3):
        for offset in range(0, policy['num_rules'], 20):
            payload = {"offset": offset, "limit": 20, "name": policy['name'], "show-as-ranges": True, "show-hits": True,  "use-object-dictionary": False}
            # payload = {"offset": offset, "limit": 15, "name": policy['name'], "show-as-ranges": True, "show-hits": True,  "use-object-dictionary": False}
            output = api_call(dev , "show-access-rulebase", payload, sid)
            acl_expanded.append(output)

    return acl_brief, acl_expanded


################################## DRY filters run by the main Sanitize method (format_acl) ##################################

# CATEG_OBJ: Based on the object type adda an identifier to the start of the name (hst, net, grp, app, service, etc)
def categorize_obj(object):
    normalized = []
    for obj in object:
        # Checkpoint devices (gateway, manager or reporter)
        if obj['type'] == 'CpmiGatewayCluster' or obj['type'] == 'CpmiClusterMember':
            normalized.append('gtw_' + obj['name'])
        elif obj['type'] == 'CpmiHostCkp':
            normalized.append('mgr_' + obj['name'])
        elif obj['type'] == 'simple-gateway':
            normalized.append('rpt_' + obj['name'])
        # Source or destination address objects (host, network, dns_name or group)
        elif obj['type'] == 'host':
            normalized.append('hst_' + obj['name'])
        elif obj['type'] == 'network':
            normalized.append('net_' + obj['name'])
        elif obj['type'] == 'dns-domain':
            normalized.append('dns_' + obj['name'])
        elif obj['type'] == 'group':
            normalized.append('grp_' + obj['name'])
        # Services, application and groups for these
        elif obj['type'] == 'service-tcp':
            normalized.append('tcp_' + obj['port'])
        elif obj['type'] == 'service-udp':
            normalized.append('udp_' + obj['port'])
        elif obj['type'] == 'service-icmp':
            normalized.append('icmp_' + obj['name'])
        elif obj['type'] == 'service-dce-rpc':
            normalized.append('dce-rpc_' + obj['name'])
        elif obj['type'] == 'service-other':
            normalized.append('other_' + obj['name'])
        elif obj['type'] == 'service-group':
            normalized.append('svc-grp_' + obj['name'])
        elif obj['type'] == 'application-site':
            normalized.append('app_' + obj['name'])
        elif obj['type'] == 'application-site-group':
            normalized.append('app-grp_' + obj['name'])
        # Other object types
        elif obj['type'] == 'Internet' or obj['type'] == 'CpmiAnyObject':
            normalized.append(obj['name'])
    # Catchall if the object UID is not one of these types
    if len(normalized) == 0:
        normalized.append('unknown_' + obj['name'])
    return normalized

# NORM_IP: Converts source and destination Address ranges into usable format (host, network or range).
def normalise_ip(ip_element):
    addr_list = []
    # If is no IPv4 addresses or address objects adds a buffer object
    if len(ip_element['ipv4']) == 0 and len(ip_element['others']) == 0:
        addr_list.append('none')
    # If is IPv4 addresses converts ranges to prefixes
    elif len(ip_element['ipv4']) != 0:
        for addr in ip_element['ipv4']:
            # If start/end ranges are the same create a host entry
            if addr['start'] == addr['end']:
                addr_list.append(addr['start'] + '/32')
            # If its address range 0.0.0.0 to 255.255.255.255 represents 'any' in the rulebase
            elif addr['start'] == '0.0.0.0' and addr['end'] == '255.255.255.255':
                addr_list.append('any')
            else:
            # If start/end range are a valid network address create a network entry
                try:
                    # Split IPs into octets and subtract creating new list that is the wildcard mask
                    wildcard = []
                    for start, end in zip(addr['start'].split('.'), addr['end'].split('.')):
                        wildcard.append(int(end) - int(start))
                    # As is a list of numbers map() converts each item to a string so they can be joined
                    wildcard = '.'.join(map(str, wildcard))
                    addr_list.append(str(ip_network(addr['start'] + '/' + wildcard)))
                # If is not a valid network creates a range just adds start-end addresses
                except ValueError:
                        addr_list.append(addr['start'] + '-' + addr['end'])
    # None IPs, so UID of an object (normally Internet)
    elif len(ip_element['others']) != 0:
        addr_list.extend(categorize_obj(ip_element['others']))
    # Catchall for anything may have missed as would break logic when do final reformatting
    else:
        addr_list.append('none')
    return addr_list

# NEGATE: Adds NOT to any source, destination, or services that are negated
def negate(ace):
    temp_svc, temp_dst, temp_src = ([] for i in range(3))
    # If service is negated splits protocol and service, adds NOT_ to the svc and rejoins
    if ace[13] == True:
        for prot_svc in ace[7]:
            prot_svc = prot_svc.split('_')
            prot_svc[1] = 'NOT_' + prot_svc[1]
            temp_svc.append('_'.join(prot_svc))
        ace[7] = temp_svc
    # If destination is negated create a new list where all dst start with NOT_ and replace original list
    if ace[12] == True:
        for dst in ace[6]:
            temp_dst.append('NOT_' + dst)
        ace[6] = temp_dst
    # If source is negated create a new list where all src start with NOT_ and replace original list
    if ace[11] == True:
        for src in ace[4]:
            temp_src.append('NOT_' + src)
        ace[4] = temp_src


# ################################## 3. Sanitize the data - Create ACL structured data ##################################
# 3. ENGINE: Feeds ACL data and uses functions to produce standardized data model of ACL and expanded ACL
def format_acl(fw, acl_brief, acl_expanded):
    acl, acl_exp, final_acl = ([] for i in range(3))
    #3a. Loops through each section and set of 500 rules (non-expanded ACEs) to create new list of lists of only the fields required
    for policy in acl_brief:
        for rule in policy['rulebase']:
            # If it has access-sections then is another layer of nested rulebase
            if rule['type'] == 'access-section':
                for rule in rule['rulebase']:
                    # For nested inline policies replaces action with name of nested policy
                    if rule.get('inline-layer') != None:
                        rule['action']['name'] = 'POLICY_' + rule['inline-layer']['name']
                    acl.append([policy['name'], rule['rule-number'], rule['action']['name'], 'protocol', rule['source'], 'any_port',
                                rule['destination'], rule['service'], rule['hits']['value'], rule['hits'].get('last-date'),
                                rule['enabled'], rule['source-negate'], rule['destination-negate'], rule['service-negate']])
            # If it does not have an access-sections no more rulebase nesting
            elif rule['type'] == 'access-rule':
                # For nested inline policies replaces action with name of nested policy
                if rule.get('inline-layer') != None:
                    rule['action']['name'] = 'POLICY_' + rule['inline-layer']['name']
                acl.append([policy['name'], rule['rule-number'], rule['action']['name'], 'protocol', rule['source'], 'any_port',
                            rule['destination'], rule['service'], rule['hits']['value'], rule['hits'].get('last-date'),
                            rule['enabled'], rule['source-negate'], rule['destination-negate'], rule['service-negate']])

    #3b. Loops through each section and set of 20 rules (expanded ACEs) to create new list of lists of only the fields required
    for policy in acl_expanded:
        for rule in policy['rulebase']:
            # If it has access-sections then is another layer of nested rulebase
            if rule['type'] == 'access-section':
                for rule in rule['rulebase']:
                    # For nested inline policies replaces action with name of the nested policy
                    if rule.get('inline-layer') != None:
                        rule['action']['name'] = 'POLICY_' + rule['inline-layer']['name']
                    acl_exp.append([policy['name'], rule['rule-number'], rule['action']['name'], 'protocol', rule['source-ranges'],
                                    'any_port', rule['destination-ranges'], rule['service-ranges'], rule['hits']['value'],
                                    rule['hits'].get('last-date'), rule['enabled']])
            # If it does not have an access-sections no more rulebase nesting
            elif rule['type'] == 'access-rule':
            # For nested inline policies replaces action with name of the nested policy
                if rule.get('inline-layer') != None:
                    rule['action']['name'] = 'POLICY_' + rule['inline-layer']['name']
                acl_exp.append([policy['name'], rule['rule-number'], rule['action']['name'], 'protocol', rule['source-ranges'],
                                'any_port', rule['destination-ranges'], rule['service-ranges'], rule['hits']['value'],
                                rule['hits'].get('last-date'), rule['enabled']])

    # Loops though both rulebases to normalise the data (categorize object names, simplify ranges, timestamp, etc)
    for acl_item in [acl, acl_exp]:
        for ace in acl_item:

            # 3c.ACL: For source, destination and service objects add an identifier (hst, net, grp, etc)
            if len(ace) == 14:
                ace[4] = categorize_obj(ace[4])
                ace[6] = categorize_obj(ace[6])
                dst_svc = categorize_obj(ace[7])
                # Object 'CpmiAnyObject' can be used by other things so have to add protocol on here
                if dst_svc == ['Any']:
                    ace[7] = ['any_any']
                else:
                    ace[7] = dst_svc

            # 3d. ACL_EXP: For address ranges converts source and destination ranges into host or network
            else:
                ace[4] = normalise_ip(ace[4])
                ace[6] = normalise_ip(ace[6])
                # If has TCP and UDP range is represented as 'ANY' in the rulebase
                dst_svc = []
                temp_svc = []
                if len(ace[7]['tcp']) != 0 and len(ace[7]['udp']) != 0:
                    dst_svc.append('any_any')
                # Anything else adds identifier to ICMP, protocol, application or group objects
                if len(ace[7]['others']) != 0:
                    dst_svc.extend(categorize_obj(ace[7]['others']))
                # For excludes source. Needs to go through negate function later so adds negate boolean to ace (element 12 to 14)
                elif len(ace[7]['excluded-others']) != 0:
                    dst_svc.extend(categorize_obj(ace[7]['excluded-others']))
                    ace.extend([False, False, True])
                ace[7] = dst_svc

            #3e. ACE: Only ACE has the negate field, adds NOT to any source, destination, or services that are negated
            if len(ace) == 14:
                negate(ace)

            # 3f. From unixtime (posix) gets human readable time and splits date and time into separate elements
            if ace[9] == None:
                ace[9] = ''
                ace.insert(10, '')
            else:
                unix_time = str(ace[9]['posix'])[:-3]
                human_time = datetime.fromtimestamp(int(unix_time)).strftime('%Y-%m-%d %H:%M:%S').split(' ')
                ace[9] = human_time[0]
                ace.insert(10, human_time[1])
            # 3g. Change state to 'inactive' or blank
            if ace[11] == False:
                ace[11] = 'Inactive'
            else:
                ace[11] = ''

    # # 3h. "show-as-ranges" with negated dst or src fields are blank, therefore need to get those values from acl list
    for rule, rule_exp in zip(acl,acl_exp):
        # tmp_rule = []
        if rule[12] == True:
            rule_exp[4] = rule[4]
        if rule[13] == True:
            rule_exp[6] = rule[6]

    # CREATE ACE: Creates a separate ace entry for each unique source/destination rule before creating ACL and adding it to the final_acl list
    for acl_item in [acl, acl_exp]:
        temp_acl = []                # Has to be here so is cleared at each iteration
        for ace in acl_item:
            # Loops through source, destination  and service lists and spliting out into all variations
            for src in ace[4]:
                for dst in ace[6]:
                    for each_prot_svc in ace[7]:
                        # Splits the dst_svc into protocol and service
                        prot_svc = each_prot_svc.split('_')
                        # Needed incase object names have underscore in them (_) to join rest of object name back together
                        if len(prot_svc) == 2:
                            svc = prot_svc[1]
                        else:
                            svc = '_'.join(prot_svc[1:])
                        temp_acl.append([ace[0], ace[1], ace[2], prot_svc[0], src, 'any_port', dst, svc, ace[8], ace[9], ace[10], ace[11]])
        final_acl.append(temp_acl)

    # OUTPUT: Returns a dictionary of {device_ip_acl: non_expanded_acl, device_ip_exp_acl: expanded_acl} with every line of each being in the format:
    # [name, num, permit/deny, protocol, src_ip/pfx, src_port, dst_ip/pfx, dst_port, hitcnt, last_hit_date, last_hit_time, state]
    return {fw + '_acl': final_acl[0], fw + '_exp_acl': final_acl[1]}

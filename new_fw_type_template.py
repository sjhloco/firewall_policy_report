#!/usr/bin/env python
import json
import requests
import urllib3
from datetime import datetime
urllib3.disable_warnings()


###################################### 1. Login ######################################
# Initial login to get a Session ID (SID) and handling of errors.
def login(fw, user, pword):
    # Login attempt
    try:
        pass
        return (True, net_conn)
    # Login failure
    except Exception as e:
        return (False, "\u26A0\uFE0F  [yellow]WARNING[/yellow] - '{}'".format(e).splitlines()[0])

# Used to close all sessions
def logoff(fw, sid):
    sid.disconnect()


################################## 2. Gather ACLs from CHeckpoints ##################################
# Uses SID (session ID) to connect to the device and run commands to get the ACL contents and return back two lists to main.py
def get_acls(dev, sid):
    pass
    return acl_brief, acl_expanded


################################## DRY filters run by the main Sanitize method (format_acl) ##################################
# Due to the repetitive nature of ACLs it is likely same code is used multiple times when santising the data
# Is best to create functions for these and call them multiple times to save having repetitive code


# ################################## 3. Sanitize the data - Create ACL structured data ##################################
# Takes the data gathered from get_acls and normalises it to create two lists (ACL and Expanded_ACL) in a standardized data model format to create the XL sheet report
# [name, num, permit/deny, protocol, src_ip/pfx, src_port, dst_ip/pfx, dst_port, hitcnt, last_hit_date, last_hit_time, state]

def format_acl(fw, acl_brief, acl_expanded):
    pass
    return {fw + '_acl': acl, fw + '_exp_acl': acl_exp}

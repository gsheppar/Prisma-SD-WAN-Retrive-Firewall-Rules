#!/usr/bin/env python3
import cloudgenix
import argparse
from cloudgenix import jd, jd_detailed, jdout
import yaml
import cloudgenix_settings
import sys
import logging
import ipcalc
import ipaddress
import os
import datetime
import sys
import csv


# Global Vars
TIME_BETWEEN_API_UPDATES = 60       # seconds
REFRESH_LOGIN_TOKEN_INTERVAL = 7    # hours
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix: Example get firewall rules'
SCRIPT_VERSION = "1"

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)

####################################################################
# Read cloudgenix_settings file for auth token or username/password
####################################################################

sys.path.append(os.getcwd())
try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

def get_firewall(cgx, policy_name):  
    try:
        print('Retrieving list of all local prefixes\n')
        local_prefix_id2n = {}
        for prefix_filter in cgx.get.ngfwsecuritypolicylocalprefixes().cgx_content['items']:
            prefix_name =  prefix_filter['name']
            prefix_id =  prefix_filter['id']
            local_prefix_id2n[prefix_id] = prefix_name

        print('Retrieving list of all global prefixes\n')

        global_prefix_id2n = {}
        for prefix_filter in cgx.get.ngfwsecuritypolicyglobalprefixes().cgx_content['items']:
            prefix_name =  prefix_filter['name']
            prefix_id =  prefix_filter['id']
            global_prefix_id2n[prefix_id] = prefix_name

        print('Retrieving list of all zones\n')

        zone_id2n = {}
        for zone in cgx.get.securityzones().cgx_content['items']:
            zone_name =  zone['name']
            zone_id =  zone['id']
            zone_id2n[zone_id] = zone_name

        print('Retrieving list of all apps\n')

        appdefs_id2n = {}
        for app in cgx.get.appdefs().cgx_content['items']:
            app_name =  app['display_name']
            app_id =  app['id']
            appdefs_id2n[app_id] = app_name
    
        security_policy_id = None

        for security_policy_stack in cgx.get.ngfwsecuritypolicysetstacks().cgx_content["items"]:
            if security_policy_stack['name'] == policy_name:
                security_policy_id = security_policy_stack['policyset_ids']
                security_policy_id.append(security_policy_stack["defaultrule_policyset_id"])
                break
        firewall_rules = []
        firewall_rules_ordered = []
    
        if not security_policy_id:
            print("Security policy set " + policy_name + " does not exsist")
        
        for item_id in security_policy_id:
            for security_policy_stack in cgx.get.ngfwsecuritypolicysets().cgx_content["items"]:
                if security_policy_stack['id'] == item_id:
                    security_policy_id = security_policy_stack['id']
                    set_name = security_policy_stack["name"]
                    policyrule_order = security_policy_stack['policyrule_order']
            print("Getting rules from set " + set_name)
            for security_rules in cgx.get.ngfwsecuritypolicyrules(ngfwsecuritypolicyset_id=security_policy_id).cgx_content["items"]:
                firewall_rule_dict = {}
                firewall_rule_dict["policy_name"] = set_name
                firewall_rule_dict["id"] = security_rules["id"]
                firewall_rule_dict["name"] = security_rules["name"]
                firewall_rule_dict["description"] = security_rules["description"]

                id_list = security_rules["source_zone_ids"]
                name_list = []
                for id in id_list:
                    if id == "any":
                        name_list.append("any")
                    else:
                        name_list.append(zone_id2n[id])
                updated_str = ", ".join(name_list)
                firewall_rule_dict["source_zones"] = updated_str
            
                id_list = security_rules["source_prefix_ids"]
                name_list = []
                if id_list == None:
                    firewall_rule_dict["source_filters"] = "None"
                else:
                    for id in id_list:
                        if id == "any":
                            name_list.append("any")
                        else:
                            if id in local_prefix_id2n:
                                name_list.append(local_prefix_id2n[id])
                            elif id in global_prefix_id2n:
                                name_list.append(global_prefix_id2n[id])
                    updated_str = ", ".join(name_list)
                    firewall_rule_dict["source_filters"] = updated_str

                id_list = security_rules["destination_zone_ids"]
                name_list = []
                for id in id_list:
                    if id == "any":
                        name_list.append("any")
                    else:
                        name_list.append(zone_id2n[id])
                updated_str = ", ".join(name_list)
                firewall_rule_dict["destination_zones"] = updated_str

                id_list = security_rules["destination_prefix_ids"]
                name_list = []
                if id_list == None:
                    firewall_rule_dict["destination_filters"] = "None"
                else:
                    for id in id_list:
                        if id == "any":
                            name_list.append("any")
                        else:
                            if id in local_prefix_id2n:
                                name_list.append(local_prefix_id2n[id])
                            elif id in global_prefix_id2n:
                                name_list.append(global_prefix_id2n[id])
                    updated_str = ", ".join(name_list)
                    firewall_rule_dict["destination_filters"] = updated_str

                id_list = security_rules["app_def_ids"]
                name_list = []
                for id in id_list:
                    if id == "any":
                        name_list.append("any")
                    else:
                        name_list.append(appdefs_id2n[id])
                updated_str = ", ".join(name_list)
                firewall_rule_dict["applications"] = updated_str
                firewall_rule_dict["action"] = security_rules["action"]
                firewall_rule_dict["disabled_flag"] = security_rules["enabled"]

                firewall_rules.append(firewall_rule_dict)

            for rule_order in policyrule_order:
                for rule in firewall_rules:
                    if rule_order == rule["id"]:
                        updated_rule = {}
                        updated_rule = rule.copy()
                        updated_rule.pop("id")
                        firewall_rules_ordered.append(updated_rule)
    
        csv_columns = []        
        for key in (firewall_rules_ordered)[0]:
            csv_columns.append(key)
        
        csv_file = policy_name + " firewall_rules.csv"
        with open(csv_file, 'w', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
            writer.writeheader()
            for data in firewall_rules_ordered:
                try:
                    writer.writerow(data)
                except:
                    print("Failed to write data for row")
            print("Saved " + csv_file + " file")
    
    except Exception as e:
        print("Failed getting firewall policy")
        print(str(e))
    return
                                 
def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    config_group = parser.add_argument_group('Name', 'These options change how the configuration is loaded.')
    config_group.add_argument("--name", "-N", help="Firewall policy name", required=True, default=None)
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "Alpha: https://api-alpha.elcapitan.cloudgenix.com"
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default=None)
    controller_group.add_argument("--insecure", "-I", help="Disable SSL certificate and hostname verification",
                                  dest='verify', action='store_false', default=True)
    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-PW", help="Use this Password instead of prompting",
                             default=None)
    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    debug_group.add_argument("--debug", "-D", help="Verbose Debug info, levels 0-2", type=int,
                             default=0)
                             
    args = vars(parser.parse_args())
    
    ############################################################################
    # Instantiate API
    ############################################################################
    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=args["verify"])

    # set debug
    cgx_session.set_debug(args["debug"])

    ##
    # ##########################################################################
    # Draw Interactive login banner, run interactive login including args above.
    ############################################################################
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SCRIPT_VERSION, cgx_session.controller))

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["pass"]:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit()

    else:
        while cgx_session.tenant_id is None:
            cgx_session.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not cgx_session.tenant_id:
                user_email = None
                user_password = None

    ############################################################################
    # End Login handling, begin script..
    ############################################################################

    # get time now.
    curtime_str = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')

    # create file-system friendly tenant str.
    tenant_str = "".join(x for x in cgx_session.tenant_name if x.isalnum()).lower()
    cgx = cgx_session
    policy_name = args["name"]

    get_firewall(cgx, policy_name) 
    # end of script, run logout to clear session.
    print("End of script. Logout!")
    cgx_session.get.logout()

if __name__ == "__main__":
    go()
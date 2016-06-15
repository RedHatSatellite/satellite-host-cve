#!/usr/bin/python

import json
import sys
import getpass

try:
    import requests
    import argparse
except ImportError:
    print "Please install the python-requests and python-argparse modules."
    sys.exit(-1)

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# Performs a GET using the passed URL data
def get_json(url):
    url = "https://{0}/{1}".format(args.server, url)
    url += "&per_page=9999" if "?" in url else "?per_page=9999"
    ssl = False if (args.nossl) else True

    r = requests.get(url, auth=(args.username, args.password), verify=ssl)
    return r.json()


# Performs the call to Satellite with some error handling on the result
def get_results(url):
    jsn = get_json(url)
    if jsn.get('error'):
        print "Error: " + jsn['error']['message']
    else:
        if jsn.get('results'):
            return jsn['results']
        elif 'results' not in jsn:
            return jsn
    return None

# Get all CVE's and related errata from env in env-path of host and add to data maps
def build_host_cves(host_id, env, cv, host_cve_errata, host_cve_env):

    env_id = 0 if env == 1 and cv == 1 else env

    errata = get_results("api/v2/hosts/{0}/errata?environment_id={1}&content_view_id={2}&search=type=security".format(host_id, env, cv))

    if errata:
        for erratum in errata:
            cves = erratum['cves']
            for cve in cves:
                if cve['cve_id'] not in host_cve_errata:
                   host_cve_errata[cve['cve_id']] = []
                   host_cve_env[cve['cve_id']] = []
                if not env_id:
                   host_cve_errata[cve['cve_id']].append(erratum['errata_id'])
                if env_id not in host_cve_env[cve['cve_id']]:
                   host_cve_env[cve['cve_id']].append(env_id)
    return None

# build the env-path of the host in a list
def build_env_path(env_id):

    env_path = []
    env_size = 0
    while env_id:
        lce = get_results("katello/api/v2/organizations/{0}/environments/{1}".format(args.organization, env_id))
        env_path.append([lce['id'],lce['name']])
        if lce['library']:
            env_id = 0
            env_path.append([env_id,lce['name']])
        else:
            env_id = lce['prior']['id']
    return env_path
    

def main():

    global args # make sure all parser data is available globally

    # set up parser
    parser = argparse.ArgumentParser(description="Satellite CVE Reporter")  

    # Define arguments
    parser.add_argument("-u", "--username", type=str.lower, help="Username to access Satellite (defaults to admin", action="store", default='admin')
    parser.add_argument("-p", "--password", type=str, help="Password to access Satellite (asked if not given)", action="store", default='')
    parser.add_argument("-n", "--server", type=str.lower, help="Satellite server (defaults to localhost)", default='localhost')
    parser.add_argument("-o", "--organization", type=str.lower, help="Organization (defaults to 1)", default='1')
    parser.add_argument("-s", "--host", type=str.lower, help="Show only CVE's for this host (all if not given)", default='')
    parser.add_argument("-x", "--no-ssl-verify", dest='nossl', help="Disable SSL verification", default=False, action="store_true")

    args = parser.parse_args()

    # ask for password if needed
    if not args.password:
       args.password = getpass.getpass()

    # Check username and password
    if not (args.username and args.password):
        print "No complete account information provided, exiting"
        sys.exit (-1)

    # get host(s) records from satellite
    search_arg = "?search=name={0}".format(args.host) if args.host else "" # either one or all hosts 
    hosts = get_results("api/v2/organizations/{0}/hosts{1}".format(args.organization, search_arg))

    # main loop: host(s)
    for host in hosts:
        if 'content_facet_attributes' not in host: # not a content host
            if args.host:
               print "Host is not a content_host"
               sys.exit (-1)
            else:
               continue # iterate to the next host when doing all hosts

        # build CVE map
        host_cve_errata={}
        host_cve_env={}
        host_env_id = host['content_facet_attributes']['lifecycle_environment']['id']

        env_path = build_env_path(host_env_id)
        for env_id, env_name in reversed(env_path):
            if not env_id:
                env_title = "CVE".ljust(15) + "Synced"
                build_host_cves(host['id'], 1, 1, host_cve_errata, host_cve_env) # library synced have env and cv on id 1
            else:
                env_title += " -> " + env_name
                build_host_cves(host['id'], env_id, host['content_facet_attributes']['content_view']['id'], host_cve_errata, host_cve_env)

        # Pretty print CVE map
        if host_cve_errata:
            print "\nCVE's for host {0} on content view {1} in lifecycle environment {2}".format \
                 (host['name'], \
                  host['content_facet_attributes']['content_view']['name'], \
                  host['content_facet_attributes']['lifecycle_environment']['name'])
            env_title = "\n" + env_title + "       In errata"
            print env_title + "\n" + "-" * (len(env_title) + 4)

            for cve_id, errata_ids in sorted(host_cve_errata.iteritems()) :
                env_map = "  "
                cve_state = "I" if host_cve_env[cve_id][-1] == host_env_id else "A"

                for env_id, env_name in reversed(env_path):
                    env_map = env_map + cve_state if env_id in host_cve_env[cve_id] else env_map + " "
                    env_map += '{:<{}s}'.format('', len(env_name)+2)
                print '{:<{}s}'.format(cve_id, 15) + env_map + "    " + ','.join(errata_ids)

if __name__ == "__main__":
    main()


#!/usr/bin/env python3

import urllib.request
import urllib.error
import argparse
import json
import re

def print_request_info():
    global data

    print("=" * 80)
    print("Request information:")
    print(" {:20s}: {:s}".format("Server ID", data['server_id']))
    print(" {:20s}: {:s}".format("Version", data['version']))
    print(" {:20s}: {:s}".format("Time:", data['time']))
    print(" {:20s}: {:s}".format("Query ID", data['query_id']))
    if data['cached']:
        print("Request is cached!")

def print_prefix_info():
    global data

    print("=" * 80)
    print("PREFIXES")

    if not len(data['data']['prefixes']):
        print("-" * 80)
        print("No routes.")
        print("=" * 80)
        return

    print("-" * 80)
    print("{:>30s}{:>12s}{:>12s}\t{:s}".format("Prefix", "BGP", "WHOIS", "WHOIS source"))
    print("-" * 80)
    for prefix in data['data']['prefixes']:
        bgp_status = "OK" if prefix['in_bgp'] else "NO ROUTE"
        whois_status = "OK" if prefix['in_whois'] else "MISSING"
        irr_sources = ", ".join(prefix["irr_sources"])
        print("{:>30s}{:>12s}{:>12s}\t{:s}".format(prefix['prefix'], bgp_status, whois_status, irr_sources))

def asn_type(asn, pattern=re.compile(r"^(AS)?([0-9]+)$")):
    """
    Argparse type checker
    :param asn:         ASN passed by argparse
    :param pattern:     Allow ASXXXX or just XXXX
    :return:            Return ASN without the "AS" prefix
    """
    match = pattern.match(asn)
    if match:
        return match.group(2)
    else:
        raise argparse.ArgumentTypeError("ASN should be in AS1234 or 1234 format")

base_url = "https://stat.ripe.net/data/as-routing-consistency/data.json?resource=AS"

argv = argparse.ArgumentParser()
argv.add_argument("ASN", help="Autonomous system number", type=asn_type)
argv.add_argument("-p", "--prefixes", help="Show only prefixes", action='store_true')
argv.add_argument("-i", "--imports", help="Show only imports", action='store_true')
argv.add_argument("-e", "--exports", help="Show only exports", action='store_true')
args = argv.parse_args()

asn = args.ASN

url = base_url + str(asn)

try:
    response = urllib.request.urlopen(url)
    data = json.loads(response.read().decode('utf-8'))
    if 'status' in data:
        status = data['status']
        if status == 'ok':
            print("=" * 80)
            print("{:20s}:\tAS{:s}".format("Resource ASN", data['data']['resource']))
            print("{:20s}:\t{:s}".format("Authority", data['data']['authority']))
            print_request_info()
            if args.prefixes:
                print_prefix_info()
            else:
                print_prefix_info()
            print("=" * 80)

except urllib.error.HTTPError:
    print("Request error")

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
    print("{:>30s}{:>12s}{:>12s}\t{:s}".format("PREFIX", "BGP", "WHOIS", "WHOIS SOURCE"))
    print("-" * 80)
    for prefix in data['data']['prefixes']:
        bgp_status = "OK" if prefix['in_bgp'] else "NO ROUTE"
        whois_status = "OK" if prefix['in_whois'] else "MISSING"
        irr_sources = ", ".join(prefix["irr_sources"])
        print("{:>30s}{:>12s}{:>12s}\t{:s}".format(prefix['prefix'], bgp_status, whois_status, irr_sources))

def print_import_info():
    global data

    print("=" * 80)
    print("IMPORTS")

    if not len(data['data']['imports']):
        print("-" * 80)
        print("No imports.")
        print("=" * 80)
        return

    print("-" * 80)
    print("{:>10s}{:>15s}{:>15s}".format("PEER ASN", "BGP", "WHOIS"))
    print("-" * 80)
    for imports in data['data']['imports']:
        bgp_status = "OK" if imports['in_bgp'] else "NO PEERING"
        whois_status = "OK" if imports['in_whois'] else "NO IMPORT"
        peer_asn = "AS{:d}".format(imports['peer'])
        print("{:>10s}{:>15s}{:>15s}".format(peer_asn, bgp_status, whois_status))

def print_export_info():
    global data

    print("=" * 80)
    print("EXPORTS")

    if not len(data['data']['exports']):
        print("-" * 80)
        print("No exports.")
        print("=" * 80)
        return

    print("-" * 80)
    print("{:>10s}{:>15s}{:>15s}".format("PEER ASN", "BGP", "WHOIS"))
    print("-" * 80)
    for exports in data['data']['exports']:
        bgp_status = "OK" if exports['in_bgp'] else "NO PEERING"
        whois_status = "OK" if exports['in_whois'] else "NO EXPORT"
        peer_asn = "AS{:d}".format(exports['peer'])
        print("{:>10s}{:>15s}{:>15s}".format(peer_asn, bgp_status, whois_status))

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
            elif args.imports:
                print_import_info()
            elif args.exports:
                print_export_info()
            else:
                print_prefix_info()
                print_import_info()
                print_export_info()
            print("=" * 80)

except urllib.error.HTTPError:
    print("Request error")

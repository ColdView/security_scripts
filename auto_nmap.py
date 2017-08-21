# -*- coding: utf-8 -*-
"""
Python 3.5.3 Script which scans a given ip range for live hosts 
then runs an nmap scan against those hosts using given nmap options.
Make sure to include (--) with nmap options as shown in usage!  
"""

import argparse
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
import pandas as pd

scanned_hosts = []
open_ports = []
services = []
cpe_list = []
URL = "https://nvd.nist.gov/vuln/search/results?" \
          "adv_search=true&cves=on&cpe_version="


def get_args():
    parser = argparse.ArgumentParser(prog="auto_nmap.py", 
                      usage ="auto_nmap.py 192.168.56.0/24 -- -sV")
    parser.add_argument(
            "-i", "--ip_range", type=str, help="Add the ip_range "
            "for the first stage host scan!", required=True)
    parser.add_argument(
            "nmap_options", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    ip_range = args.ip_range
    nmap_options = " ".join(args.nmap_options[1:])
    return ip_range, nmap_options

ip_range, nmap_options= get_args()

def host_scan():
    nm = NmapProcess(ip_range, options="-sn")
    nm.run()
    nmap_report = NmapParser.parse(nm.stdout)
    host_list = []    
    for h in nmap_report.hosts:
        if h.is_up():
            _host = h.address
            host_list.append(_host)

    return host_list

live_hosts = host_scan()

def port_scan(targets, options):
    nm = NmapProcess(targets, options)
    rc = nm.run()
    parsed_scan = NmapParser.parse(nm.stdout)
    return parsed_scan

def parse_report(nmap_report):
    for host in nmap_report.hosts:
        # Populate lists with each attribute 
        for serv in host.services:
            if serv.open():
                scanned_hosts.append(host.address)
                open_ports.append(serv.port)
                services.append(serv)
                cpe = str(serv.cpelist).strip("[]")
                cpe_list.append('<a href="{u}" target="_blank">{name}</a>' \
                      .format(u=URL+cpe, name="link"))
            else:
                pass

def make_table():
    df = pd.DataFrame({
            "Scanned Host": scanned_hosts, 
            "Service": services, 
            "Open Port": open_ports, 
            "Cve Link": cpe_list, 
        })

    table = df[["Scanned Host", "Service", "Open Port", "Cve Link"]]
    pd.set_option('display.max_colwidth', 250)
    pd.set_option('max_rows', 100)
    pd.set_option('colheader_justify', 'left')
    table.to_html('nmap_table.html', escape=False)

if __name__ == "__main__":    
    report = port_scan(live_hosts, nmap_options)
    if report:
        parse_report(report)
        make_table()

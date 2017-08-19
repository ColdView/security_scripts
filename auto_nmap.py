"""
Python 3.5.3 Script which takes an ip range as an argument and
prints to screen live hosts 
"""

import argparse
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser

def get_args():
    parser = argparse.ArgumentParser(description='Script gets hosts')
    parser.add_argument(
            '-i', '--ip_range', type=str, help='ip_range', required=True)
    args = parser.parse_args()
    #ip_range = args.ip_range
    return args.ip_range
ip_range = get_args()

def host_scan():
    nm = NmapProcess(ip_range, options="-sn")
    nm.run()
    nmap_report = NmapParser.parse(nm.stdout)
        
    for h in nmap_report.hosts:
        if h.is_up():
            _hosts = h.address
            print(_hosts)
host_scan()
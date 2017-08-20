# -*- coding: utf-8 -*-
"""
Python 3.5.3 Script which scans a given ip range for live hosts 
then runs an nmap scan against those hosts using given nmap options.
Make sure to include (--) with nmap options as shown in usage!  
"""

import argparse
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException


# start a new nmap scan on localhost with some specific options
def get_args():
    parser = argparse.ArgumentParser(prog="auto_nmap.py", 
                      usage ="auto_nmap.py 192.168.56.0/24 -- -sV")
    parser.add_argument(
            "-i", "--ip_range", type=str, help="Add the ip_range "
            "for the first stage host scan!", required=True)
    parser.add_argument(
            "opt", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    ip_range = args.ip_range
    opt = " ".join(args.opt[1:])
    return ip_range, opt

ip_range, opt = get_args()

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


def do_scan(targets, options):
    parsed = None
    nmproc = NmapProcess(targets, options)
    rc = nmproc.run()
    if rc != 0:
        print("nmap scan failed: {0}".format(nmproc.stderr))
    print(type(nmproc.stdout))

    try:
        parsed = NmapParser.parse(nmproc.stdout)
    except NmapParserException as e:
        print("Exception raised while parsing scan: {0}".format(e.msg))

    return parsed


def print_scan(nmap_report):
    print("Starting Nmap {0} ( http://nmap.org ) at {1}".format(
        nmap_report.version,
        nmap_report.started))

    for host in nmap_report.hosts:
        if len(host.hostnames):
            tmp_host = host.hostnames.pop()
        else:
            tmp_host = host.address

        print("Nmap scan report for {0} ({1})".format(
            tmp_host,
            host.address))
        print("Host is {0}.".format(host.status))
        print("  PORT     STATE         SERVICE")

        for serv in host.services:
            pserv = "{0:>5s}/{1:3s}  {2:12s}  {3}".format(
                    str(serv.port),
                    serv.protocol,
                    serv.state,
                    serv.service)
            if len(serv.banner):
                pserv += " ({0})".format(serv.banner)
            print(pserv)
    print(nmap_report.summary)


hosts = host_scan()

if __name__ == "__main__":
    report = do_scan(hosts, opt)
    if report:
        print_scan(report)
    else:
        print("No results returned")

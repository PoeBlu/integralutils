#!/usr/bin/env python3

import os
import argparse

from integralutils import CuckooParser
from integralutils import VxstreamParser
from integralutils import WildfireParser

def main():
    parser = argparse.ArgumentParser()
    
    parser.add_argument('-r', '--report-path', action='store', dest='report_path',
        required=True, default=None,
        help="Path of the Cuckoo/VxStream/Wildfire JSON report to parse.")
    
    parser.add_argument('-i', '--indicators', action='store_true', dest='indicators',
        required=False, default=None,
        help="Prints out the potential CRITS indicators from the report.")
    
    parser.add_argument('-c', '--config-path', action='store', dest='config_path',
        required=False, default="/opt/integralutils/etc/config.ini",
        help="Path of the config file to use for the sandbox parsers.")
        
    args = parser.parse_args()

    if os.path.exists(args.report_path):
        if os.path.exists(args.config_path):
            config_path = args.config_path
        else:
            config_path = None

        report = None
        try:
            report = CuckooParser.CuckooParser(args.report_path, screenshot=False, config_path=config_path)
        except ValueError:
            pass
        
        try:
            report = VxstreamParser.VxstreamParser(args.report_path, screenshot=False, config_path=config_path)
        except ValueError:
            pass
        
        try:
            report = WildfireParser.WildfireParser(args.report_path, config_path=config_path)
        except ValueError:
            pass
        
        
        if report:
            if args.indicators:
                for ioc in report.iocs:
                    print(ioc.type + ": " + ioc.indicator)
                    print("Tags: " + ",".join(ioc.tags))
                    print()
            else:
                print("=======================")
                print("==                   ==")
                print("==  SANDBOX SUMMARY  ==")
                print("==                   ==")
                print("=======================")
                print("Filename: " + report.filename)
                print("MD5: " + report.md5)
                print("SHA1: " + report.sha1)
                print("SHA256: " + report.sha256)
                print("SHA512: " + report.sha512)
                print("SSDEEP: " + report.ssdeep)
                print("Malware Family: " + report.malware_family)
                print("URL: " + report.sandbox_url)
                print("VM: " + report.sandbox_vm_name)

                if report.sha256:
                    print("VT: " + "https://virustotal.com/en/file/" + report.sha256 + "/analysis/")
                print()

                if report.all_urls:
                    print("============")
                    print("==        ==")
                    print("==  URLS  ==")
                    print("==        ==")
                    print("============")
                    for url in report.all_urls:
                        print(url)
                    print()

                if report.dropped_files:
                    print("=====================")
                    print("==                 ==")
                    print("==  DROPPED FILES  ==")
                    print("==                 ==")
                    print("=====================")
                    for file in report.dropped_files:
                        print("Filename: " + file.filename)
                        print("Path: " + file.path)
                        print("Size: " + file.size)
                        print("Type: " + file.type)
                        print("MD5: " + file.md5)
                        print("SHA256: " + file.sha256)

                        if file.sha256:
                            print("VT: " + "https://virustotal.com/en/file/" + file.sha256 + "/analysis/")
                        print()

                if report.dns_requests:
                    print("====================")
                    print("==                ==")
                    print("==  DNS REQUESTS  ==")
                    print("==                ==")
                    print("====================")
                    for request in report.dns_requests:
                        print("Request: " + request.request)
                        print("Type: " + request.type)
                        print("Answer: " + request.answer)
                        print("Answer Type: " + request.answer_type)
                        print()

                if report.http_requests:
                    print("=====================")
                    print("==                 ==")
                    print("==  HTTP REQUESTS  ==")
                    print("==                 ==")
                    print("=====================")
                    for request in report.http_requests:
                        print("Request: " + "http://" + request.host + request.uri)
                        print("Method: " + request.method)
                        print("Port: " + request.port)
                        print("User-Agent: " + request.user_agent)
                        print()

                if report.contacted_hosts:
                    print("=======================")
                    print("==                   ==")
                    print("==  CONTACTED HOSTS  ==")
                    print("==                   ==")
                    print("=======================")
                    for host in report.contacted_hosts:
                        print("IP: " + host.ipv4)
                        print("Location: " + host.location)
                        print("Associated Domains: " + str(host.associated_domains))
                        print()

                if report.mutexes:
                    print("===============")
                    print("==           ==")
                    print("==  MUTEXES  ==")
                    print("==           ==")
                    print("===============")
                    for mutex in report.mutexes:
                        print(mutex)
                    print()

                if report.process_tree:
                    print("====================")
                    print("==                ==")
                    print("==  PROCESS TREE  ==")
                    print("==                ==")
                    print("====================")
                    print(str(report.process_tree))

if __name__ == "__main__":
    main()
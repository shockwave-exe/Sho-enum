# -*- coding: utf-8 -*-
#!/usr/bin/env python
import shodan
import re
import socket
import os, sys
import requests # PUT IN REQUIREMENTS !!!!!!!!
import urllib
import dns.resolver # PUT IN REQUIREMENTS !!!!!!!!
from time import sleep
import argparse
from ipaddress import ip_address
import struct
from functools import reduce
import urllib.request, json 

api_key = ''  # <-------- HARCODED API KEY HERE --------<     
hostnames3 = ''
puertosLimpios3 = ''
cveLimpio3 = ''
product = ''
parser = argparse.ArgumentParser(description='This script intend to obtain host information with Shodan using passive reconnaisance')
parser.add_argument('-t','--target', help="Indicate ip/domain/range to process \n\n",required=False)
parser.add_argument('-f','--file', help='To read files or domains from the file\n\n', required=False)
parser.add_argument('-s','--silent', help="Dont show nothing in screen \n\n",required=False, action='store_true')
parser.add_argument('-a','--api', help="Set a custom Shodan API key - NEEDED ONCE FOR SET!!! \n\n",required=False)
args = parser.parse_args()

if args.api is not None:
    api_key = args.api
    if not os.path.exists("API.txt"):
        archive_api = open("API.txt","w+")
        archive_api.write(args.api)
        api_key = (archive_api.readline())[0:32]
        print('Shodan API Key stored !!!')
if api_key == '':
    try:
        if os.path.exists("API.txt"):
            archive_api = open('API.txt', 'r')
            api_key = (archive_api.readline())[0:32]
        else:
            print('Cant found API.txt file, please create "API.txt" with a valid Shodan API Key inside or use -a argument')
            print(' use -a argument for once and your API key will be stored in API.txt folder')
            sys.exit(1)
    except Exception as e:
        pass
api = shodan.Shodan(api_key)  
def formatParams (results):
    global hostnames3
    global puertosLimpios3
    global cveLimpio3

    hostnames1 =  str(results.get('hostnames')).replace("', '", " | ")
    hostnames2 =  hostnames1.replace("['", "")
    hostnames3 =  hostnames2.replace("']", "")
    puertosLimpios =  str(results['ports']).replace("[", "")
    puertosLimpios2 =  str(puertosLimpios).replace("]", "")
    puertosLimpios3 =  str(puertosLimpios2).replace(",", " |")
    cveLimpio =  str(results.get('vulns')).replace("', '", " | ")
    cveLimpio2 =  cveLimpio.replace("['", "")
    cveLimpio3 =  cveLimpio2.replace("']", "")

def process (results):    
    formatParams (results)
    global hostnames3
    global puertosLimpios3
    global cveLimpio3
    global product
    global prodList
    if args.silent is False:
        print(' -------------------------------- ')
        print(' IP:           {}'.format(results['ip_str']))                       
        print(' Hostnames:    {}'.format(hostnames3))
        print(' ISP:          {}'.format(results['isp']))
        print(' ASN:          {}'.format(results['asn']))    
        
        try:
            location = '{} {} {} {}'.format(
            check(results['country_code3']),
            check(results['country_name']),
            check(results['city']),
            check(results['postal_code'])
            )
            print(' Location:     {}'.format(location))
        except Exception as e:
            pass
        
        print(' Ports:        {}'.format(puertosLimpios3))
        print(' CVEs:         {}'.format(cveLimpio3))
        print(' Updated:      {}'.format(results.get('last_update')[0:10]))
        print(' ---------------- ')
        prodList = ''
        first = 0
        for data in results['data']:
            puerto = data['port']
            
            print(' -*- Port:     ' + str(data['port']))
            print('     Protocol: ' + str(data['transport']))
            try:
                if str(data['os']) == "None":
                    data['os'] = "N/A"
                else:
                    print('     OS:       ' + str(data['os']))
            
            except Exception as e:
                continue
            try:
                print('     Product:  ' + str(data['product']))
                prod = str(data['product'])
                if not prodList:
                   prodList = prod
                    
                elif prod not in prodList:
                    prodList = prodList + ', ' + prod
            
            except Exception as e:
                data['product'] = "N/A"
                continue
            try:
                print('     Version:  ' + str(data['version']))
                prodVer = product + ', ' + str(data['product']) + '(' + str(data['version']) + ')'
                if prodVer not in prodList:
                    prodList = prodList + '' + prodVer
                
            except Exception as e:
                data['version'] = "N/A"
                continue

        if not prodList:
            pass
        else:
            print('\n' + ' Detected products:  {}'.format(prodList))
    print('\n')

def check(param):
    if param==None:
        return ''
    else:
        return param

       
if api_key == '':
    print(' Shodan API key not defined, edit the script or use (-a) option.')
    sys.exit(1)
else:
    try:
        if args.target is not None: 
            cleanParam = args.target
            if 'http://' in cleanParam:
                cleanParam =  cleanParam.replace("http://", "")
                cleanParam =  socket.gethostbyname(cleanParam)
            if 'https://' in cleanParam:
                args.target =  args.target.replace("https://", "")
                args.target =  socket.gethostbyname(cleanParam)
            
            if 'www.' in cleanParam:
                cleanParam =  cleanParam.replace("www.", "")
                cleanParam =  socket.gethostbyname(cleanParam)
            args.target = cleanParam
            if '/' in args.target:
                with urllib.request.urlopen('https://api.shodan.io/shodan/host/search?key=' + api_key + '&query=net:' + args.target) as url:
                    data = json.loads(url.read().decode())
                    
                    total_ip = data.get('total')
                    print(' Processing range {} - {} IPs found on Shodan'.format(args.target, total_ip))
                    results = data.get('matches')
                    
                    for info in results:
                        if 'ip_str' in info:
                            ip = info.get('ip_str')
                            try:
                                #ipv4 = socket.gethostbyname(ip)
                                ipv4 = ip
                                results = api.host(ipv4)
                                process(results)
                                sleep(1)
                                 
                            except Exception as e:
                                print(' Warning: {} {}'.format(ip, e))
                                sleep(1)
            else:
                print(' Processing IP / Host: ' + args.target)
                try:
                    ipv4 = socket.gethostbyname(args.target)
                    results = api.host(ipv4)
                    process(results)
                      
                except Exception as e:
                    print(' Warning: {} {}'.format(args.target, e))
        elif args.file is not None:
            print(' Processing file: ' + str(args.file))
            with open(args.file, 'r') as file:
                for line in file.readlines():   
                    line_ip = line.split('\n')[0]
                    if 'http://' in line_ip:
                        line_ip =  line_ip.replace("http://", "")
                        line_ip =  socket.gethostbyname(line_ip)
                    if 'https://' in line_ip:
                        line_ip =  line_ip.replace("https://", "")
                        line_ip =  socket.gethostbyname(line_ip)
                    
                    if 'www.' in line_ip:
                        line_ip =  line_ip.replace("www.", "")
                        line_ip =  socket.gethostbyname(line_ip)
                    if '/' in line_ip:
                        with urllib.request.urlopen('https://api.shodan.io/shodan/host/search?key=' + api_key + '&query=net:' + line_ip) as url:
                            data = json.loads(url.read().decode())
                            
                            total_ip = data.get('total')
                            print(' Processing range {} - {} IPs found on Shodan'.format(line_ip, total_ip))
                            results = data.get('matches')
                            
                            for info in results:
                                if 'ip_str' in info:
                                    ip = info.get('ip_str')
                                    try:
                                        ipv4 = socket.gethostbyname(ip)
                                        results = api.host(ipv4)
                                        process(results)
                                        sleep(1)
                                          
                                    except Exception as e:
                                        print('Warning: {} - {}'.format(ipv4, e))
                                        sleep(1)
                            print(' Range processed, continuing... ')
                    else:
                        
                        try:
                            ipv4 = socket.gethostbyname(line_ip)
                            results = api.host(ipv4)
                            process(results)
                            sleep(1)
                            
                        except Exception as e:
                            print(' Warning: {} {}'.format(ipv4, e))
                            sleep(1)               
                                    
        else:
            print(' Warning: Need indicate ip/domain/range or file to process, use -h for help')
            sys.exit(1)
    
        print(' --- The execution has been completed --- ')
    except Exception as e:
        print(' Fatal Error: {}'.format(e))
        sys.exit(1)
    
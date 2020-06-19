import requests
import sys
from bs4 import BeautifulSoup as bs 
import os
from termcolor import cprint
import socket
import json

#headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
headers = {'User-Agent':'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'}
domain = sys.argv[1]


def subdom(domain):
    cprint("*****************",'red',attrs=['bold'])
    cprint("[+]Checking for alive subdomains of: {}".format(domain),'green',attrs=['bold'])
    cprint("*****************",'red',attrs=['bold'])
    url = 'https://rapiddns.io/subdomain/'
    u = url + domain 
    r = requests.get(u,headers=headers)
    if r.status_code == 200:
        html = bs(r.text,'html.parser')
        total = html.find("div",{"style":"margin: 0 8px;"}).get_text().strip().strip(':')
        print(total+'\n')
        tot = total.split(':')
        tot = int(tot[1][1:])
        table_list = html.find("table",{"class":"table table-striped table-bordered"})
        list_data = table_list.tbody.find_all("tr")
        for list in list_data:
            dom = list.find_all("td")
            arr=[]
            for i in dom:
                arr.append(i.text)
            print(arr[0])
        if tot > 34:
            print("\nFind more subdomain at: " + u)


def whois(domain):
    cprint("*****************",'red',attrs=['bold'])
    cprint("[+]Whois data of {}".format(domain),'green',attrs=['bold'])
    cprint("*****************",'red',attrs=['bold'])
    url = 'https://www.whois.com/whois/'
    path = domain
    r = requests.get(url+path,headers=headers)
    if r.status_code == 200:
        html = bs(r.text, 'html.parser')
        for p in html.select('pre'):
            if p['id'] == 'registryData' or p['id'] == 'registrarData':
                print(p.text)
                with open('whois'+domain+'.txt','w') as who:
                    who.write(p.text)    
                who.close()

def reversewhois(domain):
    cprint("*****************",'red',attrs=['bold'])
    cprint("[+]Reversewhois data of Registrant Organization of {}".format(domain),'green',attrs=['bold'])
    cprint("*****************",'red',attrs=['bold'])
    with open('whois'+domain+'.txt','r') as who:
        lines = who.readlines()
        for line in lines:
            if 'Registrant Organization:' in line:
                t = line.split(':')
                print(line)
                path = t[1][1:-1]
            else:
                path = None
    if path != None:
        url = 'https://viewdns.info/reversewhois/'
        payload = {'q':path}
        r = requests.get(url,headers=headers,params=payload)
        if r.status_code == 200:
            html = bs(r.text,'html.parser')
            table = html.find("table",{"border":"1"})
            table_data = table.find_all("tr")
            for i in table_data:
                dom = i.find_all("td")
                arr = []
                for j in dom:
                    arr.append(j.text)
                print(arr[0])
    else:
        print("Could'nt find any data on reversewhois of the "+domain+". No registrant found!!!")
    who.close()
    os.remove('whois'+domain+'.txt')

def reverseip(domain):
    cprint("*****************",'red',attrs=['bold'])
    cprint("[+]Other domains hosted on the same server as {}".format(domain),'green',attrs=['bold'])
    cprint("*****************",'red',attrs=['bold'])
    url = 'https://viewdns.info/reverseip/'
    payload = {'host':domain,'t':1}
    r = requests.get(url,headers=headers,params=payload)
    print(r.status_code)

def iphistory(domain):
    cprint("*****************",'red',attrs=['bold'])
    cprint("[+]IP history of {}".format(domain),'green',attrs=['bold'])
    cprint("*****************",'red',attrs=['bold'])
    url = 'https://viewdns.info/iphistory/'
    payload = {'domain':domain}
    r = requests.get(url,headers=headers,params=payload)
    if r.status_code == 200:
        html = bs(r.text,'html.parser')
        table = html.find("table",{"border":"1"})
        table_data = table.find_all("tr")
        for i in table_data:
            dom = i.find_all("td")
            arr = []
            for j in dom:
                arr.append(j.text)
            print(arr[0])

def iplocation(domain):
    cprint("*****************",'red',attrs=['bold'])
    cprint("[+]IP location of server of {}".format(domain),'green',attrs=['bold'])
    cprint("*****************",'red',attrs=['bold'])
    ip = socket.gethostbyname(domain)
    url = 'https://geolocation-db.com/json/'
    r = requests.get(url+ip,headers=headers)
    json_data = json.loads(r.text)
    print('IP ----> '+ str(ip))
    if json_data['country_name'] != None:
        print('Country: ' + json_data['country_name'])
    else:
        print('Country: ')
    if json_data['city'] != None:
        print('City: ' + json_data['city'])
    else:
        print('City: ')
    if json_data['latitude'] != None:
        print('Latitude: ' + str(json_data['latitude']))
    else:
        print('Latitude: ')
    if json_data['longitude'] != None:
        print('Longitude: ' + str(json_data['longitude']))
    if json_data['state'] != None:
        print('State: ' + json_data['state'])
    else:
        print('State: ')

if __name__ == '__main__':
    whois(domain)
    print('\n')
    subdom(domain)
    print('\n')
    reversewhois(domain)
    print('\n')
    iphistory(domain)
    print('\n')
    iplocation(domain)
    print('\n')

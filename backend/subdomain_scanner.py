#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
وحدة فحص النطاقات الفرعية - مسؤولة عن جمع وفحص النطاقات الفرعية
"""

import subprocess
import concurrent.futures
import socket
import ssl
import requests
from functools import lru_cache
from utils import Colors, EMOJI

@lru_cache(maxsize=100)
def run_subfinder(domain):
    """جمع النطاقات الفرعية باستخدام Subfinder مع التخزين المؤقت"""
    print("\n" + EMOJI['search'] + " " + Colors.BLUE + "جمع النطاقات الفرعية لـ " + domain + "..." + Colors.END)
    
    try:
        command = "subfinder -d " + domain + " -silent -all"
        result = subprocess.run(command, shell=True, check=True, 
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                              text=True, timeout=300)
        return list(set(result.stdout.splitlines()))
    except subprocess.TimeoutExpired:
        print(EMOJI['fail'] + " " + Colors.RED + "انتهى الوقت المحدد لجمع النطاقات الفرعية" + Colors.END)
        return []
    except Exception as e:
        print(EMOJI['fail'] + " " + Colors.RED + "خطأ في Subfinder: " + str(e) + Colors.END)
        return []

def check_subdomain_status(subdomain):
    """فحص حالة النطاق الفرعي مع إدارة أفضل للأخطاء"""
    result = {
        'subdomain': subdomain,
        'dns': False,
        'http': False,
        'https': False,
        'ssl_valid': False,
        'ssl_expiry': None
    }
    
    # فحص DNS مع زيادة الوقت المخصص
    try:
        socket.setdefaulttimeout(5)
        socket.gethostbyname(subdomain)
        result['dns'] = True
    except:
        return result
    
    # فحص HTTP/HTTPS مع تحسين معالجة الأخطاء
    for protocol in ['http', 'https']:
        try:
            response = requests.get(
                protocol + "://" + subdomain,
                timeout=5,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            result[protocol] = response.status_code < 400
        except:
            result[protocol] = False
    
    # فحص SSL مع إعدادات أكثر مرونة
    if result['https']:
        try:
            ctx = ssl.create_default_context()
            ctx.set_ciphers('DEFAULT@SECLEVEL=1')
            with socket.create_connection((subdomain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=subdomain) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        from datetime import datetime
                        expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        result['ssl_valid'] = expiry > datetime.now()
                        result['ssl_expiry'] = expiry
        except:
            pass
    
    return result

def check_subdomains_parallel(subdomains, max_workers=15):
    """فحص النطاقات الفرعية بشكل متوازي مع تحسين الأداء"""
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_subdomain_status, sd): sd for sd in subdomains}
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                print(EMOJI['warning'] + " " + Colors.YELLOW + "خطأ في فحص " + futures[future] + ": " + str(e) + Colors.END)
    return results

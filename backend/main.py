#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
أداة مسح ضوئي لفحص الثغرات في النطاقات - الإصدار النهائي


"""

import subprocess
import concurrent.futures
import socket
import ssl
import requests
import dns.resolver
import os
from datetime import datetime
import time
from functools import lru_cache

# ألوان للعرض في الطرفية
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# إموجيات للعرض
EMOJI = {
    'ok': '✅',
    'fail': '❌',
    'info': 'ℹ️',
    'search': '🔍',
    'clock': '⏱️',
    'warning': '⚠️',
    'globe': '🌐',
    'lock': '🔒',
    'unlock': '🔓',
    'dns': '📡',
    'whois': '📋'
}

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

def run_nmap_scan(domain):
    """إجراء فحص داخلي للشبكة باستخدام nmap للنطاق الأساسي"""
    print("\n" + EMOJI['search'] + " " + Colors.BLUE + "جاري إجراء الفحص الداخلي للشبكة لـ " + domain + "..." + Colors.END)
    
    try:
        # الحصول على معلومات IP للنطاق
        ip_address = socket.gethostbyname(domain)
        print("\n" + EMOJI['info'] + " " + Colors.PURPLE + "معلومات IP:" + Colors.END)
        print(Colors.CYAN + "عنوان IP: " + ip_address + Colors.END)
        
        # فحص المنافذ الشائعة
        print("\n" + EMOJI['search'] + " " + Colors.BLUE + "جاري فحص المنافذ..." + Colors.END)
        port_command = "nmap -T4 -F " + domain
        port_result = subprocess.run(port_command, shell=True, check=True, 
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                 text=True, timeout=180)
        
        print("\n" + EMOJI['info'] + " " + Colors.PURPLE + "نتائج فحص المنافذ:" + Colors.END)
        print(Colors.CYAN + port_result.stdout + Colors.END)
        
        return {
            "ip": ip_address,
            "ports": port_result.stdout
        }
    except socket.gaierror:
        print(EMOJI['fail'] + " " + Colors.RED + "فشل في الحصول على عنوان IP للنطاق " + domain + Colors.END)
        return None
    except subprocess.TimeoutExpired:
        print(EMOJI['fail'] + " " + Colors.RED + "انتهى الوقت المحدد للفحص الداخلي للشبكة" + Colors.END)
        return None
    except Exception as e:
        print(EMOJI['fail'] + " " + Colors.RED + "خطأ في الفحص الداخلي للشبكة: " + str(e) + Colors.END)
        return None

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

def display_whois(data, source):
    """عرض معلومات WHOIS بشكل منظم"""
    print("\n" + EMOJI['info'] + " " + Colors.PURPLE + "معلومات WHOIS (مصدر: " + source + "):" + Colors.END)
    
    fields = {
        'domain_name': ['📌 النطاق', 'text'],
        'registrar': ['🏢 المسجل', 'text'],
        'creation_date': ['📅 تاريخ الإنشاء', 'date'],
        'expiration_date': ['⌛ تاريخ الانتهاء', 'date'],
        'updated_date': ['🔄 آخر تحديث', 'date'],
        'name_servers': ['🔧 خوادم الأسماء', 'list'],
        'status': ['🔄 الحالة', 'list'],
        'emails': ['📧 البريد الإلكتروني', 'list']
    }
    
    for field, (display, field_type) in fields.items():
        value = data.get(field)
        if value:
            if field_type == 'date':
                if isinstance(value, list):
                    value = value[0]
                if isinstance(value, str):
                    print(display + ": " + value)
                else:
                    print(display + ": " + value.strftime('%Y-%m-%d'))
            elif field_type == 'list':
                if isinstance(value, (list, set)):
                    print(display + ": " + ', '.join(value))
                else:
                    print(display + ": " + value)
            else:
                print(display + ": " + value)

def get_whois_info(domain):
    """الحصول على معلومات WHOIS باستخدام API وطرق بديلة"""
    print("\n" + EMOJI['whois'] + " " + Colors.BLUE + "جمع معلومات WHOIS..." + Colors.END)
    
    # المحاولة الأولى: whois عبر النظام
    try:
        result = os.popen("whois " + domain).read()
        if "Domain Name:" in result or "domain:" in result.lower():
            print("\n" + EMOJI['info'] + " " + Colors.PURPLE + "معلومات WHOIS (مصدر: نظام):" + Colors.END)
            print(result[:1000])  # عرض أول 1000 حرف فقط
            return
    except Exception as e:
        print(EMOJI['warning'] + " " + Colors.YELLOW + "فشل في استخدام whois النظامي: " + str(e) + Colors.END)
    
    # المحاولة الثانية: API مجاني
    try:
        api_url = "https://api.whoisfreaks.com/v1.0/whois?domain=" + domain
        response = requests.get(api_url, timeout=10)
        if response.status_code == 200:
            display_whois(response.json(), 'api')
            return
    except Exception as e:
        print(EMOJI['warning'] + " " + Colors.YELLOW + "فشل الاتصال بالAPI: " + str(e) + Colors.END)
    
    # الخيار الأخير: رابط يدوي
    print(EMOJI['info'] + " " + Colors.CYAN + "راجع المعلومات يدوياً: " + Colors.UNDERLINE + "https://who.is/whois/" + domain + Colors.END)

def get_dns_records(domain):
    """الحصول على سجلات DNS مع تحسين معالجة الأخطاء"""
    print("\n" + EMOJI['dns'] + " " + Colors.BLUE + "جمع سجلات DNS..." + Colors.END)
    
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    
    print("\n" + EMOJI['info'] + " " + Colors.PURPLE + "سجلات DNS:" + Colors.END)
    
    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            print("\n" + rtype + " Records:")
            for rdata in answers:
                print("  - " + rdata.to_text())
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            print(EMOJI['fail'] + " " + Colors.RED + "النطاق غير موجود" + Colors.END)
            break
        except Exception as e:
            print(EMOJI['warning'] + " " + Colors.YELLOW + "خطأ في سجل " + rtype + ": " + str(e) + Colors.END)

def main():
    """الوظيفة الرئيسية مع تحسينات واجهة المستخدم"""
    # عرض شعار التطبيق
    print(Colors.CYAN + '''
 =========================================================================
                          DOMAIN VULN SCANNER
 =========================================================================
''' + Colors.END)
    print(Colors.BOLD + Colors.GREEN + "Domain Vuln Scanner" + Colors.END)
    separator = "=" * 50
    print(Colors.YELLOW + separator + Colors.END)
    
    target_domain = input("\n" + EMOJI['globe'] + " " + Colors.YELLOW + "أدخل النطاق المستهدف: " + Colors.END)
    target_domain = target_domain.strip().lower()
    
    if not target_domain:
        print(EMOJI['fail'] + " " + Colors.RED + "النطاق مطلوب" + Colors.END)
        return
    
    start_time = time.time()
    print("\n" + EMOJI['clock'] + " " + Colors.GREEN + "بدأ الفحص في " + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + Colors.END)
    
    # تنظيف عنوان النطاق
    domain = target_domain.replace('http://', '').replace('https://', '').split('/')[0]
    
    # فحص داخلي للشبكة باستخدام nmap للنطاق الأساسي
    run_nmap_scan(domain)
    
    # جمع النطاقات الفرعية أولاً
    print("\n" + EMOJI['search'] + " " + Colors.BLUE + "جاري جمع النطاقات الفرعية لـ " + domain + "..." + Colors.END)
    subdomains = run_subfinder(domain)
    
    if subdomains:
        print("\n" + EMOJI['info'] + " " + Colors.GREEN + "تم العثور على " + str(len(subdomains)) + " نطاق فرعي:" + Colors.END)
        
        # عرض جميع النطاقات الفرعية أولاً
        for i, subdomain in enumerate(subdomains, 1):
            print("  " + str(i) + ". " + Colors.CYAN + subdomain + Colors.END)
        
        # سؤال المستخدم عما إذا كان يريد فحص حالة هذه النطاقات الفرعية
        check_status = input("\n" + EMOJI['search'] + " " + Colors.YELLOW + "هل ترغب في فحص حالة هذه النطاقات الفرعية؟ (y/n): " + Colors.END).strip().lower()
        
        if check_status in ['y', 'yes', 'نعم']:
            # فحص حالة النطاقات الفرعية
            print("\n" + EMOJI['search'] + " " + Colors.BLUE + "جاري فحص حالة النطاقات الفرعية..." + Colors.END)
            results = check_subdomains_parallel(subdomains)
            
            # عرض النتائج
            print("\n" + EMOJI['info'] + " " + Colors.PURPLE + "نتائج فحص حالة النطاقات الفرعية:" + Colors.END)
            for result in results:
                if result['dns']:
                    status = EMOJI['ok'] if result['http'] or result['https'] else EMOJI['fail']
                    protocols = []
                    if result['http']: protocols.append(Colors.GREEN + "HTTP" + Colors.END)
                    if result['https']: 
                        ssl_status = Colors.GREEN + "✓" + Colors.END if result['ssl_valid'] else Colors.RED + "✗" + Colors.END
                        protocols.append(Colors.GREEN + "HTTPS" + Colors.END + " [SSL: " + ssl_status + "]")
                    
                    print(status + " " + result['subdomain'] + " - " + ' '.join(protocols))
        else:
            print(EMOJI['info'] + " " + Colors.CYAN + "تم تخطي فحص حالة النطاقات الفرعية" + Colors.END)
    else:
        print(EMOJI['warning'] + " " + Colors.YELLOW + "لم يتم العثور على نطاقات فرعية" + Colors.END)
    
    # جمع سجلات DNS
    get_dns_records(domain)
    
    # معلومات WHOIS
    get_whois_info(domain)
    
    elapsed_time = time.time() - start_time
    print("\n" + EMOJI['clock'] + " " + Colors.GREEN + "اكتمل الفحص في " + str(elapsed_time) + " ثانية" + Colors.END)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + EMOJI['fail'] + " " + Colors.RED + "تم إيقاف البرنامج بواسطة المستخدم" + Colors.END)
    except Exception as e:
        print("\n" + EMOJI['fail'] + " " + Colors.RED + "خطأ غير متوقع: " + str(e) + Colors.END)

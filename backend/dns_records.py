#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
وحدة سجلات DNS - مسؤولة عن جمع وعرض سجلات DNS للنطاق
"""

import dns.resolver
from utils import Colors, EMOJI

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

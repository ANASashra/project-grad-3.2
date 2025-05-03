#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
وحدة معلومات WHOIS - مسؤولة عن جمع وعرض معلومات WHOIS للنطاق
"""

import os
import requests
from utils import Colors, EMOJI

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

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
وحدة فحص الشبكة - مسؤولة عن إجراء الفحص الداخلي للشبكة باستخدام nmap
"""

import subprocess
import socket
from utils import Colors, EMOJI

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

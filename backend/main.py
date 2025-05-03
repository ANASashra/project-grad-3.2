#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
أداة مسح ضوئي لفحص الثغرات في النطاقات - الإصدار النهائي
تم إعادة هيكلته ليستخدم وحدات منفصلة لكل وظيفة
"""

import time
from datetime import datetime

# استيراد الوحدات المنفصلة
from utils import Colors, EMOJI, print_banner
from network_scan import run_nmap_scan
from subdomain_scanner import run_subfinder, check_subdomains_parallel
from dns_records import get_dns_records
from whois_info import get_whois_info
from vulnerability_scanner import smart_vuln_scan, get_user_mode, check_nuclei_template_paths

def main():
    """واجهة تفاعلية موحدة لكل الوظائف"""
    print_banner()
    target_domain = input("\n" + EMOJI['globe'] + " " + Colors.YELLOW + "أدخل النطاق المستهدف: " + Colors.END).strip().lower()
    if not target_domain:
        print(EMOJI['fail'] + " " + Colors.RED + "النطاق مطلوب" + Colors.END)
        return
    domain = target_domain.replace('http://', '').replace('https://', '').split('/')[0]
    subdomains = []
    start_time = time.time()
    while True:
        print("\n" + Colors.BOLD + Colors.BLUE + "اختر العملية التي تريد تنفيذها:" + Colors.END)
        print(" 1. فحص الشبكة الداخلية (nmap)")
        print(" 2. جمع النطاقات الفرعية (subfinder)")
        print(" 3. فحص حالة النطاقات الفرعية (HTTP/HTTPS/SSL)")
        print(" 4. جمع سجلات DNS")
        print(" 5. معلومات WHOIS")
        print(" 6. التحقق من مسارات قوالب Nuclei")
        print(" 7. الفحص الأمني الذكي (Nuclei/XSStrike/SQLmap/Nikto/WPScan)")
        print(" 0. خروج")
        choice = input("\nأدخل رقم الخيار: ").strip()
        if choice == '1':
            run_nmap_scan(domain)
        elif choice == '2':
            subdomains = run_subfinder(domain)
            if subdomains:
                print("\n" + EMOJI['info'] + " " + Colors.GREEN + f"تم العثور على {len(subdomains)} نطاق فرعي:" + Colors.END)
                for i, sub in enumerate(subdomains, 1):
                    print(f"  {i}. {Colors.CYAN}{sub}{Colors.END}")
            else:
                print(EMOJI['warning'] + " " + Colors.YELLOW + "لم يتم العثور على نطاقات فرعية" + Colors.END)
        elif choice == '3':
            if not subdomains:
                print(EMOJI['fail'] + Colors.RED + " يجب جمع النطاقات الفرعية أولاً!" + Colors.END)
            else:
                results = check_subdomains_parallel(subdomains)
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
        elif choice == '4':
            get_dns_records(domain)
        elif choice == '5':
            get_whois_info(domain)
        elif choice == '6':
            check_nuclei_template_paths()
        elif choice == '7':
            is_wp = input("هل الموقع WordPress؟ (y/n): ").strip().lower() in ['y', 'yes', 'نعم']
            fast_mode = get_user_mode()
            smart_vuln_scan(target_domain, is_wordpress=is_wp, fast_mode=fast_mode)
        elif choice == '0':
            break
        else:
            print(EMOJI['fail'] + Colors.RED + " خيار غير صحيح!" + Colors.END)
    elapsed_time = time.time() - start_time
    print("\n" + EMOJI['clock'] + " " + Colors.GREEN + "اكتمل الفحص في " + str(int(elapsed_time)) + " ثانية" + Colors.END)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + EMOJI['fail'] + " " + Colors.RED + "تم إيقاف البرنامج بواسطة المستخدم" + Colors.END)
    except Exception as e:
        print("\n" + EMOJI['fail'] + " " + Colors.RED + "خطأ غير متوقع: " + str(e) + Colors.END)

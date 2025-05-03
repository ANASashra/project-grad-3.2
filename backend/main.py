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
from vulnerability_scanner import run_nuclei_scan, run_xsstrike_scan, run_sqlmap_scan, run_nikto_scan, run_wpscan, get_user_mode, check_nuclei_template_paths

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
        print(" 1. فحص الشبكة الداخلية ")
        print(" 2. جمع النطاقات الفرعية ")
        print(" 3. فحص حالة النطاقات الفرعية (HTTP/HTTPS/SSL)")
        print(" 4. جمع سجلات DNS")
        print(" 5. معلومات WHOIS")
        print(" 6. فحص ثغرات Nuclei")
        print(" 7. فحص XSS  ")
        print(" 8. فحص SQLi  ")
        print(" 9. فحص Nikto")
        print("10. فحص WordPress  ")
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
            while True:
                print("\nخيارات فحص Nuclei:")
                print(" 1. فحص جميع الثغرات (شامل)")
                print(" 2. فحص XSS فقط (سريع)")
                print(" 3. فحص SQLi فقط (سريع)")
                print(" 4. فحص LFI فقط (سريع)")
                print(" 5. فحص RCE فقط (سريع)")
                print(" 6. فحص حسب شدة معينة")
                print(" 0. رجوع")
                nuclei_choice = input("\nأدخل رقم خيار فحص Nuclei: ").strip()
                if nuclei_choice == '1':
                    run_nuclei_scan(target_domain, mode='all')
                elif nuclei_choice == '2':
                    run_nuclei_scan(target_domain, mode='xss')
                elif nuclei_choice == '3':
                    run_nuclei_scan(target_domain, mode='sqli')
                elif nuclei_choice == '4':
                    run_nuclei_scan(target_domain, mode='lfi')
                elif nuclei_choice == '5':
                    run_nuclei_scan(target_domain, mode='rce')
                elif nuclei_choice == '6':
                    sev = input("أدخل الشدة المطلوبة (low,medium,high,critical): ").strip()
                    run_nuclei_scan(target_domain, mode='severity', severity=sev)
                elif nuclei_choice == '0':
                    break
                else:
                    print(EMOJI['warning'] + " خيار غير صحيح!" + Colors.END)

        elif choice == '7':
            run_xsstrike_scan(target_domain)
        elif choice == '8':
            run_sqlmap_scan(target_domain)
        elif choice == '9':
            run_nikto_scan(target_domain)
        elif choice == '10':
            run_wpscan(target_domain)
        elif choice == '0':
            break
        else:
            print(EMOJI['fail'] + Colors.RED + " خيار غير صحيح!" + Colors.END)
    elapsed_time = time.time() - start_time
    if elapsed_time >= 60:
        mins = int(elapsed_time // 60)
        secs = int(elapsed_time % 60)
        print("\n" + EMOJI['clock'] + " " + Colors.GREEN + f"اكتمل الفحص في {mins} دقيقة" + (f" و {secs} ثانية" if secs else "") + Colors.END)
    else:
        print("\n" + EMOJI['clock'] + " " + Colors.GREEN + f"اكتمل الفحص في {int(elapsed_time)} ثانية" + Colors.END)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + EMOJI['fail'] + " " + Colors.RED + "تم إيقاف البرنامج بواسطة المستخدم" + Colors.END)
    except Exception as e:
        print("\n" + EMOJI['fail'] + " " + Colors.RED + "خطأ غير متوقع: " + str(e) + Colors.END)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
وحدة المساعدة - تحتوي على الأدوات المساعدة مثل الألوان والرموز التعبيرية
"""

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
    'danger': '🚨',
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

def print_banner():
    """عرض شعار التطبيق"""
    print(Colors.CYAN + '''
 =========================================================================
                          DOMAIN VULN SCANNER
 =========================================================================
''' + Colors.END)
    print(Colors.BOLD + Colors.GREEN + "Domain Vuln Scanner" + Colors.END)
    separator = "=" * 50
    print(Colors.YELLOW + separator + Colors.END)

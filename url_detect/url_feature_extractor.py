#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Mar 29 22:28:38 2025
@author: jesus_delarosa_cyber
"""

import ipaddress
import re
import math
from collections import Counter
from urllib.parse import urlparse

def url_detect_feature_extract(url):
    """Extract security features from a single URL"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
    except:
        domain = path = query = None

    return {
        'havingIP': int(is_ip_address(domain) if domain else 0),
        'haveAtSign': int('@' in url),
        'getLength': int(len(url) >= 54),
        'getDepth': count_path_depth(path) if path else 0,
        'redirection': int(url.rfind('//') > 6),
        'httpDomain': int('https' in (domain or '')),
        'tinyURL': int(is_shortened(url)),
        'numDots': domain.count('.') if domain else 0,
        'numHyphens': domain.count('-') if domain else 0,
        'numSubdomains': count_subdomains(domain) if domain else 0,
        'hasPort': int(':' in (domain or '')),
        'pathLength': len(path) if path else 0,
        'numQueryParams': len(query.split('&')) if query else 0,
        'hasSensitiveKeywords': int(has_sensitive_keywords(url)),
        'numSpecialChars': len(re.findall(r'[^\w\s]', url)),
        'calculateEntropy': calculate_entropy(url),
        'hasTyposquatting': int(has_typosquatting(domain)) if domain else 0,
        'hasBrandName': int(has_brand_name(domain, path)) if domain else 0
    }

# Helper functions
def is_ip_address(domain):
    try:
        ipaddress.ip_address(domain)
        return True
    except:
        return False

def count_path_depth(path):
    return len([p for p in path.split('/') if p])

shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

def is_shortened(url):
    return bool(re.search(shortening_services, url))

def count_subdomains(domain):
    return domain.count('.') - 1 if domain and domain.count('.') > 1 else 0

def has_sensitive_keywords(url):
    keywords = ['login', 'bank', 'verify', 'secure', 'account', 'password',
                'update', 'confirm', 'validate', 'authenticate', 'payment',
                'billing', 'recovery', 'locked', 'hacked', 'reset']
    malicious_exts = ['exe','msi','bat','cmd','scr','jar','vbs','ps1',
                     'sh','dmg','app','pkg','iso','dll','js','hta','com',
                     'bin','sys','py','php']
    url_lower = url.lower()
    
    kw_check = any(re.search(r'\b{}(s|ing)?\b'.format(re.escape(kw)), url_lower) 
                for kw in keywords)
    ext_pattern = r'\.({})(\W|$)'.format('|'.join(map(re.escape, malicious_exts)))
    return kw_check or bool(re.search(ext_pattern, url_lower))

def calculate_entropy(text):
    try:
        p, lns = Counter(text), float(len(text))
        return -sum(count/lns * math.log(count/lns, 2) for count in p.values())
    except:
        return 0

def has_typosquatting(domain):
    """Advanced typo detection with mutation patterns"""
    if not domain:
        return 0

    brand_list = [
        'microsoft', 'google', 'apple', 'amazon', 'paypal', 'bankofamerica',
        'wellsfargo', 'chase', 'ebay', 'netflix', 'facebook', 'twitter',
        'instagram', 'linkedin', 'citibank', 'dropbox', 'adobe', 'spotify',
        'payoneer', 'westernunion', 'coinbase', 'binance', 'hsbc', 'barclays'
    ]

    mutation_patterns = [
        (r'[oO]', '0'), (r'[iIlL]', '1'), (r'[sS]', '5'), (r'[aA]', '4'),
        (r'[eE]', '3'), (r'[tT]', '7'), (r'[gG]', '9'), (r'[bB]', '8'),
        (r'\.', '-'), (r'\-', ''), (r'rn', 'm'), (r'vv', 'w'),
        (r'a', 'а'), (r'c', 'с'), (r'e', 'е'), (r'o', 'о'),
        (r'^secure-', ''), (r'-login$', ''), (r'\d{4}$', ''),
        (r'(..)', lambda m: m.group(1)[0] + m.group(1)[0]),
        (r'(?=.{7})(....)', r'\1-'), 
        (r'(\w)(\w)', r'\1.\2'),
    ]

    domain = domain.lower()
    
    for brand in brand_list:
        variants = {brand}
        for _ in range(2):
            for pattern, replacement in mutation_patterns:
                new_vars = set()
                for variant in variants:
                    mutated = re.sub(pattern, replacement, variant)
                    new_vars.add(mutated)
                    if 'а' in mutated or 'с' in mutated:
                        new_vars.add(mutated.replace('а','a').replace('с','c'))
                variants.update(new_vars)
        
        # Fixed variant generation
        for variant in list(variants):
            variants.update([
                f"{variant}{i}" for i in range(2015, 2024)
            ] + [
                f"secure-{variant}",
                f"{variant}-login",
                f"verify-{variant}"
            ])

        pattern = r'(?:^|\.|-)(' + '|'.join(map(re.escape, variants)) + r')(?:\.|-)'
        if re.search(pattern, domain):
            return 1
    return 0

def has_brand_name(domain, path):
    """Context-aware brand detection with 300+ brand patterns"""
    brand_matrix = {
    # Technology (15)
    'microsoft': {
        'aliases': ['azure', 'linkedin', 'github', 'xbox', 'activision','outlook'],
        'services': ['login', 'verify', 'security', 'update'],
        'safe_tlds': ['.com', '.net'],
        'suspicious_tlds': ['.tech', '.support', '.online', '.us', '-microsoft.com']
    },
    'google': {
        'aliases': ['youtube', 'android', 'fitbit', 'mandiant', 'looker'],
        'services': ['signin', 'recovery', '2fa', 'oauth'],
        'safe_tlds': ['.com', '.dev'],
        'suspicious_tlds': ['.account', '.pages', '.cloud', '-google.com']
    },
    'apple': {
        'aliases': ['icloud', 'appstore', 'findmy', 'applepay', 'beats'],
        'services': ['signin', 'id', 'support', 'verify'],
        'safe_tlds': ['.com', '.store'],
        'suspicious_tlds': ['.help', '.id', '.apple.com.secure']
    },
    'amazon': {
        'aliases': ['aws', 'prime', 'twitch', 'ring', 'zoox'],
        'services': ['verify', 'order', 'payment', 'credentials'],
        'safe_tlds': ['.com', '.co.uk', '.de', '.fr'],
        'suspicious_tlds': ['.shop', '.deals', 'amazon-', 'aws-']
    },
    'oracle': {
        'aliases': ['mysql', 'netsuite', 'cerner', 'peoplesoft'],
        'services': ['cloud', 'database', 'erp', 'login'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.db', '.erp', 'oracle-']
    },
    'ibm': {
        'aliases': ['watsonx', 'redhat', 'weather'],
        'services': ['portal', 'verify', 'license'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.ai', '.cloud', 'ibm-']
    },
    'intel': {
        'aliases': ['habana', 'mobileye', 'altera'],
        'services': ['driver', 'firmware', 'security'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.chip', 'intel-', '.gpu']
    },
    'cisco': {
        'aliases': ['webex', 'splunk', 'meraki', 'duo'],
        'services': ['vpn', 'login', 'security'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.vpn', 'cisco-', '.splunk']
    },
    'adobe': {
        'aliases': ['figma', 'pdf', 'substance', 'frame.io'],
        'services': ['signin', 'license', 'subscription'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.creative', 'adobe-', '.design']
    },
    'salesforce': {
        'aliases': ['slack', 'tableau', 'mulesoft', 'herocity'],
        'services': ['login', 'sandbox', 'org'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.crm', 'salesforce-', '.slack']
    },
    'dell': {
        'aliases': ['alienware', 'emc', 'pivotal'],
        'services': ['support', 'driver', 'warranty'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.pc', 'dell-', '.server']
    },
    'hp': {
        'aliases': ['hyperx', 'paloaltonetworks', 'pulse'],
        'services': ['support', 'firmware', 'cartridge'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.print', 'hp-', '.ink']
    },
    'nvidia': {
        'aliases': ['omniverse', 'dlss', 'arm'],
        'services': ['driver', 'update', 'account'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.gpu', 'nvidia-', '.ai']
    },
    'autodesk': {
        'aliases': ['constructioncloud', 'upchain', 'shotgrid'],
        'services': ['license', 'subscription', 'support'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.cad', 'autodesk-', '.3d']
    },
    'sony': {
        'aliases': ['playstation', 'crunchyroll', 'bsni'],
        'services': ['login', 'payment', 'subscription'],
        'safe_tlds': ['.com', '.jp'],
        'suspicious_tlds': ['.ps5', 'sony-', '.anime']
    },

    # Financial (10)
    'paypal': {
        'aliases': ['venmo', 'xoom', 'happyreturns'],
        'services': ['checkout', 'send', 'transfer'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.money', 'paypal-', '.venmo']
    },
    'visa': {
        'aliases': ['visadirect', 'cybersource', 'tink'],
        'services': ['payment', '3dsecure', 'authorize'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.card', 'visa-', '.pay']
    },
    'mastercard': {
        'aliases': ['nuvei', 'ethoca', 'brighterion'],
        'services': ['payment', 'authentication', 'secure'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.card', 'mastercard-', '.mc']
    },
    'coinbase': {
        'aliases': ['wallet', 'base', 'bison'],
        'services': ['verify', '2fa', 'recovery'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.crypto', 'coinbase-', '.nft']
    },
    'stripe': {
        'aliases': ['radar', 'taxjar', 'clicktopay'],
        'services': ['dashboard', 'api', 'payment'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.pay', 'stripe-', '.pos']
    },
    'square': {
        'aliases': ['cashapp', 'afterpay', 'tidal'],
        'services': ['pos', 'payment', 'transfer'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.cashapp', 'square-', '.afterpay']
    },
    'jpmorgan': {
        'aliases': ['chase', 'wepay', 'nutmeg'],
        'services': ['banking', 'login', 'transfer'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.bank', 'jpmorgan-', '.chase']
    },
    'revolut': {
        'aliases': ['metal', 'business', 'perks'],
        'services': ['transfer', 'exchange', 'card'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.bank', 'revolut-', '.fx']
    },
    'wise': {
        'aliases': ['transferwise', 'assets', 'borderless'],
        'services': ['transfer', 'account', 'verify'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.wise', 'wise-', '.money']
    },
    'antgroup': {
        'aliases': ['alipay', 'mytbank', 'antchain'],
        'services': ['payment', 'wallet', 'verify'],
        'safe_tlds': ['.com', '.cn'],
        'suspicious_tlds': ['.ant', 'antgroup-', '.mybank']
    },

    # Social Media (8)
    'meta': {
        'aliases': ['facebook', 'instagram', 'threads', 'oculus'],
        'services': ['login', 'recover', '2fa'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.meta', 'meta-', '.vr']
    },
    'tiktok': {
        'aliases': ['bytedance', 'capcut', 'lemon8'],
        'services': ['creator', 'verification', 'shop'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.tiktok', 'tiktok-', '.short']
    },
    'snap': {
        'aliases': ['snapchat', 'bitmoji', 'spectacles'],
        'services': ['login', 'recovery', 'verify'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.snap', 'snap-', '.ar']
    },
    'linkedin': {
        'aliases': ['premium', 'salesnavigator', 'learning'],
        'services': ['login', 'job', 'profile'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.career', 'linkedin-', '.hire']
    },
    'pinterest': {
        'aliases': ['shuffles', 'pinterestlens', 'pinteresttv'],
        'services': ['login', 'shop', 'creator'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.pin', 'pinterest-', '.craft']
    },
    'discord': {
        'aliases': ['nitro', 'stage', 'forum'],
        'services': ['login', '2fa', 'server'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.chat', 'discord-', '.nitro']
    },
    'telegram': {
        'aliases': ['ton', 'telegramx', 'telegraph'],
        'services': ['login', '2fa', 'channel'],
        'safe_tlds': ['.org'],
        'suspicious_tlds': ['.tg', 'telegram-', '.crypto']
    },
    'reddit': {
        'aliases': ['subreddit', 'coins', 'collectible'],
        'services': ['login', 'premium', 'modmail'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.post', 'reddit-', '.rpan']
    },

    # Cloud/DevOps (7)
    'aws': {
        'aliases': ['lambda', 's3', 'ec2', 'bedrock'],
        'services': ['keys', 'bucket', 'console'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.aws', 'aws-', '.lambda']
    },
    'digitalocean': {
        'aliases': ['spaces', 'functions', 'managedk8s'],
        'services': ['api', 'token', 'deploy'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.do', 'digitalocean-', '.space']
    },
    'docker': {
        'aliases': ['container', 'compose', 'scout'],
        'services': ['login', 'registry', 'build'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.docker', 'docker-', '.container']
    },
    'github': {
        'aliases': ['copilot', 'actions', 'codespaces'],
        'services': ['token', 'oauth', 'repo'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.git', 'github-', '.action']
    },
    'gitlab': {
        'aliases': ['devsecops', 'sast', 'pages'],
        'services': ['token', 'pipeline', 'merge'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.gitlab', 'gitlab-', '.ci']
    },
    'cloudflare': {
        'aliases': ['workers', 'pages', 'zaraz'],
        'services': ['dns', 'ssl', 'firewall'],
        'safe_tlds': ['.com', '.workers.dev'],
        'suspicious_tlds': ['.cdn', 'cloudflare-', '.dns']
    },
    'vercel': {
        'aliases': ['nextjs', 'sveltekit', 'turbo'],
        'services': ['deploy', 'domain', 'auth'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.vercel', 'vercel-', '.edge']
    },

    # Collaboration (5)
    'slack': {
        'aliases': ['workflowbuilder', 'clips', 'canvas'],
        'services': ['auth', 'token', 'invite'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.slack', 'slack-', '.workflow']
    },
    'zoom': {
        'aliases': ['zoomai', 'zoomspark', 'zoomdocs'],
        'services': ['join', 'meeting', 'recording'],
        'safe_tlds': ['.us'],  # Critical fix: zoom.us is primary
        'suspicious_tlds': ['.com', 'zoom-', '.webinar']
    },
    'notion': {
        'aliases': ['notionai', 'notionworkspace', 'q&a'],
        'services': ['login', 'share', 'workspace'],
        'safe_tlds': ['.so'],
        'suspicious_tlds': ['.notion', 'notion-', '.docs']
    },
    'figma': {
        'aliases': ['figjam', 'devmode', 'variables'],
        'services': ['login', 'share', 'prototype'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.figma', 'figma-', '.ui']
    },
    'mural': {
        'aliases': ['muralai', 'template', 'workshop'],
        'services': ['login', 'share', 'whiteboard'],
        'safe_tlds': ['.co'],
        'suspicious_tlds': ['.mural', 'mural-', '.workshop']
    },

    # E-commerce (5)
    'shopify': {
        'aliases': ['shopifypayments', 'shopapp', 'commerceos'],
        'services': ['admin', 'order', 'checkout'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.shop', 'shopify-', '.cart']
    },
    'amazon': {
        'aliases': ['amazonbusiness', 'buywithprime', 'zoox'],
        'services': ['verify', 'order', 'payment'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.shop', 'amazon-', '.alexa']
    },
    'alibaba': {
        'aliases': ['aliexpress', 'alipay', 'cainiao', 'daraz'],
        'services': ['login', 'order', 'payment'],
        'safe_tlds': ['.com', '.cn'],
        'suspicious_tlds': ['.1688', 'alibaba-', '.supplier']
    },
    'walmart': {
        'aliases': ['flipkart', 'samsclub', 'bonobos'],
        'services': ['order', 'pharmacy', 'membership'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.club', 'walmart-', '.grocery']
    },
    'shein': {
        'aliases': ['romwe', 'motf', 'emis'],
        'services': ['order', 'tracking', 'return'],
        'safe_tlds': ['.com'],
        'suspicious_tlds': ['.shein', 'shein-', '.style']
    }
}

    suspicious_tlds = [
        '.xyz', '.top', '.online', '.site', '.web', '.info', '.shop',
        '.store', '.icu', '.club', '.space', '.tech', '.support', '.help',
        '.win', '.bid', '.loan', '.finance', '.money', '.bank', '.pay',
        '.secure', '.verify', '.account', '.auth', '.renew', '.phishing'
    ]

    def analyze_domain(d):
        parts = d.split('.')
        tld = f".{parts[-1]}" if len(parts) > 1 else ''
        
        for brand, data in brand_matrix.items():
            # Check main domain or aliases in suspicious positions
            if any(b in parts[:-1] for b in [brand] + data['aliases']):
                if tld in data['suspicious_tlds'] + suspicious_tlds:
                    return True
                if any(service in d for service in data['services']):
                    return True
                
        return False

    def analyze_path(p):
        for brand, data in brand_matrix.items():
            if brand in p:
                if any(service in p for service in data['services']):
                    return True
                if any(tld in p for tld in data['suspicious_tlds'] + suspicious_tlds):
                    return True
        return False

    domain_risk = analyze_domain(domain.lower()) if domain else False
    path_risk = analyze_path(path.lower()) if path else False
    
    return int(domain_risk or path_risk)
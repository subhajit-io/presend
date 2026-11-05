#!/usr/bin/env python3
"""
Presend v2.0 — Zero-AI Privacy Shield
100% offline, deterministic PII redaction engine.
Runs under the hood powering both the HTML frontend and the Python CLI.

Linguistic & Deterministic Processing:
- Honorific-preceded and self-introduction names
- Address suffix detection and residence contexts (e.g. "live in <Place>")
- Acronym protection (NEET, UPSC, CSE, BTECH, API, HTTP, etc.)
- Tool & Artifact syntactic protection (e.g. "PII Redactor", "app named Foo")
- Emails, Passwords, API Keys (sk-, AKIA, GitHub PATs, JWTs, Bearer tokens)
- Indian PAN, Aadhaar (12-digit), Passport, UPI IDs, @usernames
- Phone numbers (Indian +91, US, International)
- Credit cards (Luhn-checked), IBANs, IPv4 addresses, Hex private keys
- Bare digits encoded to X
"""

import re
import sys
import os
import json
import http.server
import urllib.parse

# ---------------------------------------------------------------------------
# NLTK corpora — cached locally, zero cloud network calls
# ---------------------------------------------------------------------------
try:
    import nltk
    from nltk.corpus import stopwords, wordnet as wn
    _STOPWORDS = set(stopwords.words('english'))
    def _is_en_verb_or_modifier(word_lower: str) -> bool:
        return (
            bool(wn.synsets(word_lower, pos=wn.VERB)) or
            bool(wn.synsets(word_lower, pos=wn.ADJ))  or
            bool(wn.synsets(word_lower, pos=wn.ADV))
        )
    _NLTK_OK = True
except Exception:
    _STOPWORDS = set()
    _NLTK_OK = False
    def _is_en_verb_or_modifier(word_lower: str) -> bool:
        return False

# ---------------------------------------------------------------------------
# STATIC CLOSED-CLASS SETS
# ---------------------------------------------------------------------------
FUNCTIONAL_WORDS = _STOPWORDS | {
    'i', 'me', 'my', 'myself', 'we', 'us', 'our', 'ours', 'ourselves',
    'you', 'your', 'yours', 'yourself', 'yourselves',
    'he', 'him', 'his', 'himself', 'she', 'her', 'hers', 'herself',
    'it', 'its', 'itself', 'they', 'them', 'their', 'theirs', 'themselves',
    'this', 'that', 'these', 'those', 'who', 'whom', 'whose', 'which', 'what',
    'a', 'an', 'the', 'some', 'any', 'no', 'every', 'each', 'either', 'neither',
    'all', 'both', 'few', 'many', 'much', 'more', 'most', 'other', 'another', 'such',
    'and', 'but', 'or', 'nor', 'so', 'yet', 'for', 'although', 'because', 'since',
    'while', 'unless', 'until', 'though', 'whether', 'if', 'when', 'where', 'how', 'why',
    'at', 'in', 'on', 'to', 'of', 'from', 'with', 'by', 'about', 'as',
    'into', 'through', 'over', 'under', 'above', 'below', 'between', 'among',
    'after', 'before', 'during', 'within', 'without', 'against', 'along',
    'around', 'behind', 'beside', 'beyond', 'despite', 'except', 'near', 'off',
    'onto', 'out', 'outside', 'per', 'plus', 'than', 'throughout',
    'toward', 'towards', 'upon', 'via', 'versus', 'vs',
    'is', 'are', 'was', 'were', 'be', 'been', 'being',
    'have', 'has', 'had', 'having', 'do', 'does', 'did', 'done', 'doing',
    'will', 'would', 'shall', 'should', 'may', 'might', 'must', 'can', 'could',
    'need', 'dare', 'ought', 'used',
    'not', 'very', 'just', 'also', 'too', 'already', 'still', 'even', 'only',
    'then', 'now', 'here', 'there', 'always', 'often', 'never', 'sometimes',
    'really', 'quite', 'rather', 'almost', 'again', 'once', 'twice',
    'please', 'well', 'okay', 'ok', 'yes', 'no', 'hi', 'hello', 'hey', 'oh', 'ah',
}

HONORIFICS = {'mr', 'mrs', 'ms', 'miss', 'dr', 'prof', 'rev', 'shri', 'smt', 'sri', 'shr', 'km'}

ADDRESS_SUFFIXES = {
    'road', 'rd', 'street', 'st', 'avenue', 'ave', 'lane', 'ln', 'drive',
    'nagar', 'colony', 'marg', 'chowk', 'vihar', 'enclave', 'apartment', 'apartments',
    'apts', 'society', 'layout', 'cross', 'main', 'sector', 'block', 'phase',
    'tower', 'towers', 'building', 'bldg', 'plaza', 'hospital', 'clinic', 'bank',
    'park', 'gardens', 'heights', 'court', 'circle', 'square', 'place', 'trail',
    'blvd', 'boulevard', 'way', 'terrace', 'crescent', 'close', 'grove', 'vale',
}

DATA_LABELS = {
    'email', 'mail', 'password', 'passwd', 'pwd', 'secret', 'token', 'key',
    'username', 'user', 'handle', 'login', 'phone', 'mobile', 'tel', 'cell',
    'address', 'pin', 'pincode', 'zip', 'zipcode', 'otp', 'pan', 'upi',
    'aadhaar', 'aadhar', 'account', 'acc', 'id', 'num', 'number', 'card',
    'total', 'amount', 'cost', 'price', 'rs', 'inr', 'usd', 'eur', 'gbp',
    'item', 'items', 'stuff', 'office', 'home', 'work', 'flat', 'details',
    'info', 'information', 'data', 'note', 'notes', 'message', 'msg',
    'name', 'contact', 'signature',
}

COMMON_PREDICATES = {
    'fine', 'good', 'great', 'bad', 'well', 'sick', 'tired', 'ready',
    'happy', 'sad', 'sorry', 'here', 'there', 'busy', 'late', 'early',
    'sure', 'okay', 'ok', 'alive', 'back', 'free', 'done', 'home',
    'away', 'out', 'in', 'lost', 'found', 'safe', 'grateful', 'thankful',
    'excited', 'nervous', 'worried', 'confused', 'writing', 'working',
    'going', 'coming', 'waiting', 'thinking', 'trying',
    'available', 'unavailable', 'online', 'offline', 'active', 'inactive',
    'correct', 'wrong', 'right', 'serious', 'joking', 'your', 'friend',
    'student', 'teacher', 'manager', 'owner', 'a', 'an', 'the',
}

INTRO_TWO_WORD = {
    'i am', "i'm", 'name is', 'this is', 'call me', 'i go', 'go by',
    'meet me', 'known as', 'my name', 'her name', 'his name', 'their name',
    'your name', 'introduce myself', 'everyone call',
}

INTRO_ONE_WORD = {"iam", "i'm", "introduce", "introducing", "presenting"}

LOCATION_CONTEXT_TWO_WORD = {
    'live in', 'lives in', 'living in', 'lived in',
    'stay in', 'stays in', 'staying in', 'stayed in',
    'reside in', 'resides in', 'residing in', 'resided in',
    'located in', 'born in', 'moved to', 'moving to', 'relocated to',
    'travel to', 'traveling to', 'travelled to',
    'native of', 'native to', 'trip to', 'flew to', 'flying to',
    'hails from', 'settled in', 'visiting', 'welcome to'
}

ARTIFACT_NOUNS = {
    'redactor', 'app', 'application', 'tool', 'project', 'software', 'bot', 'model',
    'system', 'extension', 'program', 'algorithm', 'plugin', 'module', 'package',
    'library', 'device', 'game', 'repo', 'repository', 'site', 'website', 'service',
    'database', 'table', 'code', 'script', 'file', 'folder', 'utility', 'api',
    'framework', 'platform', 'agent', 'product', 'workflow', 'pipeline', 'engine', 'dataset'
}

# ---------------------------------------------------------------------------
# GRAMMAR CLASSIFIERS
# ---------------------------------------------------------------------------
def luhn_check(num_str: str) -> bool:
    digits = re.sub(r'\D', '', num_str)
    if not (13 <= len(digits) <= 19):
        return False
    total, dbl = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if dbl:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        dbl = not dbl
    return total % 10 == 0

def _is_function_word(word: str) -> bool:
    wl = word.lower()
    if wl in FUNCTIONAL_WORDS or wl in DATA_LABELS or wl in HONORIFICS:
        return True
    if _NLTK_OK and len(wl) > 2 and _is_en_verb_or_modifier(wl):
        return True
    return False

def _is_acronym(word: str) -> bool:
    return bool(re.match(r'^[A-Z0-9]{2,10}$', word)) and not word.isdigit()

def _is_artifact_or_tool(word: str, prev_word: str, prev2_word: str) -> bool:
    prev_is_acronym = _is_acronym(prev_word)
    prev_lower = prev_word.lower() if prev_word else ''
    prev2_lower = prev2_word.lower() if prev2_word else ''
    is_demonstrative = (prev_lower in {'this', 'that', 'these', 'those'}) or (prev2_lower in {'this', 'that'} and prev_is_acronym)
    if is_demonstrative or prev_is_acronym:
        return True

    wl = word.lower()
    if re.search(r'(?:or|er|ware|base|tion|sion|ment|sys)$', wl) and prev_lower in {'a', 'an', 'the', 'our', 'new', 'my'}:
        return True
    return False

def _is_artifact_context(prev_word: str, prev2_word: str) -> bool:
    p1 = prev_word.lower() if prev_word else ''
    p2 = prev2_word.lower() if prev2_word else ''
    if p1 in ARTIFACT_NOUNS or p2 in ARTIFACT_NOUNS:
        return True
    if re.search(r'(?:or|er|ware|base|tion|sion|ment|sys)$', p2) and (_is_acronym(prev_word) or p1 in {'this', 'that', 'our', 'my', 'the', 'a', 'an'}):
        return True
    return False

# ---------------------------------------------------------------------------
# STRUCTURAL REGEX PATTERNS
# ---------------------------------------------------------------------------
PATTERNS = [
    { 'regex': re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), 'tag': '[EMAIL]', 'badge': 'badge-email', 'stat': 'email', 'cat': 'Email' },
    { 'regex': re.compile(r'\bey[A-Za-z0-9_\-]+\.ey[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b'), 'tag': '[API_KEY]', 'badge': 'badge-secret', 'stat': 'secret', 'cat': 'API Key' },
    { 'regex': re.compile(r'(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*'), 'tag': '[API_KEY]', 'badge': 'badge-secret', 'stat': 'secret', 'cat': 'API Key' },
    { 'regex': re.compile(r'\bsk-[A-Za-z0-9_\-]{20,}\b'), 'tag': '[API_KEY]', 'badge': 'badge-secret', 'stat': 'secret', 'cat': 'API Key' },
    { 'regex': re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b'), 'tag': '[API_KEY]', 'badge': 'badge-secret', 'stat': 'secret', 'cat': 'API Key' },
    { 'regex': re.compile(r'\bAKIA[0-9A-Z]{16}\b'), 'tag': '[API_KEY]', 'badge': 'badge-secret', 'stat': 'secret', 'cat': 'API Key' },
    { 'regex': re.compile(r'(?i)((?:password|passwd|pwd|secret|api[_\-]?key|token|auth|credentials?)\s*[:=]\s*["\']?)[^\s"\'\n\r,;]{3,}'), 'tag': '[PASSWORD]', 'badge': 'badge-secret', 'stat': 'secret', 'cat': 'Password', 'group': 1 },
    { 'regex': re.compile(r'(?i)mongodb(?:\+srv)?://[^\s"\'<>]+'), 'tag': '[DB_URI]', 'badge': 'badge-secret', 'stat': 'secret', 'cat': 'DB URI' },
    { 'regex': re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'), 'tag': '[PAN]', 'badge': 'badge-id', 'stat': 'id', 'cat': 'PAN' },
    { 'regex': re.compile(r'\b(?:\d[\s\-]?){13,19}\d\b'), 'tag': '[CARD]', 'badge': 'badge-secret', 'stat': 'secret', 'cat': 'Card', 'validate': luhn_check },
    { 'regex': re.compile(r'(?<![+\d])[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}(?!\d)'), 'tag': '[AADHAAR]', 'badge': 'badge-id', 'stat': 'id', 'cat': 'Aadhaar' },
    { 'regex': re.compile(r'\b[A-PR-WY][1-9]\d{6}\b'), 'tag': '[PASSPORT]', 'badge': 'badge-id', 'stat': 'id', 'cat': 'Passport' },
    { 'regex': re.compile(r'(?i)\b[a-zA-Z0-9.\-_]{2,}@(okaxis|oksbi|okhdfcbank|okicici|paytm|ybl|ibl|axl|upi|sbi|hdfcbank|icici|barodampay|pnb|postbank|apl|rapl|freecharge|airtel|gpay|idfcbank|kotak|hsbc)\b'), 'tag': '[UPI_ID]', 'badge': 'badge-id', 'stat': 'id', 'cat': 'UPI' },
    { 'regex': re.compile(r'@[A-Za-z0-9_.\-]{3,30}\b'), 'tag': '[USERNAME]', 'badge': 'badge-user', 'stat': 'id', 'cat': 'Username' },
    { 'regex': re.compile(r'(?i)((?:username|user|handle|login)\s*[:=]\s*["\']?)[A-Za-z0-9_.\-]{3,30}\b'), 'tag': '[USERNAME]', 'badge': 'badge-user', 'stat': 'id', 'cat': 'Username', 'group': 1 },
    { 'regex': re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b'), 'tag': '[IBAN]', 'badge': 'badge-id', 'stat': 'id', 'cat': 'IBAN' },
    { 'regex': re.compile(r'(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])'), 'tag': '[PRIVATE_KEY]', 'badge': 'badge-secret', 'stat': 'secret', 'cat': 'Private Key' },
    { 'regex': re.compile(r'(?:(?:\+|00)91[\s\-]?|91[\s\-]?|0)?[6-9]\d{9}\b'), 'tag': '[PHONE]', 'badge': 'badge-phone', 'stat': 'phone', 'cat': 'Phone', 'validate': lambda m: len(re.sub(r'\D', '', m)) >= 10 },
    { 'regex': re.compile(r'(?:\+1[\s\-]?)?\(?[2-9]\d{2}\)?[\s\-]?[2-9]\d{2}[\s\-]?\d{4}\b'), 'tag': '[PHONE]', 'badge': 'badge-phone', 'stat': 'phone', 'cat': 'Phone' },
    { 'regex': re.compile(r'\+[1-9]\d{1,14}\b'), 'tag': '[PHONE]', 'badge': 'badge-phone', 'stat': 'phone', 'cat': 'Phone' },
    { 'regex': re.compile(r'\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'), 'tag': '[IP_ADDR]', 'badge': 'badge-secret', 'stat': 'secret', 'cat': 'IP Address' },
]

TAG_META = {
    '[Name]':        ('badge-name', 'Name', 'name'),
    '[NAME]':        ('badge-name', 'Name', 'name'),
    '[ADDRESS]':     ('badge-address', 'Address', 'address'),
    '[PHONE]':       ('badge-phone', 'Phone', 'phone'),
    '[EMAIL]':       ('badge-email', 'Email', 'email'),
    '[USERNAME]':    ('badge-user', 'Username', 'id'),
    '[PASSWORD]':    ('badge-secret', 'Password', 'secret'),
    '[API_KEY]':     ('badge-secret', 'API Key', 'secret'),
    '[AADHAAR]':     ('badge-id', 'Aadhaar', 'id'),
    '[PAN]':         ('badge-id', 'PAN', 'id'),
    '[PASSPORT]':    ('badge-id', 'Passport', 'id'),
    '[CARD]':        ('badge-secret', 'Card', 'secret'),
    '[UPI_ID]':      ('badge-id', 'UPI', 'id'),
    '[IBAN]':        ('badge-id', 'IBAN', 'id'),
    '[IP_ADDR]':     ('badge-secret', 'IP Address', 'secret'),
    '[DB_URI]':      ('badge-secret', 'DB URI', 'secret'),
    '[PRIVATE_KEY]': ('badge-secret', 'Private Key', 'secret'),
    '[REDACTED]':    ('badge-manual', 'Custom', 'custom'),
    '[CUSTOM]':      ('badge-manual', 'Custom', 'custom'),
}

# ---------------------------------------------------------------------------
# POSITION-AWARE TOKENIZER
# ---------------------------------------------------------------------------
def find_regex_spans(text: str):
    accepted = []
    def overlaps(s, e):
        return any(s < item['end'] and e > item['start'] for item in accepted)

    for p in PATTERNS:
        for m in p['regex'].finditer(text):
            full = m.group(0)
            t_start = m.start()
            t_text = full
            if 'group' in p and p['group'] is not None:
                prefix = m.group(p['group']) or ''
                t_start += len(prefix)
                t_text = full[len(prefix):]
            if 'validate' in p and p['validate'] is not None and not p['validate'](t_text):
                continue
            t_end = t_start + len(t_text)
            if t_end <= t_start:
                continue
            if not overlaps(t_start, t_end):
                accepted.append({
                    'start': t_start,
                    'end': t_end,
                    'originalText': t_text,
                    'mask': p['tag'],
                    'badgeClass': p['badge'],
                    'stat': p['stat'],
                    'category': p['cat']
                })

    accepted.sort(key=lambda x: x['start'])
    return accepted

def tokenize_text_with_spans(text: str, spans):
    tokens = []
    cur_idx = 0
    next_id = 0

    def tokenize_segment(seg, offset):
        nonlocal next_id
        sub_re = re.compile(r'(\[[A-Za-z_]+\]|\s+|[^\s\w]+|\w+)')
        for m in sub_re.finditer(seg):
            raw = m.group(0)
            is_pre = bool(re.match(r'^\[[A-Za-z_]+\]$', raw))
            is_word = not is_pre and bool(re.match(r'^\w+$', raw))
            s = offset + m.start()
            e = s + len(raw)
            tokens.append({
                'id': next_id,
                'start': s,
                'end': e,
                'originalText': raw,
                'text': raw,
                'isWord': is_word,
                'isRegex': False,
                'isPreMasked': is_pre,
                'masked': is_pre,
                'mask': raw if is_pre else '[REDACTED]',
                'badgeClass': 'badge-manual',
                'category': 'PII' if is_pre else 'Text',
                'stat': None
            })
            next_id += 1

    for span in spans:
        if span['start'] > cur_idx:
            tokenize_segment(text[cur_idx:span['start']], cur_idx)
        tokens.append({
            'id': next_id,
            'start': span['start'],
            'end': span['end'],
            'originalText': span['originalText'],
            'text': span['originalText'],
            'isWord': True,
            'isRegex': True,
            'isPreMasked': True,
            'masked': True,
            'mask': span['mask'],
            'badgeClass': span['badgeClass'],
            'category': span['category'],
            'stat': span['stat']
        })
        next_id += 1
        cur_idx = span['end']

    if cur_idx < len(text):
        tokenize_segment(text[cur_idx:], cur_idx)

    return tokens

def build_sentence_start_ids(tokens):
    start_ids = set()
    after_boundary = True
    last_word_lower = ''
    for t in tokens:
        raw = t['text']
        if raw in {'!', '?', '\n'}:
            after_boundary = True
        elif raw == '.':
            after_boundary = last_word_lower not in HONORIFICS
        elif t['isWord']:
            last_word_lower = raw.lower()
            if after_boundary:
                start_ids.add(t['id'])
                after_boundary = False
    return start_ids

def classify_names_and_entities(tokens, manual_overrides=None, label_overrides=None, custom_word_rules=None):
    manual_overrides = manual_overrides or {}
    label_overrides = label_overrides or {}
    custom_word_rules = custom_word_rules or {}

    words_only = [t for t in tokens if t['isWord']]
    start_ids = build_sentence_start_ids(tokens)

    for i, t in enumerate(words_only):
        raw = t['text']
        wl = raw.lower()
        tid = str(t['id'])

        # Respect manual user overrides
        if tid in manual_overrides or t['id'] in manual_overrides:
            val = manual_overrides.get(tid, manual_overrides.get(t['id']))
            t['masked'] = bool(val)
            ov = label_overrides.get(tid, label_overrides.get(t['id']))
            if ov:
                if isinstance(ov, dict):
                    t['mask'] = ov.get('mask', t['mask'])
                    t['badgeClass'] = ov.get('badgeClass', t['badgeClass'])
                    t['category'] = ov.get('category', t['category'])
                elif isinstance(ov, str):
                    t['mask'] = ov
                    meta = TAG_META.get(ov, ('badge-manual', 'Custom', 'custom'))
                    t['badgeClass'] = meta[0]
                    t['category'] = meta[1]
            continue

        # Respect custom word rules
        if wl in custom_word_rules:
            rule = custom_word_rules[wl]
            t['masked'] = True
            t['mask'] = rule.get('label', '[CUSTOM]') if isinstance(rule, dict) else str(rule)
            t['badgeClass'] = rule.get('badgeClass', 'badge-manual') if isinstance(rule, dict) else 'badge-manual'
            t['category'] = rule.get('category', 'Custom') if isinstance(rule, dict) else 'Custom'
            continue

        # Respect custom label switch even if not in manual_overrides
        if tid in label_overrides or t['id'] in label_overrides:
            ov = label_overrides.get(tid, label_overrides.get(t['id']))
            if ov:
                t['masked'] = True
                if isinstance(ov, dict):
                    t['mask'] = ov.get('mask', t['mask'])
                    t['badgeClass'] = ov.get('badgeClass', t['badgeClass'])
                    t['category'] = ov.get('category', t['category'])
                elif isinstance(ov, str):
                    t['mask'] = ov
                    meta = TAG_META.get(ov, ('badge-manual', 'Custom', 'custom'))
                    t['badgeClass'] = meta[0]
                    t['category'] = meta[1]
            continue

        ov = label_overrides.get(tid, label_overrides.get(t['id']))
        if t['isPreMasked']:
            if ov:
                if isinstance(ov, dict):
                    t['mask'] = ov.get('mask', t['mask'])
                    t['badgeClass'] = ov.get('badgeClass', t['badgeClass'])
                    t['category'] = ov.get('category', t['category'])
                elif isinstance(ov, str):
                    t['mask'] = ov
            continue

        if re.match(r'^X+([a-z]{0,4})?$', raw):
            continue
        if re.match(r'^X+(st|nd|rd|th)?$', raw):
            continue

        active_label = (ov.get('mask') if isinstance(ov, dict) else ov) if ov else None
        active_badge = ov.get('badgeClass') if isinstance(ov, dict) else None
        active_cat   = ov.get('category') if isinstance(ov, dict) else None

        # Address suffix detection
        if wl in ADDRESS_SUFFIXES:
            t['masked'] = True
            t['mask'] = active_label or '[ADDRESS]'
            t['badgeClass'] = active_badge or 'badge-address'
            t['category'] = active_cat or 'Address'
            if i > 0:
                prev = words_only[i - 1]
                if not prev['masked'] and not prev['isPreMasked'] and re.match(r'^[A-Z]', prev['text']) and not prev['text'].startswith('X'):
                    prev['masked'] = True
                    prev['mask'] = '[ADDRESS]'
                    prev['badgeClass'] = 'badge-address'
                    prev['category'] = 'Address'
            continue

        prev_word = words_only[i - 1]['text'] if i > 0 else ''
        prev_lower = prev_word.lower()
        prev2_word = words_only[i - 2]['text'] if i > 1 else ''
        prev_two = (prev2_word.lower() + ' ' + prev_lower).strip()

        # Location / Living context
        is_location_context = (
            prev_two in LOCATION_CONTEXT_TWO_WORD or
            (prev_lower in {'from', 'near', 'around'} and prev2_word.lower() != 'away')
        )

        if is_location_context and re.match(r'^[A-Z]', raw) and not _is_function_word(raw) and not _is_acronym(raw):
            t['masked'] = True
            t['mask'] = active_label or '[ADDRESS]'
            t['badgeClass'] = active_badge or 'badge-address'
            t['category'] = active_cat or 'Address'
            continue

        # Honorific-preceded name: Dr. Sharma
        if prev_lower in HONORIFICS and re.match(r'^[A-Z]', raw):
            t['masked'] = True
            t['mask'] = active_label or '[Name]'
            t['badgeClass'] = active_badge or 'badge-name'
            t['category'] = active_cat or 'Name'
            continue

        if _is_function_word(raw):
            continue
        if _is_acronym(raw):
            continue
        if _is_artifact_or_tool(raw, prev_word, prev2_word):
            continue

        # Introduction context: "I am Ravi", "call me Priya"
        # If preceded by an artifact ("PII Redactor named Mask"), it is an artifact name, not a person
        is_named_or_called = (prev_lower in {'named', 'called'} and not _is_artifact_context(prev_word, prev2_word))
        is_intro = (prev_two in INTRO_TWO_WORD or prev_lower in INTRO_ONE_WORD or is_named_or_called)

        if is_intro and wl not in COMMON_PREDICATES and not _is_function_word(raw):
            t['masked'] = True
            t['mask'] = active_label or '[Name]'
            t['badgeClass'] = active_badge or 'badge-name'
            t['category'] = active_cat or 'Name'
            continue

        # Mid-sentence capitalized proper noun
        if re.match(r'^[A-Z]', raw):
            if t['id'] in start_ids:
                continue
            if _is_function_word(raw):
                continue
            if _is_acronym(raw):
                continue
            if _is_artifact_or_tool(raw, prev_word, prev2_word):
                continue
            if _is_artifact_context(prev_word, prev2_word):
                continue

            t['masked'] = True
            t['mask'] = active_label or '[Name]'
            t['badgeClass'] = active_badge or 'badge-name'
            t['category'] = active_cat or 'Name'
            continue

        # Lowercase name in intro context: "I am krish"
        if is_intro and wl not in COMMON_PREDICATES and len(wl) > 1 and re.match(r'^[a-z]', raw):
            if not _is_function_word(raw) and wl not in DATA_LABELS:
                t['masked'] = True
                t['mask'] = active_label or '[Name]'
                t['badgeClass'] = active_badge or 'badge-name'
                t['category'] = active_cat or 'Name'

def mask_digits(tokens):
    for t in tokens:
        if not t['isWord'] or t['masked'] or t['isPreMasked']:
            continue
        replaced = re.sub(r'[\d\u0966-\u096F\u09E6-\u09EF]', 'X', t['text'])
        if replaced != t['text']:
            t['text'] = replaced

def compute_live_stats(tokens):
    stats = { 'email': 0, 'secret': 0, 'phone': 0, 'id': 0, 'address': 0, 'name': 0, 'digit': 0, 'custom': 0 }
    for t in tokens:
        if t['masked']:
            cat = (t.get('category') or '').lower()
            mask = t.get('mask') or ''
            if cat == 'name' or mask in {'[Name]', '[NAME]'}:
                stats['name'] += 1
            elif cat == 'address' or mask == '[ADDRESS]':
                stats['address'] += 1
            elif cat == 'phone' or mask == '[PHONE]':
                stats['phone'] += 1
            elif cat == 'email' or mask == '[EMAIL]':
                stats['email'] += 1
            elif cat == 'username' or mask == '[USERNAME]':
                stats['id'] += 1
            elif cat in {'password', 'api key', 'card', 'secret', 'db uri', 'ip address', 'private key'} or mask in {'[PASSWORD]', '[API_KEY]', '[DB_URI]', '[IP_ADDR]', '[CARD]', '[PRIVATE_KEY]'}:
                stats['secret'] += 1
            elif cat in {'id', 'aadhaar', 'pan', 'passport', 'iban', 'upi'} or mask in {'[PAN]', '[AADHAAR]', '[PASSPORT]', '[IBAN]', '[UPI_ID]'}:
                stats['id'] += 1
            else:
                stats['custom'] += 1
        elif t['originalText'] != t['text'] and re.search(r'[\d\u0966-\u096F\u09E6-\u09EF]', t['originalText']):
            matches = re.findall(r'[\d\u0966-\u096F\u09E6-\u09EF]', t['originalText'])
            stats['digit'] += len(matches) if matches else 1
    return stats

def compute_risk(stats):
    if stats.get('secret', 0) > 0:
        return 'CRITICAL'
    if stats.get('id', 0) > 0:
        return 'HIGH'
    if stats.get('phone', 0) > 0 or stats.get('email', 0) > 0:
        return 'MEDIUM'
    if stats.get('name', 0) > 2:
        return 'MEDIUM'
    return 'LOW'

# ---------------------------------------------------------------------------
# CORE REDACTION API
# ---------------------------------------------------------------------------
def redact(text: str, overrides=None, return_tokens: bool = False, return_details: bool = False):
    if not text:
        empty_res = {
            'redactedText': '',
            'tokens': [],
            'stats': { 'email': 0, 'secret': 0, 'phone': 0, 'id': 0, 'address': 0, 'name': 0, 'digit': 0, 'custom': 0 },
            'risk': 'LOW',
            'engine': 'Python 3 (under the hood)'
        }
        if return_details:
            return empty_res
        if return_tokens:
            return ('', [])
        return ''

    overrides = overrides or {}
    manual_overrides = overrides.get('manualOverrides') or overrides.get('unmaskedIds') or {}
    label_overrides = overrides.get('labelOverrides') or {}
    custom_word_rules = overrides.get('customWordRules') or {}

    spans = find_regex_spans(text)
    tokens = tokenize_text_with_spans(text, spans)
    classify_names_and_entities(tokens, manual_overrides, label_overrides, custom_word_rules)
    mask_digits(tokens)

    stats = compute_live_stats(tokens)
    risk = compute_risk(stats)
    redacted_text = ''.join(t['mask'] if t['masked'] else t['text'] for t in tokens)

    if return_details:
        return {
            'redactedText': redacted_text,
            'tokens': tokens,
            'stats': stats,
            'risk': risk,
            'engine': 'Python 3 (under the hood)'
        }

    if return_tokens:
        return (redacted_text, tokens)

    return redacted_text

# ---------------------------------------------------------------------------
# BUILT-IN HTTP SERVER (Zero external dependencies)
# ---------------------------------------------------------------------------
class PresendHTTPHandler(http.server.BaseHTTPRequestHandler):
    def send_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, HEAD')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Access-Control-Request-Private-Network')
        self.send_header('Access-Control-Allow-Private-Network', 'true')

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_cors_headers()
        self.end_headers()

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path in ('/', '/index.html'):
            html_path = os.path.join(os.path.dirname(__file__), 'index.html')
            if not os.path.exists(html_path):
                html_path = 'index.html'
            try:
                with open(html_path, 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
                self.send_cors_headers()
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(e).encode('utf-8'))
        elif path == '/api/status':
            resp = json.dumps({'status': 'ok', 'engine': 'Python 3 (under the hood)'}).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_cors_headers()
            self.send_header('Content-Length', str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not found')

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == '/api/redact':
            length = int(self.headers.get('Content-Length', 0))
            body_bytes = self.rfile.read(length) if length > 0 else b'{}'
            try:
                payload = json.loads(body_bytes.decode('utf-8'))
            except Exception:
                payload = {}

            text = payload.get('text', '')
            overrides = {
                'manualOverrides': payload.get('manualOverrides', {}),
                'labelOverrides': payload.get('labelOverrides', {}),
                'customWordRules': payload.get('customWordRules', {})
            }

            result = redact(text, overrides=overrides, return_details=True)
            resp = json.dumps(result).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_cors_headers()
            self.send_header('Content-Length', str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not found')

    def log_message(self, format, *args):
        # Clean console output
        sys.stderr.write(f"[Presend Backend] {format % args}\n")

def run_server(port: int = 8000, host: str = '127.0.0.1'):
    server_address = (host, port)
    try:
        httpd = http.server.HTTPServer(server_address, PresendHTTPHandler)
    except OSError as err:
        if '10048' in str(err) or 'Address already in use' in str(err):
            # Port busy, fallback to next port
            port += 1
            server_address = (host, port)
            httpd = http.server.HTTPServer(server_address, PresendHTTPHandler)
        else:
            raise

    print('====================================================================', flush=True)
    print(f'  Presend v2.0 - Zero-AI Privacy Shield (Server Active)', flush=True)
    print(f'  Frontend:      http://{host}:{port}/', flush=True)
    print(f'  API Endpoint:  http://{host}:{port}/api/redact', flush=True)
    print(f'  All redaction processes run under the hood in Python.', flush=True)
    print('  Press Ctrl+C to stop.', flush=True)
    print('====================================================================', flush=True)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('\nServer stopped.', flush=True)
    finally:
        httpd.server_close()

# ---------------------------------------------------------------------------
# CLI & ENTRY POINT
# ---------------------------------------------------------------------------
def main():
    args = sys.argv[1:]
    show_audit = False
    if '--audit' in args or '--track' in args:
        show_audit = True
        args = [a for a in args if a not in ('--audit', '--track')]

    if not args or '--serve' in args or (len(args) == 1 and args[0] in ('serve', 'start')):
        port = 8000
        for i, a in enumerate(args):
            if a in ('--port', '-p') and i + 1 < len(args) and args[i + 1].isdigit():
                port = int(args[i + 1])
            elif a.isdigit():
                port = int(a)
        run_server(port=port)
        return

    if '-' in args:
        text = sys.stdin.read()
    else:
        target = ' '.join(args)
        if os.path.isfile(target):
            with open(target, 'r', encoding='utf-8') as f:
                text = f.read()
        else:
            text = target

    res = redact(text.rstrip('\n'), return_tokens=show_audit)
    if show_audit:
        output, tokens = res
    else:
        output = res

    if sys.stdout.isatty():
        # Bold green for [Name] in terminal
        colored = re.sub(r'\[Name\]', '\033[1;32m[Name]\033[0m', output)
        # Cyan for structural tags like [EMAIL], [PHONE], [ADDRESS]
        colored = re.sub(r'\[(?!Name)[A-Za-z_]+\]', lambda m: '\033[1;36m' + m.group(0) + '\033[0m', colored)
        print(colored)
    else:
        print(output)

    if show_audit:
        converted = [t for t in tokens if t.get('masked')]
        print('\n--- Conversion Audit Tracker ---')
        if not converted:
            print('No conversions recorded.')
        else:
            for item in converted:
                mask_val = item.get('mask', '[REDACTED]')
                orig = item.get('originalText') or item.get('text', '')
                print(f"  {orig:<25} -> {mask_val}")

if __name__ == '__main__':
    main()

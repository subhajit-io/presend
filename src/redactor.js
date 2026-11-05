/**
 * Presend - Core PII Redactor Engine
 * 
 * Accurately detects and redacts sensitive personal identifiable information (PII)
 * including phone numbers, credit card numbers, email addresses, SSNs, IP addresses,
 * API keys/tokens, and passwords with configurable masks and validation algorithms.
 */

// Luhn algorithm (Mod 10) for verifying credit card numbers
function luhnCheck(numStr) {
  const digits = numStr.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let isSecond = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = parseInt(digits.charAt(i), 10);
    if (isNaN(d)) return false;
    if (isSecond) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    isSecond = !isSecond;
  }
  return sum % 10 === 0;
}

// Detect credit card brand from card digits
function getCardBrand(numStr) {
  const digits = numStr.replace(/\D/g, '');
  if (/^4/.test(digits)) return 'Visa';
  if (/^(5[1-5]|2[2-7])/.test(digits)) return 'MasterCard';
  if (/^3[47]/.test(digits)) return 'American Express';
  if (/^(6011|65|64[4-9]|622)/.test(digits)) return 'Discover';
  if (/^3(?:0[0-5]|[68])/.test(digits)) return 'Diners Club';
  if (/^(?:2131|1800|35)/.test(digits)) return 'JCB';
  return 'Unknown Card';
}

// Format partial mask preserving last 4 characters/digits
function formatPartialMask(type, value) {
  const digits = value.replace(/\D/g, '');
  if (type === 'CARD') {
    const last4 = digits.slice(-4) || '****';
    if (value.includes('-')) {
      return `****-****-****-${last4}`;
    } else if (value.includes(' ')) {
      return `**** **** **** ${last4}`;
    }
    return `************${last4}`;
  }
  if (type === 'PHONE') {
    const last4 = digits.slice(-4) || '****';
    if (value.includes('(')) {
      return `(***) ***-${last4}`;
    } else if (value.includes('-')) {
      return `***-***-${last4}`;
    } else if (value.includes('.')) {
      return `***.***.${last4}`;
    }
    return `*******${last4}`;
  }
  if (type === 'EMAIL') {
    const parts = value.split('@');
    if (parts.length === 2) {
      const user = parts[0];
      const domain = parts[1];
      const maskedUser = user.length > 2 
        ? `${user[0]}***${user[user.length - 1]}` 
        : `${user[0] || '*'}***`;
      return `${maskedUser}@${domain}`;
    }
    return '[EMAIL]';
  }
  if (type === 'SSN') {
    const last4 = digits.slice(-4) || '****';
    return `***-**-${last4}`;
  }
  return `[${type}]`;
}

class Redactor {
  constructor(options = {}) {
    this.options = {
      // Enabled detection categories
      detectCards: options.detectCards !== false,
      detectPhones: options.detectPhones !== false,
      detectEmails: options.detectEmails !== false,
      detectSSNs: options.detectSSNs !== false,
      detectIPs: options.detectIPs !== false,
      detectApiKeys: options.detectApiKeys !== false,
      detectSecrets: options.detectSecrets !== false,

      // Mask style: 'LABEL' ([CARD]), 'INDEXED' ([CARD_1]), 'PARTIAL' (**** 1111), 'BLOCK' (████), 'REDACTED' ([REDACTED])
      maskStyle: options.maskStyle || 'LABEL',
      
      // Strict Luhn check requirement for credit cards
      strictLuhn: options.strictLuhn || false,
      
      // Custom label prefixes/wrappers if needed
      labelPrefix: options.labelPrefix || '[',
      labelSuffix: options.labelSuffix || ']',
      
      ...options
    };
  }

  /**
   * Find all credit card matches
   */
  findCardMatches(text) {
    const matches = [];
    if (!this.options.detectCards) return matches;

    // Pattern 1: Delimited card numbers (4-4-4-4, 4-6-5 Amex, 4-4-4-4-3)
    // Matches 13 to 19 digit delimited sequences
    const delimitedPattern = /\b(?:\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,4}|\d{4}[ -]\d{6}[ -]\d{5}|\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,3})\b/g;
    let m;
    while ((m = delimitedPattern.exec(text)) !== null) {
      const raw = m[0];
      const digitsOnly = raw.replace(/\D/g, '');
      const isLuhn = luhnCheck(digitsOnly);
      
      // If strictLuhn is disabled, standard card groupings (like 4-4-4-4) are accepted even if sample numbers
      if (!this.options.strictLuhn || isLuhn) {
        matches.push({
          type: 'CARD',
          start: m.index,
          end: m.index + raw.length,
          value: raw,
          details: {
            brand: getCardBrand(digitsOnly),
            luhnValid: isLuhn,
            digitCount: digitsOnly.length
          }
        });
      }
    }

    // Pattern 2: Continuous 13-19 digits that pass Luhn check (avoid matching timestamps/random serials)
    const continuousPattern = /\b\d{13,19}\b/g;
    while ((m = continuousPattern.exec(text)) !== null) {
      const raw = m[0];
      // Only match if passes Luhn or known card prefix
      if (luhnCheck(raw)) {
        // Ensure this doesn't already overlap with an existing match
        const alreadyMatched = matches.some(existing => 
          (m.index >= existing.start && m.index < existing.end) ||
          (m.index + raw.length > existing.start && m.index + raw.length <= existing.end)
        );
        if (!alreadyMatched) {
          matches.push({
            type: 'CARD',
            start: m.index,
            end: m.index + raw.length,
            value: raw,
            details: {
              brand: getCardBrand(raw),
              luhnValid: true,
              digitCount: raw.length
            }
          });
        }
      }
    }

    return matches;
  }

  /**
   * Find all phone number matches
   * Handles:
   *  - 555-123-4567
   *  - 555.123.4567
   *  - (555) 123-4567 / (555)123-4567
   *  - 555 123 4567
   *  - +1 555 123 4567 / +1-555-123-4567 / +1 (555) 123-4567
   *  - +44 20 7946 0919 / +91 98765 43210
   *  - Extensions: ext. 123, x456
   */
  findPhoneMatches(text) {
    const matches = [];
    if (!this.options.detectPhones) return matches;

    // Comprehensive international & domestic phone pattern
    // Notice negative lookaround / boundary handling to avoid matching dates like 2026-11-04 or decimals
    const phonePatterns = [
      // 1. International with leading + : e.g. +1 (555) 123-4567, +44 20 7946 0919, +91-98765-43210
      /(?:\+|00)\d{1,4}[\s.-]?(?:\(\d{1,4}\)|\d{1,4})[\s.-]?\d{2,4}[\s.-]?\d{3,5}(?:[\s.-]?\d{1,4})?(?:\s*(?:ext|x|ext\.)\s*\d{1,5})?/g,
      
      // 2. Parenthesized area code: (555) 123-4567 or (555) 123 4567 or (555)123-4567
      /\(\d{3}\)[\s.-]?\d{3}[\s.-]\d{4}(?:\s*(?:ext|x|ext\.)\s*\d{1,5})?/g,
      
      // 3. Standard delimited 10-digit US/Canada: 555-123-4567 or 555.123.4567 or 555 123 4567 or 1-555-123-4567
      /(?<!\d)(?:1[\s.-])?[2-9]\d{2}[\s.-]\d{3}[\s.-]\d{4}(?:\s*(?:ext|x|ext\.)\s*\d{1,5})?(?!\d)/g,
      
      // 4. UK / European national style: 020 7946 0919 or 07911 123456
      /(?<!\d)0\d{2,4}[\s.-]?\d{3,4}[\s.-]?\d{3,4}(?!\d)/g
    ];

    for (const pattern of phonePatterns) {
      let m;
      while ((m = pattern.exec(text)) !== null) {
        const raw = m[0].trim();
        const digitsOnly = raw.replace(/\D/g, '');
        
        // Filter out false positives:
        // - Dates like 2026-11-04 (starts with 4-digit year)
        // - IP addresses like 192.168.1.1
        // - Too few digits (< 7) or too many (> 15)
        if (digitsOnly.length < 7 || digitsOnly.length > 15) continue;
        if (/^\d{4}[-/]\d{2}[-/]\d{2}/.test(raw)) continue; // ISO date
        if (/^\d{2}[-/]\d{2}[-/]\d{4}/.test(raw)) continue; // Date
        if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(raw)) continue; // IP

        matches.push({
          type: 'PHONE',
          start: m.index,
          end: m.index + m[0].length,
          value: m[0],
          details: {
            digits: digitsOnly,
            hasCountryCode: raw.startsWith('+') || raw.startsWith('00')
          }
        });
      }
    }

    return matches;
  }

  /**
   * Find email matches
   */
  findEmailMatches(text) {
    const matches = [];
    if (!this.options.detectEmails) return matches;

    const emailPattern = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
    let m;
    while ((m = emailPattern.exec(text)) !== null) {
      matches.push({
        type: 'EMAIL',
        start: m.index,
        end: m.index + m[0].length,
        value: m[0],
        details: {
          domain: m[0].split('@')[1]
        }
      });
    }
    return matches;
  }

  /**
   * Find US SSN matches (format: 123-45-6789)
   */
  findSSNMatches(text) {
    const matches = [];
    if (!this.options.detectSSNs) return matches;

    // Standard US SSN with valid prefix ranges
    const ssnPattern = /\b(?!000|666|9\d{2})\d{3}[ -](?!00)\d{2}[ -](?!0000)\d{4}\b/g;
    let m;
    while ((m = ssnPattern.exec(text)) !== null) {
      matches.push({
        type: 'SSN',
        start: m.index,
        end: m.index + m[0].length,
        value: m[0],
        details: {}
      });
    }
    return matches;
  }

  /**
   * Find IP address matches (IPv4 and IPv6)
   */
  findIPMatches(text) {
    const matches = [];
    if (!this.options.detectIPs) return matches;

    // IPv4
    const ipv4Pattern = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
    let m;
    while ((m = ipv4Pattern.exec(text)) !== null) {
      matches.push({
        type: 'IP_ADDRESS',
        start: m.index,
        end: m.index + m[0].length,
        value: m[0],
        details: { version: 4 }
      });
    }

    // IPv6
    const ipv6Pattern = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g;
    while ((m = ipv6Pattern.exec(text)) !== null) {
      matches.push({
        type: 'IP_ADDRESS',
        start: m.index,
        end: m.index + m[0].length,
        value: m[0],
        details: { version: 6 }
      });
    }

    return matches;
  }

  /**
   * Find API keys and security secrets
   */
  findApiKeyMatches(text) {
    const matches = [];
    if (!this.options.detectApiKeys) return matches;

    const patterns = [
      { name: 'OpenAI API Key', regex: /\bsk-[a-zA-Z0-9_-]{20,}\b/g },
      { name: 'AWS Access Key', regex: /\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g },
      { name: 'GitHub Token', regex: /\b(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b/g },
      { name: 'JWT Token', regex: /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g },
      { name: 'Bearer Token', regex: /\bBearer\s+[a-zA-Z0-9\-._~+/]+=*/gi }
    ];

    for (const p of patterns) {
      let m;
      while ((m = p.regex.exec(text)) !== null) {
        matches.push({
          type: 'API_KEY',
          start: m.index,
          end: m.index + m[0].length,
          value: m[0],
          details: { keyType: p.name }
        });
      }
    }

    return matches;
  }

  /**
   * Find credentials/passwords embedded in key-value strings
   */
  findSecretMatches(text) {
    const matches = [];
    if (!this.options.detectSecrets) return matches;

    const secretPattern = /(?:["']?[a-zA-Z0-9_.-]*(?:password|passwd|secret|api[_-]?secret|auth[_-]?token)["']?\s*[:=]\s*["']?)([^"'\s\n\r,;]{4,})["']?/gi;
    let m;
    while ((m = secretPattern.exec(text)) !== null) {
      if (m[1]) {
        // Redact just the secret value, preserving the key
        const fullMatch = m[0];
        const val = m[1];
        const valOffset = fullMatch.lastIndexOf(val);
        const start = m.index + valOffset;
        matches.push({
          type: 'SECRET',
          start: start,
          end: start + val.length,
          value: val,
          details: {}
        });
      }
    }
    return matches;
  }

  /**
   * Scan text for all enabled PII entities and resolve overlapping spans.
   */
  scan(text) {
    if (!text || typeof text !== 'string') {
      return [];
    }

    const allMatches = [
      ...this.findCardMatches(text),
      ...this.findPhoneMatches(text),
      ...this.findEmailMatches(text),
      ...this.findSSNMatches(text),
      ...this.findIPMatches(text),
      ...this.findApiKeyMatches(text),
      ...this.findSecretMatches(text)
    ];

    // Priority rank for overlap resolution
    const priority = {
      CARD: 10,
      SSN: 9,
      API_KEY: 8,
      SECRET: 7,
      EMAIL: 6,
      PHONE: 5,
      IP_ADDRESS: 4
    };

    // Sort by start index ascending, then length descending, then priority descending
    allMatches.sort((a, b) => {
      if (a.start !== b.start) return a.start - b.start;
      const lenA = a.end - a.start;
      const lenB = b.end - b.start;
      if (lenA !== lenB) return lenB - lenA;
      return (priority[b.type] || 0) - (priority[a.type] || 0);
    });

    // Remove overlapping matches (take the highest priority/longest match)
    const nonOverlapping = [];
    let lastEnd = -1;

    for (const match of allMatches) {
      if (match.start >= lastEnd) {
        nonOverlapping.push(match);
        lastEnd = match.end;
      } else {
        // If it starts before lastEnd, it overlaps.
        // If current match has significantly higher priority and covers similar span, handle gracefully
        const prev = nonOverlapping[nonOverlapping.length - 1];
        if (prev && (priority[match.type] || 0) > (priority[prev.type] || 0) && (match.end > prev.end)) {
          // Replace prev
          nonOverlapping[nonOverlapping.length - 1] = match;
          lastEnd = match.end;
        }
      }
    }

    return nonOverlapping;
  }

  /**
   * Main redact method
   * Returns: {
   *   original: string,
   *   redacted: string,
   *   matches: Array,
   *   stats: Object,
   *   riskScore: string
   * }
   */
  redact(text) {
    if (!text || typeof text !== 'string') {
      return {
        original: text || '',
        redacted: text || '',
        matches: [],
        stats: { total: 0, byType: {} },
        riskScore: 'LOW'
      };
    }

    const matches = this.scan(text);
    const byType = {};
    const valueToId = new Map();
    const typeCounters = {};

    // Track statistics and assign index identifiers for INDEXED masking
    for (const match of matches) {
      byType[match.type] = (byType[match.type] || 0) + 1;

      if (!typeCounters[match.type]) typeCounters[match.type] = 0;
      if (!valueToId.has(match.value)) {
        typeCounters[match.type]++;
        valueToId.set(match.value, typeCounters[match.type]);
      }
      match.indexId = valueToId.get(match.value);
    }

    // Determine replacement mask based on style
    const getMask = (match) => {
      const type = match.type;
      const p = this.options.labelPrefix;
      const s = this.options.labelSuffix;

      switch (this.options.maskStyle) {
        case 'INDEXED':
          return `${p}${type}_${match.indexId}${s}`;
        case 'PARTIAL':
          return formatPartialMask(type, match.value);
        case 'BLOCK':
          return '█'.repeat(Math.min(match.value.length, 12));
        case 'REDACTED':
          return `${p}REDACTED${s}`;
        case 'LABEL':
        default:
          return `${p}${type}${s}`;
      }
    };

    // Reconstruct text with replacements
    let result = '';
    let lastIndex = 0;

    for (const match of matches) {
      result += text.slice(lastIndex, match.start);
      const mask = getMask(match);
      match.mask = mask;
      result += mask;
      lastIndex = match.end;
    }
    result += text.slice(lastIndex);

    // Calculate privacy risk score based on detected items
    let riskScore = 'LOW';
    const total = matches.length;
    if (byType['CARD'] || byType['SSN'] || byType['API_KEY'] || byType['SECRET']) {
      riskScore = 'CRITICAL';
    } else if (byType['PHONE'] || byType['EMAIL']) {
      riskScore = total > 2 ? 'HIGH' : 'MEDIUM';
    } else if (total > 0) {
      riskScore = 'MEDIUM';
    }

    return {
      original: text,
      redacted: result,
      matches,
      stats: {
        total,
        byType
      },
      riskScore
    };
  }
}

// Universal module export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    Redactor,
    luhnCheck,
    getCardBrand,
    formatPartialMask
  };
}

if (typeof window !== 'undefined') {
  window.PresendRedactor = {
    Redactor,
    luhnCheck,
    getCardBrand,
    formatPartialMask
  };
}

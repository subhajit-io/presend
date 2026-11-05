'use strict';
/**
 * Presend v2.0 — Unit Test Suite
 * Tests the browser-side redaction logic (pure JS, no DOM)
 */

const assert = require('assert');

// ---- Minimal stubs to run browser-side logic without a DOM ------------------
// Inline copies of the sets and functions from index.html

const ADDRESS_SUFFIXES = new Set([
  'road','rd','street','st','avenue','ave','lane','ln','drive',
  'nagar','colony','marg','chowk','vihar','enclave','apartment','apartments',
  'apts','society','layout','cross','main','sector','block','phase',
  'tower','towers','building','bldg','plaza','hospital','clinic','bank',
  'park','gardens','heights','court','circle','square','place','trail',
  'blvd','boulevard','way','terrace','crescent','close','grove','vale',
]);

const HONORIFICS = new Set(['mr','mrs','ms','miss','dr','prof','rev','shri','smt','sri','shr','km']);

const FUNCTIONAL_WORDS = new Set([
  'i','me','my','myself','we','us','our','ours','ourselves',
  'you','your','yours','yourself','yourselves',
  'he','him','his','himself','she','her','hers','herself',
  'it','its','itself','they','them','their','theirs','themselves',
  'this','that','these','those','who','whom','whose','which','what',
  'a','an','the','some','any','no','every','each','either','neither',
  'all','both','few','many','much','more','most','other','another','such',
  'and','but','or','nor','so','yet','for','although','because','since',
  'while','unless','until','though','whether','if','when','where','how','why',
  'at','in','on','to','of','for','from','with','by','about','as',
  'into','through','over','under','above','below','between','among',
  'after','before','during','within','without','against','along',
  'around','behind','beside','beyond','despite','except','near','off',
  'onto','out','outside','per','plus','since','than','throughout',
  'toward','towards','upon','via','versus','vs',
  'is','are','was','were','be','been','being',
  'have','has','had','having','do','does','did','done','doing',
  'will','would','shall','should','may','might','must','can','could',
  'need','dare','ought','used',
  'not','very','just','also','too','already','still','even','only',
  'then','now','here','there','always','often','never','sometimes',
  'really','quite','rather','almost','again','once','twice',
  'please','well','okay','ok','yes','no','hi','hello','hey','oh','ah',
]);

const DATA_LABELS = new Set([
  'email','mail','password','passwd','pwd','secret','token','key',
  'username','user','handle','login','phone','mobile','tel','cell',
  'address','pin','pincode','zip','zipcode','otp','pan','upi',
  'aadhaar','aadhar','account','acc','id','num','number','card',
  'total','amount','cost','price','rs','inr','usd','eur','gbp',
  'item','items','stuff','office','home','work','flat','details',
  'info','information','data','note','notes','message','msg',
  'name','contact','signature',
]);

const COMMON_PREDICATES = new Set([
  'fine','good','great','bad','well','sick','tired','ready','happy','sad',
  'sorry','here','there','busy','late','early','sure','okay','ok','alive',
  'back','free','done','home','away','out','in','lost','found','safe',
  'grateful','thankful','excited','nervous','worried','confused',
  'writing','working','going','coming','waiting','thinking','trying',
  'available','unavailable','online','offline','active','inactive',
  'correct','wrong','right','serious','joking','your','friend',
  'student','teacher','manager','owner','a','an','the',
]);

const INTRO_TWO_WORD = new Set([
  'i am',"i'm",'name is','this is','call me','i go','go by',
  'meet me','known as','my name','her name','his name','their name',
  'your name','introduce myself','everyone call',
]);
const INTRO_ONE_WORD = new Set(['iam',"i'm",'introduce','introducing','presenting']);

function isFunctionWord(word) {
  const wl = word.toLowerCase();
  return FUNCTIONAL_WORDS.has(wl) || DATA_LABELS.has(wl) || HONORIFICS.has(wl);
}

function isAcronym(word) {
  // Any all-caps token of 2 to 10 letters/digits (e.g. BTECH, CSE, AIML, NASA, UPSC, HTML5, PII, IIT, NEET, etc.)
  return /^[A-Z0-9]{2,10}$/.test(word) && !/^\d+$/.test(word);
}

function isArtifactOrTool(word, prevWord, prev2Word) {
  const prevIsAcronym = isAcronym(prevWord);
  const prevLower = prevWord.toLowerCase();
  const prev2Lower = prev2Word ? prev2Word.toLowerCase() : '';
  const isDemonstrative = ['this', 'that', 'these', 'those'].includes(prevLower) ||
                          (['this', 'that', 'these', 'those'].includes(prev2Lower) && prevIsAcronym);
  if (isDemonstrative || prevIsAcronym) return true;

  const wl = word.toLowerCase();
  if (/(?:or|er|ware|base|tion|sion|ment|sys)$/.test(wl) && ['a', 'an', 'the', 'our', 'new', 'my'].includes(prevLower)) {
    return true;
  }
  return false;
}

const ARTIFACT_NOUNS = new Set([
  'redactor', 'app', 'application', 'tool', 'project', 'software', 'bot', 'model',
  'system', 'extension', 'program', 'algorithm', 'plugin', 'module', 'package',
  'library', 'device', 'game', 'repo', 'repository', 'site', 'website', 'service',
  'database', 'table', 'code', 'script', 'file', 'folder', 'utility', 'api',
  'framework', 'platform', 'agent', 'product', 'workflow', 'pipeline', 'engine', 'dataset'
]);

function isArtifactContext(prevWord, prev2Word) {
  const p1 = prevWord ? prevWord.toLowerCase() : '';
  const p2 = prev2Word ? prev2Word.toLowerCase() : '';
  if (ARTIFACT_NOUNS.has(p1) || ARTIFACT_NOUNS.has(p2)) return true;
  if (/(?:or|er|ware|base|tion|sion|ment|sys)$/.test(p2) && (isAcronym(prevWord) || ['this', 'that', 'our', 'my', 'the', 'a', 'an'].includes(p1))) return true;
  return false;
}

function luhnCheck(str) {
  const digits = str.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0, dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = parseInt(digits[i], 10);
    if (dbl && (d *= 2) > 9) d -= 9;
    sum += d; dbl = !dbl;
  }
  return sum % 10 === 0;
}

// ---- Pattern definitions (mirror of index.html PATTERNS) -------------------
const PATTERNS = [
  { regex: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, tag: '[EMAIL]', stat: 'email' },
  { regex: /\bey[A-Za-z0-9_\-]+\.ey[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b/g, tag: '[API_KEY]', stat: 'secret' },
  { regex: /\bBearer\s+[A-Za-z0-9\-._~+\/]+=*/gi, tag: '[API_KEY]', stat: 'secret' },
  { regex: /\bsk-[A-Za-z0-9_\-]{20,}\b/g, tag: '[API_KEY]', stat: 'secret' },
  { regex: /\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b/g, tag: '[API_KEY]', stat: 'secret' },
  { regex: /\bAKIA[0-9A-Z]{16}\b/g, tag: '[API_KEY]', stat: 'secret' },
  { regex: /mongodb(?:\+srv)?:\/\/[^\s"'<>]+/gi, tag: '[DB_URI]', stat: 'secret' },
  { regex: /((?:password|passwd|pwd|secret|api[_\-]?key|token|auth|credentials?)\s*[:=]\s*["']?)[^\s"'\n\r,;]{3,}/gi, tag: '[PASSWORD]', stat: 'secret', replaceGroup: 1 },
  { regex: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g, tag: '[PAN]', stat: 'id' },
  // Cards before Aadhaar
  { regex: /\b(?:\d[\s\-]?){13,19}\d\b/g, tag: '[CARD]', stat: 'secret', validate: (m) => luhnCheck(m) },
  { regex: /(?<![+\d])[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}(?!\d)/g, tag: '[AADHAAR]', stat: 'id' },
  { regex: /\b[A-PR-WY][1-9]\d{6}\b/g, tag: '[PASSPORT]', stat: 'id' },
  { regex: /\b[a-zA-Z0-9.\-_]{2,}@(okaxis|oksbi|okhdfcbank|okicici|paytm|ybl|ibl|axl|upi|sbi|hdfcbank|icici|barodampay|pnb|postbank|apl|rapl|freecharge|airtel|gpay|idfcbank|kotak|hsbc)\b/gi, tag: '[UPI_ID]', stat: 'id' },
  { regex: /@[A-Za-z0-9_.\-]{3,30}\b/g, tag: '[USERNAME]', stat: 'id' },
  { regex: /((?:username|user|handle|login)\s*[:=]\s*["']?)[A-Za-z0-9_.\-]{3,30}\b/gi, tag: '[USERNAME]', stat: 'id', replaceGroup: 1 },
  { regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b/g, tag: '[IBAN]', stat: 'id' },
  { regex: /(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])/g, tag: '[PRIVATE_KEY]', stat: 'secret' },
  { regex: /(?:(?:\+|00)91[\s\-]?|91[\s\-]?|0)?[6-9]\d{9}\b/g, tag: '[PHONE]', stat: 'phone' },
  { regex: /(?:\+1[\s\-]?)?\(?[2-9]\d{2}\)?[\s\-]?[2-9]\d{2}[\s\-]?\d{4}\b/g, tag: '[PHONE]', stat: 'phone' },
  { regex: /\+[1-9]\d{1,14}\b/g, tag: '[PHONE]', stat: 'phone' },
  { regex: /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g, tag: '[IP_ADDR]', stat: 'secret' },
];

function findRegexSpans(text) {
  const acceptedSpans = [];
  function overlaps(start, end) {
    return acceptedSpans.some(s => (start < s.end && end > s.start));
  }

  for (const p of PATTERNS) {
    const re = new RegExp(p.regex.source, p.regex.flags);
    let m;
    while ((m = re.exec(text)) !== null) {
      let fullMatch = m[0];
      let targetStart = m.index;
      let targetText = fullMatch;
      if (p.replaceGroup !== undefined) {
        const prefix = m[p.replaceGroup] || '';
        targetStart += prefix.length;
        targetText = fullMatch.slice(prefix.length);
      }
      if (p.validate && !p.validate(targetText)) {
        if (m.index === re.lastIndex) re.lastIndex++;
        continue;
      }
      const targetEnd = targetStart + targetText.length;
      if (targetEnd <= targetStart) {
        if (m.index === re.lastIndex) re.lastIndex++;
        continue;
      }
      if (!overlaps(targetStart, targetEnd)) {
        acceptedSpans.push({
          start: targetStart,
          end: targetEnd,
          originalText: targetText,
          defaultMask: p.tag,
          stat: p.stat,
          category: p.tag.replace(/[\[\]]/g, ''),
        });
      }
      if (m.index === re.lastIndex) re.lastIndex++;
    }
  }
  acceptedSpans.sort((a, b) => a.start - b.start);
  return acceptedSpans;
}

function tokenizeTextWithSpans(text, spans) {
  const tokens = [];
  let curIdx = 0;
  let nextId = 0;

  for (const span of spans) {
    if (span.start > curIdx) {
      const seg = text.slice(curIdx, span.start);
      tokenizeSegment(seg, curIdx, tokens);
    }
    tokens.push({
      id: nextId++,
      start: span.start,
      end: span.end,
      originalText: span.originalText,
      text: span.originalText,
      isWord: true,
      isRegex: true,
      isPreMasked: true,
      masked: true,
      mask: span.defaultMask,
      category: span.category,
      stat: span.stat,
    });
    curIdx = span.end;
  }

  if (curIdx < text.length) {
    const seg = text.slice(curIdx);
    tokenizeSegment(seg, curIdx, tokens);
  }

  function tokenizeSegment(seg, offset, outList) {
    const subRe = /(\[[A-Za-z_]+\]|\s+|[^\s\w]+|\w+)/g;
    let m;
    while ((m = subRe.exec(seg)) !== null) {
      const raw = m[0];
      const isPreMasked = /^\[[A-Za-z_]+\]$/.test(raw);
      const isWord = !isPreMasked && /^\w+$/.test(raw);
      const tStart = offset + m.index;
      const tEnd = tStart + raw.length;
      outList.push({
        id: nextId++,
        start: tStart,
        end: tEnd,
        originalText: raw,
        text: raw,
        isWord: isWord,
        isRegex: false,
        isPreMasked: isPreMasked,
        masked: isPreMasked,
        mask: isPreMasked ? raw : '[REDACTED]',
        category: isPreMasked ? 'PII' : 'Text',
      });
    }
  }

  return tokens;
}

function buildSentenceStartSet(tokens) {
  const startIds = new Set();
  let afterBoundary = true, lastWordLower = '';
  for (const t of tokens) {
    const raw = t.text;
    if (raw === '!' || raw === '?' || raw === '\n') { afterBoundary = true; }
    else if (raw === '.') { afterBoundary = !HONORIFICS.has(lastWordLower); }
    else if (t.isWord) {
      lastWordLower = raw.toLowerCase();
      if (afterBoundary) { startIds.add(t.id); afterBoundary = false; }
    }
  }
  return startIds;
}

function classifyNames(tokens, overrides = {}) {
  const customWordRules = overrides.customWordRules || new Map();
  const labelOverrides = overrides.labelOverrides || new Map();
  const unmaskedIds = overrides.unmaskedIds || new Set();

  const wordsOnly = tokens.filter(t => t.isWord);
  const startIds = buildSentenceStartSet(tokens);
  for (let i = 0; i < wordsOnly.length; i++) {
    const t = wordsOnly[i];
    const rawWord = t.text;
    const wl = rawWord.toLowerCase();

    if (unmaskedIds.has(t.id)) {
      t.masked = false;
      continue;
    }

    if (customWordRules.has(wl)) {
      t.masked = true;
      t.mask = customWordRules.get(wl);
      t.category = 'Custom';
      continue;
    }

    if (t.isPreMasked) {
      if (labelOverrides.has(t.id)) t.mask = labelOverrides.get(t.id);
      continue;
    }

    if (/^X+([a-z]{0,4})?$/.test(rawWord)) continue;
    if (/^X+(st|nd|rd|th)?$/.test(rawWord)) continue;

    const prevWord = i > 0 ? wordsOnly[i-1].text : '';
    const prevLower = prevWord.toLowerCase();
    const prev2Word = i > 1 ? wordsOnly[i-2].text : '';
    const prevTwo = (prev2Word.toLowerCase() + ' ' + prevLower).trim();
    const isSentStart = startIds.has(t.id);

    const customLabel = labelOverrides.get(t.id) || '[Name]';
    const customAddr = labelOverrides.get(t.id) || '[ADDRESS]';

    // Address suffix detection
    if (ADDRESS_SUFFIXES.has(wl)) {
      t.masked = true; t.mask = customAddr;
      if (i > 0) { const p = wordsOnly[i-1]; if (!p.masked && /^[A-Z]/.test(p.text) && !/^X/.test(p.text)) { p.masked = true; p.mask = labelOverrides.get(p.id) || '[ADDRESS]'; } }
      continue;
    }

    // Location / Living context: "live in <Place>", "from <Place>"
    const isLocationContext = (
      ['live in', 'lives in', 'living in', 'stay in', 'stays in', 'staying in', 'reside in', 'resides in', 'residing in', 'located in', 'born in', 'moved to', 'moving to', 'travel to', 'traveling to', 'travelled to', 'native of', 'native to', 'trip to', 'flew to', 'flying to'].includes(prevTwo) ||
      (['from', 'near', 'around'].includes(prevLower) && !['away'].includes(prev2Word.toLowerCase()))
    );
    if (isLocationContext && /^[A-Z]/.test(rawWord) && !isFunctionWord(rawWord) && !isAcronym(rawWord)) {
      t.masked = true; t.mask = customAddr;
      continue;
    }

    // Honorific-preceded name: Dr. Sharma
    if (HONORIFICS.has(prevLower) && /^[A-Z]/.test(rawWord)) { t.masked = true; t.mask = customLabel; continue; }

    if (isFunctionWord(rawWord)) continue;
    if (isAcronym(rawWord)) continue;

    // Artifact, software, or tool (e.g. "this PII Redactor", "AI Model", "this Tool")
    if (isArtifactOrTool(rawWord, prevWord, prev2Word)) {
      continue;
    }
    if (isArtifactContext(prevWord, prev2Word)) {
      continue;
    }

    // Introduction context: "I am Ravi", "call me Priya"
    const isNamedOrCalled = ['named', 'called'].includes(prevLower) && !isArtifactContext(prevWord, prev2Word);
    const isIntro = INTRO_TWO_WORD.has(prevTwo) || INTRO_ONE_WORD.has(prevLower) || isNamedOrCalled;
    if (isIntro && !COMMON_PREDICATES.has(wl) && !isFunctionWord(rawWord)) {
      t.masked = true; t.mask = customLabel; continue;
    }

    // Mid-sentence capitalized proper noun
    if (/^[A-Z]/.test(rawWord)) {
      if (isSentStart) continue;
      if (isFunctionWord(rawWord) || isAcronym(rawWord)) continue;
      if (isArtifactOrTool(rawWord, prevWord, prev2Word)) continue;
      if (isArtifactContext(prevWord, prev2Word)) continue;
      t.masked = true; t.mask = customLabel; continue;
    }

    // Lowercase name in intro context
    if (isIntro && !COMMON_PREDICATES.has(wl) && wl.length > 1) {
      if (!FUNCTIONAL_WORDS.has(wl) && !DATA_LABELS.has(wl) && !COMMON_PREDICATES.has(wl)) {
        t.masked = true; t.mask = customLabel;
      }
    }
  }
}

function maskDigits(tokens) {
  for (const t of tokens) {
    if (!t.isWord || t.masked || t.isPreMasked) continue;
    t.text = t.text.replace(/[0-9]/g, 'X');
  }
}

function redact(text, overrides = {}) {
  if (!text) return '';
  const spans = findRegexSpans(text);
  const tokens = tokenizeTextWithSpans(text, spans);
  classifyNames(tokens, overrides);
  maskDigits(tokens);
  return tokens.map(t => t.masked ? t.mask : t.text).join('');
}

function getTokens(text, overrides = {}) {
  if (!text) return [];
  const spans = findRegexSpans(text);
  const tokens = tokenizeTextWithSpans(text, spans);
  classifyNames(tokens, overrides);
  maskDigits(tokens);
  return tokens;
}

// ---- TESTS ------------------------------------------------------------------
let pass = 0, fail = 0;

function test(description, input, expected) {
  const result = redact(input);
  if (result === expected) {
    console.log('  Pass: ' + description);
    pass++;
  } else {
    console.error('  FAIL: ' + description);
    console.error('    Input:    ' + input);
    console.error('    Expected: ' + expected);
    console.error('    Got:      ' + result);
    fail++;
  }
}

console.log('\nPresend v2.0 — Unit Test Suite\n');

// ---- Name detection tests
test('I am fine — predicate not masked',    'I am fine',  'I am fine');
test('I am going — predicate not masked',   'I am going', 'I am going');
test('I am here — predicate not masked',    'I am here',  'I am here');
test('I am Krish — intro name masked',      'I am Krish', 'I am [Name]');
test('I am krish — lowercase intro masked', 'I am krish', 'I am [Name]');
test('call me Priya — masked',              'call me Priya', 'call me [Name]');
test('My name is Rohit — masked',           'My name is Rohit', 'My name is [Name]');
test('Dr. Sharma — honorific masked',       'Dr. Sharma visited', 'Dr. [Name] visited');
test('Mr. Kapoor — honorific masked',       'Mr. Kapoor called', 'Mr. [Name] called');
test('Mid-sentence Vishal masked',          'shopping in the Vishal', 'shopping in the [Name]');
test('TechCorp mid-sentence masked',        'The company is TechCorp', 'The company is [Name]');
test('Sentence starter not masked',         'Delivered quickly', 'Delivered quickly');
test('USA acronym not masked',              'USA is a country',  'USA is a country');
test('API acronym not masked',              'The API is ready',  'The API is ready');
test('HTTP acronym not masked',             'HTTP requests fail', 'HTTP requests fail');
test('Any dynamic unlisted acronyms (NEET, UPSC, ISRO, GDPR, IIT)', 'Studying for NEET and UPSC at IIT with ISRO under GDPR.', 'Studying for NEET and UPSC at IIT with ISRO under GDPR.');
test('Demonstrative tool artifact not masked (this Tool, that Scanner)', 'I built this Tool and developed that Scanner', 'I built this Tool and developed that Scanner');

// ---- Digit tests
test('Digits → X',                          'I have 5000rs',      'I have XXXXrs');
test('Multiple digits',                     '30rs for shopping',  'XXrs for shopping');
test('Date digits',                         'On 2026-11-05',      'On XXXX-XX-XX');

// ---- Email
test('Email redacted',    'mail: test@example.com',  'mail: [EMAIL]');
test('Email in sentence', 'email me at a@b.co now',  'email me at [EMAIL] now');

// ---- Phone
test('Indian 10-digit phone',  'Phone: 9876543210',      'Phone: [PHONE]');
test('Phone with +91',         'Call +919876543210',     'Call [PHONE]');

// ---- IDs
test('PAN redacted',     'PAN: ABCDE1234F',                'PAN: [PAN]');
test('UPI redacted',     'UPI: alice@okaxis',              'UPI: [UPI_ID]');
test('Aadhaar redacted', 'Aadhaar: 2345 6789 0123',       'Aadhaar: [AADHAAR]');
test('Username @handle', 'Contact @dev_user',              'Contact [USERNAME]');

// ---- Secrets
test('Password field',   'password: mySecret123',          'password: [PASSWORD]');
test('sk- API key',      'key: sk-abcdefghij12345678901234', 'key: [API_KEY]');
test('IP address',       'IP: 192.168.1.1',                'IP: [IP_ADDR]');
test('Credit card Luhn', 'Card: 4111 1111 1111 1111',      'Card: [CARD]');
test('IBAN',             'IBAN: GB29NWBK60161331926819',   'IBAN: [IBAN]');

// ---- Address
test('Address suffix detection', 'Greenfield Apts on MG Road', '[ADDRESS] [ADDRESS] on [ADDRESS] [ADDRESS]');
test('Location context: live in Arambagh', 'I live in Arambagh', 'I live in [ADDRESS]');

// ---- Sentence boundary
test('Sentence start capital not masked', 'Delivered quickly. Vishal came.', 'Delivered quickly. Vishal came.');
test('Mid-sentence proper noun masked',   'Please call Rahul tomorrow.',     'Please call [Name] tomorrow.');

// ---- Complex sentence with PII Redactor
test('User screenshot test case with Redactor and Arambagh',
  'Hello my name is Krish. I live in Arambagh. I study about BTECH CSE AIML. My phone number is +91 7001023356. I made this PII Redactor named Mask.',
  'Hello my name is [Name]. I live in [ADDRESS]. I study about BTECH CSE AIML. My phone number is [PHONE]. I made this PII Redactor named Mask.');

// ---- Conversion tracking, position exactness & dynamic stats count tests
function testTrackingAndOverrides() {
  const sample = 'Hello my name is Krish. I live in Arambagh. My phone number is +91 7001023356.';
  const tokens = getTokens(sample);

  // 1. Verify character slice matches originalText 100%
  let sliceErrors = 0;
  for (const t of tokens) {
    if (sample.slice(t.start, t.end) !== t.originalText) {
      sliceErrors++;
    }
  }
  if (sliceErrors === 0) {
    console.log('  Pass: Position-aware tokens match exact character slices');
    pass++;
  } else {
    console.error('  FAIL: Position-aware tokens have slice mismatches');
    fail++;
  }

  // 2. Custom label override test (e.g. rename [Name] to [Candidate])
  const krishToken = tokens.find(t => t.originalText === 'Krish');
  assert(krishToken, 'Krish token should exist');
  const labelOverrides = new Map([[krishToken.id, '[Candidate]']]);
  const customizedOutput = redact(sample, { labelOverrides });
  if (customizedOutput.includes('[Candidate]') && !customizedOutput.includes('[Name]')) {
    console.log('  Pass: Custom mask label override applies successfully');
    pass++;
  } else {
    console.error('  FAIL: Custom mask label override failed');
    fail++;
  }

  // 3. Unmask / delete mask test (e.g. unmasking Arambagh)
  const arambaghToken = tokens.find(t => t.originalText === 'Arambagh');
  assert(arambaghToken, 'Arambagh token should exist');
  const unmaskedIds = new Set([arambaghToken.id]);
  const unmaskedOutput = redact(sample, { unmaskedIds });
  if (unmaskedOutput.includes('Arambagh') && !unmaskedOutput.includes('[ADDRESS]')) {
    console.log('  Pass: Unmask / delete mask restores original word');
    pass++;
  } else {
    console.error('  FAIL: Unmask / delete mask failed');
    fail++;
  }

  // 4. Custom word masking rule test (e.g. mask shopping as [ACTIVITY])
  const customWordRules = new Map([['shopping', '[ACTIVITY]']]);
  const customWordOutput = redact('I spent 30rs for shopping in the market', { customWordRules });
  if (customWordOutput.includes('[ACTIVITY]')) {
    console.log('  Pass: Custom word rule masks arbitrary word with custom tag');
    pass++;
  } else {
    console.error('  FAIL: Custom word rule failed');
    fail++;
  }

  // 5. Dynamic count verification for Name, Address, Phone
  const complexText = 'Hello my name is Krish. I live in Arambagh. I study about BTECH CSE AIML. My phone number is +91 7001023356. I made this PII Redactor named Mask.';
  const complexTokens = getTokens(complexText);
  const nameTokens = complexTokens.filter(t => t.masked && t.mask === '[Name]');
  const addrTokens = complexTokens.filter(t => t.masked && t.mask === '[ADDRESS]');
  const phoneTokens = complexTokens.filter(t => t.masked && t.mask === '[PHONE]');
  if (nameTokens.length === 1 && addrTokens.length === 1 && phoneTokens.length === 1) {
    console.log('  Pass: Dynamic category counts exact: Names: 1, Addresses: 1, Phones: 1');
    pass++;
  } else {
    console.error(`  FAIL: Dynamic category count mismatch: Names=${nameTokens.length}, Addr=${addrTokens.length}, Phone=${phoneTokens.length}`);
    fail++;
  }
}

testTrackingAndOverrides();

console.log('\nResults: ' + pass + '/' + (pass + fail) + ' tests passed.');
if (fail > 0) process.exit(1);

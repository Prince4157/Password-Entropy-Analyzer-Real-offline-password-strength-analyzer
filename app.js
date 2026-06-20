/* ============================================================
   Password Entropy Analyzer — Core Application Logic
   ============================================================
   100% client-side. No passwords are logged, stored, or sent.
   ============================================================ */

// --------------- Library Imports (Local ESM) ---------------
import { ZxcvbnFactory } from '@zxcvbn-ts/core';
import * as zxcvbnCommonPackage from '@zxcvbn-ts/language-common';
import * as zxcvbnEnPackage from '@zxcvbn-ts/language-en';

// --------------- zxcvbn Configuration ---------------
const options = {
  dictionary: {
    ...zxcvbnCommonPackage.dictionary,
    ...zxcvbnEnPackage.dictionary,
  },
  graphs: zxcvbnCommonPackage.adjacencyGraphs,
  translations: zxcvbnEnPackage.translations,
};
const zxcvbn = new ZxcvbnFactory(options);

// --------------- Constants ---------------
const ATTACK_VECTORS = [
  { name: 'Online, Rate-Limited', detail: 'Banking login w/ lockouts', rate: 10 },
  { name: 'Online, No Rate Limiting', detail: 'Web app w/o throttling', rate: 1_000 },
  { name: 'Offline, Slow Hash', detail: 'bcrypt / argon2 (salted)', rate: 50_000 },
  { name: 'Offline, Fast Hash', detail: 'Unsalted MD5 / SHA-1', rate: 10_000_000_000 },
  { name: 'Dedicated Cracking Rig', detail: 'Nation-state / GPU farm', rate: 100_000_000_000 },
];

const PATTERN_LABELS = {
  dictionary: 'Dictionary Word',
  spatial: 'Keyboard Pattern',
  repeat: 'Repeated Characters',
  sequence: 'Sequential Characters',
  date: 'Date Pattern',
  bruteforce: 'Random (Brute Force)',
  regex: 'Regex Match',
};

const PATTERN_CSS_CLASS = {
  dictionary: 'dictionary',
  spatial: 'spatial',
  repeat: 'repeat',
  sequence: 'sequence',
  date: 'date',
  bruteforce: 'bruteforce',
  regex: 'regex',
};

const AGE_OF_UNIVERSE_SECONDS = 13.8e9 * 365.25 * 24 * 3600; // ~4.35e17 seconds

// --------------- DOM Elements ---------------
const $ = (id) => document.getElementById(id);

const passwordInput = $('password-input');
const toggleVisibility = $('toggle-visibility');
const eyeIconOff = $('eye-icon-off');
const eyeIconOn = $('eye-icon-on');
const statsBar = $('stats-bar');
const statLength = $('stat-length');
const statPool = $('stat-pool');
const statSets = $('stat-sets');
const analysisResults = $('analysis-results');
const placeholderState = $('placeholder-state');
const naiveEntropyEl = $('naive-entropy');
const effectiveEntropyEl = $('effective-entropy');
const gapBarNaive = $('gap-bar-naive');
const gapBarEffective = $('gap-bar-effective');
const gapLabel = $('gap-label');
const entropyExplanation = $('entropy-explanation');
const gaugeFill = $('gauge-fill');
const gaugeTime = $('gauge-time');
const patternToggle = $('pattern-toggle');
const patternCount = $('pattern-count');
const patternList = $('pattern-list');
const collapseIcon = $('collapse-icon');
const crackTimeGrid = $('crack-time-grid');
const btnCopyReport = $('btn-copy-report');
const btnHibpCheck = $('btn-hibp-check');
const hibpResult = $('hibp-result');
const improvementSuggestion = $('improvement-suggestion');
const copyToast = $('copy-toast');
const themeToggle = $('theme-toggle');
const themeIconMoon = $('theme-icon-moon');
const themeIconSun = $('theme-icon-sun');

// --------------- Utility: Debounce ---------------
function debounce(fn, delay) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}

// --------------- Naive Entropy Calculation ---------------
function computeNaiveEntropy(password) {
  if (!password.length) return { entropy: 0, poolSize: 0, sets: [] };

  let poolSize = 0;
  const sets = [];

  if (/[a-z]/.test(password)) { poolSize += 26; sets.push('a-z'); }
  if (/[A-Z]/.test(password)) { poolSize += 26; sets.push('A-Z'); }
  if (/[0-9]/.test(password)) { poolSize += 10; sets.push('0-9'); }
  if (/[^a-zA-Z0-9]/.test(password)) { poolSize += 33; sets.push('symbols'); }

  const entropy = password.length * Math.log2(poolSize || 1);
  return { entropy, poolSize, sets };
}

// --------------- Time Formatting ---------------
function formatTime(seconds) {
  if (!isFinite(seconds) || seconds < 0) return { text: '—', tier: 'instant' };

  if (seconds < 1) return { text: 'instant', tier: 'instant' };
  if (seconds < 60) return { text: `${Math.round(seconds)} seconds`, tier: 'instant' };
  if (seconds < 3600) return { text: `${Math.round(seconds / 60)} minutes`, tier: 'weak' };
  if (seconds < 86400) return { text: `${Math.round(seconds / 3600)} hours`, tier: 'weak' };
  if (seconds < 86400 * 30) return { text: `${Math.round(seconds / 86400)} days`, tier: 'fair' };
  if (seconds < 86400 * 365.25) return { text: `${Math.round(seconds / (86400 * 30))} months`, tier: 'fair' };

  const years = seconds / (86400 * 365.25);
  if (years < 100) return { text: `${Math.round(years)} years`, tier: 'good' };
  if (years < 1_000) return { text: `${Math.round(years)} years`, tier: 'strong' };
  if (years < 1_000_000) return { text: `${formatLargeNumber(years)} years`, tier: 'strong' };
  if (years < 1e9) return { text: `${formatLargeNumber(years)} years`, tier: 'max' };
  if (years < 13.8e9) return { text: `${formatLargeNumber(years)} years`, tier: 'max' };

  return { text: 'longer than the age of the universe', tier: 'max' };
}

function formatLargeNumber(n) {
  if (n >= 1e15) return '∞';
  if (n >= 1e12) return `${(n / 1e12).toFixed(1)} trillion`;
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)} billion`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)} million`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)} thousand`;
  return Math.round(n).toLocaleString();
}

function formatGuesses(guesses) {
  if (guesses < 1000) return guesses.toString();
  if (guesses >= 1e15) return '> 10¹⁵';
  return formatLargeNumber(guesses);
}

// --------------- Gauge Calculations ---------------
function getGaugePercent(seconds) {
  // Log-scale mapping for the gauge
  // instant = 0%, 1 minute = 10%, 1 hour = 20%, 1 day = 30%,
  // 1 year = 50%, 100 years = 65%, 10k years = 80%, 1M years = 90%, universe = 100%
  if (seconds < 1) return 0;

  const logSec = Math.log10(seconds);
  // Map log10(seconds) from 0 to 18 → 0% to 100%
  const percent = Math.min(100, Math.max(0, (logSec / 18) * 100));
  return percent;
}

function getGaugeColor(seconds) {
  if (seconds < 3600) return 'var(--strength-instant)';          // < 1 hour
  if (seconds < 86400) return 'var(--strength-weak)';            // < 1 day
  if (seconds < 86400 * 365.25) return 'var(--strength-fair)';   // < 1 year
  if (seconds < 86400 * 365.25 * 100) return 'var(--strength-good)';   // < 100 years
  if (seconds < 86400 * 365.25 * 10000) return 'var(--strength-strong)'; // < 10k years
  return 'var(--strength-max)';
}

// --------------- Pattern Explanation Generator ---------------
function generateExplanation(sequence, naiveEntropy, effectiveEntropy) {
  if (!sequence || sequence.length === 0) {
    return 'Enter a password to see how its naive mathematical entropy compares to its real-world effective entropy after accounting for human-predictable patterns.';
  }

  const gap = naiveEntropy - effectiveEntropy;
  const parts = [];

  // Group patterns by type
  const patternTypes = {};
  for (const match of sequence) {
    const type = match.pattern;
    if (!patternTypes[type]) patternTypes[type] = [];
    patternTypes[type].push(match);
  }

  // Build explanation parts
  if (patternTypes.dictionary) {
    const words = patternTypes.dictionary.map(m => {
      let desc = `'${m.token}'`;
      if (m.l33t) desc += ' (with l33t substitutions)';
      if (m.reversed) desc += ' (reversed)';
      return desc;
    });
    parts.push(`a common dictionary word ${words.join(' and ')}`);
  }

  if (patternTypes.spatial) {
    const patterns = patternTypes.spatial.map(m => `'${m.token}'`);
    parts.push(`a keyboard pattern ${patterns.join(' and ')}`);
  }

  if (patternTypes.sequence) {
    const seqs = patternTypes.sequence.map(m => `'${m.token}'`);
    parts.push(`a predictable sequence ${seqs.join(' and ')}`);
  }

  if (patternTypes.repeat) {
    const reps = patternTypes.repeat.map(m => `'${m.token}'`);
    parts.push(`repeated characters ${reps.join(' and ')}`);
  }

  if (patternTypes.date) {
    const dates = patternTypes.date.map(m => `'${m.token}'`);
    parts.push(`a date pattern ${dates.join(' and ')}`);
  }

  if (patternTypes.regex) {
    const regexes = patternTypes.regex.map(m => `'${m.token}'`);
    parts.push(`a recognizable pattern ${regexes.join(' and ')}`);
  }

  // Build the sentence
  if (parts.length === 0 && patternTypes.bruteforce) {
    if (gap < 5) {
      return 'This password appears to be <strong>genuinely random</strong> — the naive and effective entropy are very close, meaning there are no detectable patterns that would help an attacker.';
    }
    return 'This password has minimal detectable patterns. The small entropy gap suggests it is <strong>close to random</strong>.';
  }

  if (parts.length === 0) {
    return 'No specific patterns were detected in this password.';
  }

  let explanation = `This password contains ${joinReadable(parts)}`;

  if (gap > 30) {
    explanation += `, which makes it <strong>dramatically easier to guess</strong> than its length suggests. An attacker using pattern-aware cracking would need far fewer guesses than brute force.`;
  } else if (gap > 15) {
    explanation += `, which <strong>significantly reduces</strong> its effective strength compared to a truly random password of the same length.`;
  } else if (gap > 5) {
    explanation += `, which <strong>somewhat reduces</strong> its effective strength. Consider adding more random characters.`;
  } else {
    explanation += `, but the overall strength is still reasonable due to length and complexity.`;
  }

  return explanation;
}

function joinReadable(arr) {
  if (arr.length === 0) return '';
  if (arr.length === 1) return arr[0];
  if (arr.length === 2) return `${arr[0]} and ${arr[1]}`;
  return arr.slice(0, -1).join(', ') + ', and ' + arr[arr.length - 1];
}

// --------------- Improvement Suggestion ---------------
function computeImprovementSuggestion(guesses, effectiveEntropy) {
  const targetCrackSeconds = 100 * 365.25 * 86400; // 100 years
  const slowHashRate = 50_000;
  const targetGuesses = targetCrackSeconds * slowHashRate;

  if (guesses >= targetGuesses) {
    improvementSuggestion.classList.remove('visible');
    return;
  }

  // How many additional random characters (from full 95-char pool) needed?
  const additionalBitsNeeded = Math.log2(targetGuesses) - effectiveEntropy;
  if (additionalBitsNeeded <= 0) {
    improvementSuggestion.classList.remove('visible');
    return;
  }

  const bitsPerChar = Math.log2(95); // ~6.57 bits per random printable ASCII char
  const additionalChars = Math.ceil(additionalBitsNeeded / bitsPerChar);

  improvementSuggestion.innerHTML = `
    <strong>💡 Improvement:</strong> Add <strong>${additionalChars} more random character${additionalChars > 1 ? 's' : ''}</strong>
    (mixed case, digits, symbols) to push the offline bcrypt/argon2 crack time past <strong>100 years</strong>.
    This would add ~${Math.round(additionalChars * bitsPerChar)} bits of effective entropy.
  `;
  improvementSuggestion.classList.add('visible');
}

// --------------- Render Functions ---------------
function renderCrackTimes(guesses) {
  crackTimeGrid.innerHTML = '';

  for (const vector of ATTACK_VECTORS) {
    const seconds = guesses / vector.rate;
    const { text, tier } = formatTime(seconds);

    const card = document.createElement('div');
    card.className = 'crack-time-card';
    card.innerHTML = `
      <div class="attack-info">
        <div class="attack-name">${vector.name}</div>
        <div class="attack-detail">${vector.detail} — ${formatRate(vector.rate)}/sec</div>
      </div>
      <div class="crack-time-value ${tier}" title="${seconds.toExponential(2)} seconds">${text}</div>
    `;
    crackTimeGrid.appendChild(card);
  }
}

function formatRate(rate) {
  if (rate >= 1e9) return `${(rate / 1e9).toFixed(0)}B`;
  if (rate >= 1e6) return `${(rate / 1e6).toFixed(0)}M`;
  if (rate >= 1e3) return `${(rate / 1e3).toFixed(0)}K`;
  return rate.toString();
}

function renderPatterns(sequence) {
  patternList.innerHTML = '';

  if (!sequence || sequence.length === 0) {
    patternCount.textContent = '0 patterns';
    return;
  }

  patternCount.textContent = `${sequence.length} pattern${sequence.length !== 1 ? 's' : ''}`;

  for (const match of sequence) {
    const type = match.pattern;
    const label = PATTERN_LABELS[type] || type;
    const cssClass = PATTERN_CSS_CLASS[type] || 'bruteforce';

    // Build detail string
    let detail = '';
    if (match.dictionaryName) detail += match.dictionaryName;
    if (match.l33t) detail += (detail ? ', ' : '') + 'l33t substitution';
    if (match.reversed) detail += (detail ? ', ' : '') + 'reversed';

    const item = document.createElement('div');
    item.className = 'pattern-item';
    item.innerHTML = `
      <div>
        <div class="pattern-token">${escapeHtml(match.token)}</div>
        ${detail ? `<div class="attack-detail" style="margin-top:2px">${escapeHtml(detail)}</div>` : ''}
      </div>
      <span class="pattern-type-badge ${cssClass}">${label}</span>
      <div class="pattern-guesses" title="${match.guesses.toExponential(2)} guesses">~${formatGuesses(match.guesses)} guesses</div>
    `;
    patternList.appendChild(item);
  }
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// --------------- Main Analysis ---------------
function analyze(password) {
  // Reset HIBP result on each analysis
  hibpResult.className = 'hibp-result';
  hibpResult.textContent = '';

  if (!password) {
    analysisResults.style.display = 'none';
    placeholderState.style.display = '';
    statsBar.style.display = 'none';
    improvementSuggestion.classList.remove('visible');
    return;
  }

  // Show results, hide placeholder
  analysisResults.style.display = '';
  placeholderState.style.display = 'none';
  statsBar.style.display = '';

  // Animate sections in
  document.querySelectorAll('#analysis-results .section').forEach(s => s.classList.add('visible'));

  // --- Naive entropy ---
  const { entropy: naiveEntropy, poolSize, sets } = computeNaiveEntropy(password);

  // --- zxcvbn analysis ---
  const result = zxcvbn.check(password);
  const guesses = result.guesses;
  const effectiveEntropy = Math.log2(guesses);

  // --- Stats bar ---
  statLength.textContent = password.length;
  statPool.textContent = poolSize;
  statSets.textContent = sets.length > 0 ? sets.join(', ') : '—';

  // --- Entropy comparison ---
  naiveEntropyEl.textContent = naiveEntropy.toFixed(1);
  effectiveEntropyEl.textContent = effectiveEntropy.toFixed(1);

  // Gap visualization
  const maxEntropy = Math.max(naiveEntropy, effectiveEntropy, 1);
  gapBarNaive.style.width = `${(naiveEntropy / maxEntropy) * 100}%`;
  gapBarEffective.style.width = `${(effectiveEntropy / maxEntropy) * 100}%`;

  const gap = naiveEntropy - effectiveEntropy;
  if (gap > 5) {
    gapLabel.textContent = `−${gap.toFixed(0)} bits`;
    gapLabel.classList.add('warning');
  } else {
    gapLabel.textContent = `≈ ${Math.abs(gap).toFixed(0)} bits gap`;
    gapLabel.classList.remove('warning');
  }

  // Explanation
  entropyExplanation.innerHTML = generateExplanation(result.sequence, naiveEntropy, effectiveEntropy);

  // --- Strength gauge (offline slow hash baseline) ---
  const slowHashSeconds = guesses / 50_000;
  const { text: gaugeTimeText } = formatTime(slowHashSeconds);
  const gaugePercent = getGaugePercent(slowHashSeconds);
  const gaugeColor = getGaugeColor(slowHashSeconds);

  gaugeFill.style.width = `${gaugePercent}%`;
  gaugeFill.style.background = gaugeColor;
  gaugeTime.textContent = gaugeTimeText;

  // --- Patterns ---
  renderPatterns(result.sequence);

  // --- Crack times ---
  renderCrackTimes(guesses);

  // --- Improvement suggestion ---
  computeImprovementSuggestion(guesses, effectiveEntropy);
}

// --------------- Event Handlers ---------------

// Debounced analysis
const debouncedAnalyze = debounce((pw) => analyze(pw), 150);

passwordInput.addEventListener('input', () => {
  debouncedAnalyze(passwordInput.value);
});

// Also handle paste
passwordInput.addEventListener('paste', () => {
  // Use setTimeout to get the pasted value after the paste event
  setTimeout(() => debouncedAnalyze(passwordInput.value), 10);
});

// Show/hide password toggle
toggleVisibility.addEventListener('click', () => {
  const isPassword = passwordInput.type === 'password';
  passwordInput.type = isPassword ? 'text' : 'password';
  eyeIconOff.style.display = isPassword ? 'none' : '';
  eyeIconOn.style.display = isPassword ? '' : 'none';
  toggleVisibility.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
  toggleVisibility.setAttribute('title', isPassword ? 'Hide password' : 'Show password');
  passwordInput.focus();
});

// Pattern list collapse/expand
patternToggle.addEventListener('click', () => {
  const isExpanded = patternList.classList.contains('expanded');
  patternList.classList.toggle('expanded');
  collapseIcon.classList.toggle('expanded');
  patternToggle.setAttribute('aria-expanded', !isExpanded);
});

patternToggle.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') {
    e.preventDefault();
    patternToggle.click();
  }
});

// Theme toggle
themeToggle.addEventListener('click', () => {
  const html = document.documentElement;
  const currentTheme = html.getAttribute('data-theme');
  const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', newTheme);

  themeIconMoon.style.display = newTheme === 'dark' ? '' : 'none';
  themeIconSun.style.display = newTheme === 'light' ? '' : 'none';

  // Store in sessionStorage only (not localStorage per spec)
  try { sessionStorage.setItem('theme', newTheme); } catch (_) { /* ignore */ }
});

// Restore theme from sessionStorage
try {
  const savedTheme = sessionStorage.getItem('theme');
  if (savedTheme) {
    document.documentElement.setAttribute('data-theme', savedTheme);
    themeIconMoon.style.display = savedTheme === 'dark' ? '' : 'none';
    themeIconSun.style.display = savedTheme === 'light' ? '' : 'none';
  }
} catch (_) { /* ignore */ }

// --------------- Copy Report (Stretch Goal) ---------------
btnCopyReport.addEventListener('click', async () => {
  const pw = passwordInput.value;
  if (!pw) return;

  const { entropy: naiveEntropy, poolSize, sets } = computeNaiveEntropy(pw);
  const result = zxcvbn.check(pw);
  const effectiveEntropy = Math.log2(result.guesses);

  let report = `Password Entropy Analysis Report\n`;
  report += `================================\n\n`;
  report += `Length: ${pw.length} characters\n`;
  report += `Character Pool: ${poolSize} (${sets.join(', ')})\n`;
  report += `Naive Entropy: ${naiveEntropy.toFixed(1)} bits\n`;
  report += `Effective Entropy: ${effectiveEntropy.toFixed(1)} bits\n`;
  report += `Gap: ${(naiveEntropy - effectiveEntropy).toFixed(1)} bits\n\n`;

  report += `Crack Times:\n`;
  for (const vector of ATTACK_VECTORS) {
    const seconds = result.guesses / vector.rate;
    const { text } = formatTime(seconds);
    report += `  ${vector.name} (${formatRate(vector.rate)}/sec): ${text}\n`;
  }

  report += `\nPatterns Detected: ${result.sequence.length}\n`;
  for (const match of result.sequence) {
    const label = PATTERN_LABELS[match.pattern] || match.pattern;
    report += `  [${label}] "${match.token}" — ~${formatGuesses(match.guesses)} guesses\n`;
  }

  report += `\n⚠️ The actual password is NOT included in this report.\n`;
  report += `Generated by Password Entropy Analyzer (100% client-side)`;

  try {
    await navigator.clipboard.writeText(report);
    showToast();
  } catch (_) {
    // Fallback
    const textarea = document.createElement('textarea');
    textarea.value = report;
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    showToast();
  }
});

function showToast() {
  copyToast.classList.add('visible');
  setTimeout(() => copyToast.classList.remove('visible'), 2200);
}

// --------------- HIBP Breach Check (Stretch Goal) ---------------
btnHibpCheck.addEventListener('click', async () => {
  const pw = passwordInput.value;
  if (!pw) return;

  hibpResult.className = 'hibp-result loading';
  hibpResult.textContent = 'Checking breach database…';

  try {
    // SHA-1 hash the password
    const encoder = new TextEncoder();
    const data = encoder.encode(pw);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

    const prefix = hashHex.slice(0, 5);
    const suffix = hashHex.slice(5);

    // k-anonymity: only send the first 5 chars of the hash
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {

      headers: { 'Add-Padding': 'true' }
    });

    if (!response.ok) throw new Error('API request failed');

    const text = await response.text();
    const lines = text.split('\n');

    let found = false;
    let count = 0;

    for (const line of lines) {
      const [hashSuffix, countStr] = line.split(':');
      if (hashSuffix.trim() === suffix) {
        count = parseInt(countStr.trim(), 10);
        found = count > 0;
        break;
      }
    }

    if (found) {
      hibpResult.className = 'hibp-result found';
      hibpResult.innerHTML = `⚠️ <strong>This password has been found in ${count.toLocaleString()} data breach${count !== 1 ? 'es' : ''}.</strong> You should not use this password.`;
    } else {
      hibpResult.className = 'hibp-result safe';
      hibpResult.innerHTML = `✅ <strong>Not found in any known data breaches.</strong> This doesn't guarantee it's safe — it just hasn't appeared in leaked datasets.`;
    }
  } catch (err) {
    hibpResult.className = 'hibp-result loading';
    hibpResult.textContent = `Could not check: ${err.message}. Only a SHA-1 prefix was sent.`;
  }
});

// --------------- Initialization ---------------
// Start in placeholder state
analyze('');

// Auto-expand pattern list on first analysis
let firstAnalysis = true;
const origAnalyze = analyze;
// We wrap analyze to auto-expand the pattern list the first time results appear
const originalInput = passwordInput.oninput;

// Focus password input on load
passwordInput.focus();

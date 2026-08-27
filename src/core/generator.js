/**
 * Password and passphrase generation, plus a strength estimate.
 *
 * Every random choice goes through rejection sampling so that character
 * classes stay uniformly distributed -- a plain `% n` on a random byte would
 * quietly bias the output towards the first characters of each set.
 */
import { randomBytes } from './crypto.js';
import { WORDS } from './wordlist.js';

export const CHARSETS = {
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?/',
};

/** Characters that are easy to misread when transcribing a password by hand. */
const AMBIGUOUS = new Set(['l', 'I', '1', 'O', '0', 'o', 'S', '5', 'B', '8']);

export const DEFAULT_OPTIONS = {
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  excludeAmbiguous: false,
};

export const MIN_LENGTH = 8;
export const MAX_LENGTH = 128;

/** Uniform integer in [0, max) -- no modulo bias. */
export function randomIndex(max) {
  if (!Number.isInteger(max) || max < 1) throw new Error('max must be a positive integer');
  if (max === 1) return 0;

  const byteCount = max <= 256 ? 1 : 2;
  const range = 256 ** byteCount;
  const limit = range - (range % max);

  for (;;) {
    let value = 0;
    for (const byte of randomBytes(byteCount)) value = value * 256 + byte;
    if (value < limit) return value % max;
  }
}

function buildPool(options) {
  let pool = '';
  for (const name of ['lowercase', 'uppercase', 'digits', 'symbols']) {
    if (options[name]) pool += CHARSETS[name];
  }
  if (options.excludeAmbiguous) {
    pool = [...pool].filter((char) => !AMBIGUOUS.has(char)).join('');
  }
  return pool;
}

/** Fisher-Yates using the same unbiased index source. */
function shuffle(items) {
  for (let i = items.length - 1; i > 0; i--) {
    const j = randomIndex(i + 1);
    [items[i], items[j]] = [items[j], items[i]];
  }
  return items;
}

/**
 * Generate a random password. Every enabled character class is guaranteed to
 * appear at least once, which is what most sites' complexity rules demand.
 */
export function generatePassword(overrides = {}) {
  const options = { ...DEFAULT_OPTIONS, ...overrides };
  const { length } = options;

  if (!Number.isInteger(length) || length < MIN_LENGTH || length > MAX_LENGTH) {
    throw new Error(`length must be an integer between ${MIN_LENGTH} and ${MAX_LENGTH}`);
  }

  const enabled = ['lowercase', 'uppercase', 'digits', 'symbols']
    .filter((name) => options[name])
    .map((name) => buildPool({ ...options, lowercase: false, uppercase: false, digits: false, symbols: false, [name]: true }))
    .filter((set) => set.length > 0);

  if (enabled.length === 0) throw new Error('at least one character class must be enabled');
  if (enabled.length > length) throw new Error('length is too short to include every character class');

  const pool = buildPool(options);
  const chars = enabled.map((set) => set[randomIndex(set.length)]);
  while (chars.length < length) chars.push(pool[randomIndex(pool.length)]);

  return shuffle(chars).join('');
}

export function generatePassphrase({ words = 4, separator = '-', capitalize = false, includeNumber = false } = {}) {
  if (!Number.isInteger(words) || words < 2 || words > 12) {
    throw new Error('words must be an integer between 2 and 12');
  }

  const picked = Array.from({ length: words }, () => {
    const word = WORDS[randomIndex(WORDS.length)];
    return capitalize ? word[0].toUpperCase() + word.slice(1) : word;
  });

  if (includeNumber) picked[randomIndex(picked.length)] += randomIndex(100);
  return picked.join(separator);
}

/** Shannon entropy of the generator that could have produced this passphrase. */
export function passphraseEntropyBits(words) {
  return words * Math.log2(WORDS.length);
}

const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'passw0rd', '123456', '12345678', '123456789', 'qwerty',
  'abc123', 'letmein', 'monkey', 'iloveyou', 'admin', 'welcome', 'login', 'dragon',
  'sunshine', 'princess', 'football', 'baseball', 'master', 'shadow', 'trustno1',
]);

function isRepeated(password) {
  return /^(.+?)\1+$/.test(password) && new Set(password).size <= 4;
}

function isSequential(password) {
  const lower = password.toLowerCase();
  if (lower.length < 4) return false;
  let ascending = true;
  let descending = true;
  for (let i = 1; i < lower.length; i++) {
    const delta = lower.charCodeAt(i) - lower.charCodeAt(i - 1);
    if (delta !== 1) ascending = false;
    if (delta !== -1) descending = false;
  }
  return ascending || descending;
}

/**
 * Rough entropy estimate for an arbitrary password.
 *
 * This is a heuristic, not a cracking simulation: it assumes an attacker who
 * knows which character classes were used but nothing else, then penalises the
 * few patterns that assumption badly overrates. It deliberately errs low.
 */
export function estimateStrength(password) {
  if (typeof password !== 'string' || password.length === 0) {
    return { bits: 0, label: 'empty', score: 0 };
  }

  if (COMMON_PASSWORDS.has(password.toLowerCase()) || isRepeated(password) || isSequential(password)) {
    return { bits: 0, label: 'very weak', score: 0 };
  }

  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(password)) pool += 33;

  const distinctRatio = new Set(password).size / password.length;
  const bits = Math.log2(pool) * password.length * distinctRatio;

  let label = 'very weak';
  let score = 0;
  if (bits >= 120) { label = 'excellent'; score = 4; }
  else if (bits >= 80) { label = 'strong'; score = 3; }
  else if (bits >= 60) { label = 'good'; score = 2; }
  else if (bits >= 36) { label = 'weak'; score = 1; }

  return { bits: Math.round(bits), label, score };
}

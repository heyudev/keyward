import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CHARSETS,
  MAX_LENGTH,
  MIN_LENGTH,
  estimateStrength,
  generatePassphrase,
  generatePassword,
  passphraseEntropyBits,
  randomIndex,
} from '../src/core/generator.js';
import { WORDS } from '../src/core/wordlist.js';

test('generated passwords honour the requested length', () => {
  for (const length of [MIN_LENGTH, 20, 64, MAX_LENGTH]) {
    assert.equal(generatePassword({ length }).length, length);
  }
});

test('every enabled character class appears at least once', () => {
  // Repeated because the guarantee is probabilistic-looking but must be exact.
  for (let i = 0; i < 200; i++) {
    const password = generatePassword({ length: MIN_LENGTH });
    assert.match(password, /[a-z]/);
    assert.match(password, /[A-Z]/);
    assert.match(password, /[0-9]/);
    assert.match(password, /[^a-zA-Z0-9]/);
  }
});

test('disabled character classes never appear', () => {
  for (let i = 0; i < 100; i++) {
    assert.match(generatePassword({ length: 24, symbols: false, digits: false }), /^[a-zA-Z]+$/);
    assert.match(generatePassword({ length: 24, uppercase: false, symbols: false }), /^[a-z0-9]+$/);
  }
});

test('excludeAmbiguous removes look-alike characters', () => {
  for (let i = 0; i < 100; i++) {
    assert.doesNotMatch(generatePassword({ length: 32, excludeAmbiguous: true }), /[lI1O0oS5B8]/);
  }
});

test('generatePassword rejects impossible requests', () => {
  assert.throws(() => generatePassword({ length: MIN_LENGTH - 1 }), /between/);
  assert.throws(() => generatePassword({ length: MAX_LENGTH + 1 }), /between/);
  assert.throws(() => generatePassword({ length: 12.5 }), /between/);
  assert.throws(
    () => generatePassword({ lowercase: false, uppercase: false, digits: false, symbols: false }),
    /at least one character class/,
  );
  // Four classes cannot fit into three characters.
  assert.throws(() => generatePassword({ length: 3 }), /between/);
});

test('consecutive passwords differ', () => {
  const seen = new Set(Array.from({ length: 100 }, () => generatePassword({ length: 20 })));
  assert.equal(seen.size, 100);
});

test('randomIndex stays in range and covers every value', () => {
  for (const max of [1, 2, 7, 256, 1000]) {
    const seen = new Set();
    for (let i = 0; i < max * 40; i++) {
      const value = randomIndex(max);
      assert.ok(Number.isInteger(value) && value >= 0 && value < max, `${value} out of range for ${max}`);
      seen.add(value);
    }
    assert.equal(seen.size, max, `expected all ${max} values to be reachable`);
  }
  assert.throws(() => randomIndex(0), /positive integer/);
});

test('randomIndex is free of modulo bias', () => {
  // 3 does not divide 256, so a naive `byte % 3` would over-represent 0 and 1
  // by ~0.4%. 30k samples: expected 10000 per bucket, sigma ~82, so a 12%
  // window is ~15 sigma -- tight enough to catch bias, wide enough never to flake.
  const counts = [0, 0, 0];
  const samples = 30_000;
  for (let i = 0; i < samples; i++) counts[randomIndex(3)]++;

  const expected = samples / 3;
  for (const count of counts) {
    assert.ok(Math.abs(count - expected) < expected * 0.12, `bucket skew: ${counts.join(',')}`);
  }
});

test('passphrases use real words and the requested shape', () => {
  const phrase = generatePassphrase({ words: 5, separator: '.' });
  const parts = phrase.split('.');

  assert.equal(parts.length, 5);
  for (const part of parts) assert.ok(WORDS.includes(part), `${part} is not in the word list`);
});

test('passphrase capitalize and includeNumber options apply', () => {
  assert.match(generatePassphrase({ words: 3, capitalize: true }), /^[A-Z][a-z]+-[A-Z][a-z]+-[A-Z][a-z]+$/);

  const numbered = generatePassphrase({ words: 4, includeNumber: true });
  assert.match(numbered, /[0-9]/);
  assert.equal(numbered.split('-').length, 4);

  assert.throws(() => generatePassphrase({ words: 1 }), /between 2 and 12/);
});

test('passphrase entropy matches the word list size', () => {
  assert.equal(passphraseEntropyBits(4), 4 * Math.log2(WORDS.length));
  assert.ok(passphraseEntropyBits(4) >= 32);
});

test('strength estimates rank passwords sensibly', () => {
  assert.equal(estimateStrength('').label, 'empty');
  assert.equal(estimateStrength('password').score, 0);
  assert.equal(estimateStrength('123456').score, 0);
  assert.equal(estimateStrength('aaaaaaaaaaaa').score, 0, 'repeated characters must not score');
  assert.equal(estimateStrength('abcdefghij').score, 0, 'sequential characters must not score');

  assert.ok(estimateStrength('Tr0ub4dor').score <= 2);
  assert.ok(estimateStrength(generatePassword({ length: 20 })).score >= 3);
  assert.equal(estimateStrength(generatePassword({ length: 40 })).label, 'excellent');
});

test('strength is monotonic in length for the same alphabet', () => {
  const short = estimateStrength(generatePassword({ length: 12, symbols: false }));
  const long = estimateStrength(generatePassword({ length: 32, symbols: false }));
  assert.ok(long.bits > short.bits);
});

test('the character sets are disjoint', () => {
  const all = Object.values(CHARSETS).join('');
  assert.equal(new Set(all).size, all.length);
});

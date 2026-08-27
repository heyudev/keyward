import test from 'node:test';
import assert from 'node:assert/strict';
import { MIN_MASTER_PASSWORD_LENGTH, planUnlock } from '../src/core/unlock.js';

const strong = 'demo-master-passphrase';

test('an existing vault is always unlocked, never recreated', () => {
  // The regression that matters: locking used to leave the form in "create"
  // mode, so the next submit would overwrite a real vault with an empty one.
  for (const formInCreateMode of [true, false]) {
    const plan = planUnlock({ vaultExists: true, formInCreateMode, password: strong, confirmation: '' });
    assert.equal(plan.action, 'unlock', `create mode ${formInCreateMode} must still unlock`);
  }
});

test('unlocking an existing vault ignores a mismatched confirmation field', () => {
  const plan = planUnlock({ vaultExists: true, formInCreateMode: true, password: strong, confirmation: 'something else' });
  assert.equal(plan.action, 'unlock');
  assert.equal(plan.repairForm, true, 'the form should be put back into unlock mode');
});

test('an empty password is rejected rather than sent to the KDF', () => {
  assert.deepEqual(planUnlock({ vaultExists: true, formInCreateMode: false, password: '' }), {
    action: 'reject',
    message: 'Enter your master password.',
  });
});

test('creating a vault requires a confirmed, long-enough password', () => {
  const create = (password, confirmation) =>
    planUnlock({ vaultExists: false, formInCreateMode: true, password, confirmation });

  assert.equal(create(strong, strong).action, 'create');
  assert.equal(create('short', 'short').action, 'reject');
  assert.match(create('short', 'short').message, new RegExp(`${MIN_MASTER_PASSWORD_LENGTH} characters`));
  assert.equal(create(strong, 'mismatch').action, 'reject');
  assert.match(create(strong, 'mismatch').message, /do not match/);
});

test('a missing vault switches the form into create mode', () => {
  const plan = planUnlock({ vaultExists: false, formInCreateMode: false, password: strong });
  assert.equal(plan.action, 'switch-to-create');
  assert.match(plan.message, /no vault on this device/);
});

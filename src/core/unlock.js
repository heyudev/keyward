/**
 * Decides what submitting the lock screen should do.
 *
 * This lives apart from the DOM because getting it wrong destroys data: if the
 * form still believes it is creating a vault while one already exists on disk,
 * "create" would replace a real vault with an empty one. The rule is that the
 * stored vault -- not the state of the form -- decides.
 */
export const MIN_MASTER_PASSWORD_LENGTH = 8;

export function planUnlock({ vaultExists, formInCreateMode, password = '', confirmation = '' }) {
  if (vaultExists) {
    // A vault exists, so the only safe action is to open it, whatever the form
    // currently shows. Never create over an existing vault.
    if (!password) return { action: 'reject', message: 'Enter your master password.' };
    return { action: 'unlock', repairForm: formInCreateMode };
  }

  if (!formInCreateMode) {
    // No vault, but the form is asking for an existing password: the file was
    // removed or moved. Switch the form over rather than failing to decrypt.
    return { action: 'switch-to-create', message: 'There is no vault on this device yet. Choose a master password to create one.' };
  }

  if (password.length < MIN_MASTER_PASSWORD_LENGTH) {
    return { action: 'reject', message: `Choose a master password of at least ${MIN_MASTER_PASSWORD_LENGTH} characters.` };
  }
  if (password !== confirmation) {
    return { action: 'reject', message: 'The two passwords do not match.' };
  }

  return { action: 'create' };
}

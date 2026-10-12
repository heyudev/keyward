import { fillLogin, probePage } from './fill.js';
import { websiteOrigin } from './matching.js';

/** Credentials are acquired only after tab and document checks have completed. */
export async function fillAccount({ browser, tabId, pageUrl, getCredentials, isCurrent = () => true }) {
  const origin = websiteOrigin(pageUrl);
  if (!origin || !isCurrent()) throw new Error('pageChanged');
  const [active] = await browser.tabs.query({ active: true, currentWindow: true });
  if (!isCurrent() || active?.id !== tabId || websiteOrigin(active.url) !== origin) throw new Error('pageChanged');
  const results = await browser.scripting.executeScript({ target: { tabId, frameIds: [0] }, func: probePage });
  const main = results.find((result) => result.frameId === 0);
  if (!isCurrent() || !main?.documentId || main.result?.origin !== origin) throw new Error('pageChanged');
  const credentials = getCredentials();
  const filled = await browser.scripting.executeScript({
    target: { tabId, documentIds: [main.documentId] },
    func: fillLogin, args: [origin, credentials], world: 'ISOLATED',
  });
  if (!isCurrent()) throw new Error('sessionCancelled');
  const result = filled.find((entry) => entry.documentId === main.documentId && entry.frameId === 0)?.result;
  if (!result?.ok) throw new Error(result?.reason ?? 'fillFailed');
}

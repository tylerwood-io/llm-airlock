// Wraps untrusted content in nonce-delimited fences. The extractor is told to
// treat everything inside the fence as DATA, never instructions. We also
// neutralize any attempt by the payload to forge our delimiters and "break out".
import { randomBytes } from 'node:crypto';

export function makeNonce() {
  return randomBytes(8).toString('hex');
}

const OPEN_TAG = '<<<UNTRUSTED';
const CLOSE_TAG = '<<<END_UNTRUSTED';

// Insert a zero-width space after the leading "<" so a forged delimiter in the
// payload can never match the real one, while staying human-readable.
function neutralizeDelimiters(s) {
  return String(s)
    .split(CLOSE_TAG).join('<​<<END_UNTRUSTED')
    .split(OPEN_TAG).join('<​<<UNTRUSTED');
}

export function fence(raw, nonce = makeNonce()) {
  const open = `${OPEN_TAG} id="${nonce}">>>`;
  const close = `${CLOSE_TAG} id="${nonce}">>>`;
  const safe = neutralizeDelimiters(raw);
  return { nonce, open, close, text: `${open}\n${safe}\n${close}` };
}

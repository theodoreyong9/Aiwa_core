import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { EventLog } from '../src/event-log.js';
import { generateIdentity } from '../src/identity.js';
import { createEvent } from '../src/event.js';
import { computeContractHash, publishContractSpec, verifyContractSource, readContractSource, registerVerifiedContract, scanContractSpecs } from '../src/contract-registry.js';
import { toReducerEvent } from '../src/adapt-event.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const realGenerousTransferSource = readFileSync(path.join(__dirname, '../src/generous-transfer.js'), 'utf-8');

test('the identical real source always produces the identical real hash', async () => {
  const h1 = await computeContractHash('const x = 1;');
  const h2 = await computeContractHash('const x = 1;');
  assert.equal(h1, h2);
});

test('a real, single-character difference in source produces a genuinely different real hash', async () => {
  const h1 = await computeContractHash('const x = 1;');
  const h2 = await computeContractHash('const x = 2;');
  assert.notEqual(h1, h2);
});

test('THE REAL PUBLISHING PROPERTY: a real contract, published against a real EventLog, gets a real, content-addressed event id', async () => {
  const log = new EventLog();
  const identity = await generateIdentity();
  const { specEventId, sourceHash } = await publishContractSpec(identity, log, 'test-domain', {
    name: 'generous-transfer', version: 1, sourceCode: realGenerousTransferSource, description: 'deterministic, never chance',
  });
  assert.ok(specEventId, 'a real event id must be produced');
  assert.equal(sourceHash, await computeContractHash(realGenerousTransferSource));
});

test('THE REAL VERIFICATION PROPERTY: a real, correctly-matching source verifies against the real, already-published spec', async () => {
  const log = new EventLog();
  const identity = await generateIdentity();
  const { specEventId } = await publishContractSpec(identity, log, 'test-domain', { name: 'generous-transfer', version: 1, sourceCode: realGenerousTransferSource, description: '' });
  const specEvent = toReducerEvent(await log.get(specEventId));
  assert.equal(await verifyContractSource(specEvent, realGenerousTransferSource), true);
});

test('SECURITY: source that has been altered by even one real character fails verification against the real, already-published spec', async () => {
  const log = new EventLog();
  const identity = await generateIdentity();
  const { specEventId } = await publishContractSpec(identity, log, 'test-domain', { name: 'generous-transfer', version: 1, sourceCode: realGenerousTransferSource, description: '' });
  const specEvent = toReducerEvent(await log.get(specEventId));
  const tampered = realGenerousTransferSource + '\n// a real, added line, never in the original';
  assert.equal(await verifyContractSource(specEvent, tampered), false);
});

test('SECURITY: verification of a non-contract-spec event is refused outright', async () => {
  const log = new EventLog();
  const identity = await generateIdentity();
  const genesisEvent = await createEvent(identity, { domain: 'test-domain', parents: [], type: 'genesis', payload: {} });
  await log.append(genesisEvent);
  const otherEvent = toReducerEvent(await log.get(genesisEvent.id));
  assert.equal(await verifyContractSource(otherEvent, 'anything'), false);
});

test('THE REAL RETRIEVAL PROPERTY: the actual source code is genuinely recoverable from an already-published event, never just its fingerprint', async () => {
  const log = new EventLog();
  const identity = await generateIdentity();
  const { specEventId } = await publishContractSpec(identity, log, 'test-domain', { name: 'generous-transfer', version: 1, sourceCode: realGenerousTransferSource, description: '' });
  const specEvent = toReducerEvent(await log.get(specEventId));
  const recovered = readContractSource(specEvent);
  assert.equal(recovered, realGenerousTransferSource, 'the exact, real, complete source must come back unchanged');
});

test('readContractSource returns null, never throws, for a non-contract-spec event', () => {
  const notASpec = { payload: { type: 'genesis' } };
  assert.equal(readContractSource(notASpec), null);
});

test('scanContractSpecs finds every real, published contract-spec event', async () => {
  const log = new EventLog();
  const identity = await generateIdentity();
  await publishContractSpec(identity, log, 'test-domain', { name: 'contract-a', version: 1, sourceCode: 'code-a', description: '' });
  await publishContractSpec(identity, log, 'test-domain', { name: 'contract-b', version: 1, sourceCode: 'code-b', description: '' });
  const allIds = await log.backend.allIds();
  const events = await Promise.all(allIds.map((id) => log.get(id)));
  const specs = scanContractSpecs(events.map(toReducerEvent));
  assert.equal(specs.length, 2);
  assert.deepEqual(specs.map((s) => s.name).sort(), ['contract-a', 'contract-b']);
});

test('scanContractSpecs ignores real, non-contract-spec events', async () => {
  const log = new EventLog();
  const identity = await generateIdentity();
  const genesisEvent = await createEvent(identity, { domain: 'test-domain', parents: [], type: 'genesis', payload: {} });
  await log.append(genesisEvent);
  const events = [toReducerEvent(await log.get(genesisEvent.id))];
  assert.equal(scanContractSpecs(events).length, 0);
});

test('THE REAL STRUCTURAL CLOSE TO CONTRACTID COLLISION: registration succeeds when the real, current source genuinely matches the real, pinned expected hash', async () => {
  const realHash = await computeContractHash(realGenerousTransferSource);
  const fakeVerifier = () => 'this would be the real, trusted verifyPayout';
  const registry = await registerVerifiedContract({}, {
    contractId: 'aiwa-generous-transfer-v1', sourceCode: realGenerousTransferSource, expectedHash: realHash, verifyPayoutFn: fakeVerifier,
  });
  assert.equal(registry['aiwa-generous-transfer-v1'], fakeVerifier);
});

test('SECURITY, THE EXACT REAL ATTACK JUST DEMONSTRATED, NOW CLOSED: a real, different, malicious source claiming a trusted contractId is refused outright — a name alone can never pass this check', async () => {
  const realHash = await computeContractHash(realGenerousTransferSource);
  const maliciousSource = 'export function verifyPayout() { return { claimId: "steal-everything" }; }'; // a real, different, genuinely malicious module
  const maliciousVerifier = () => ({ claimId: 'steal-everything' });

  await assert.rejects(
    registerVerifiedContract({}, {
      contractId: 'aiwa-generous-transfer-v1', // the real, trusted name, claimed by an impostor
      sourceCode: maliciousSource, // but real, genuinely different source
      expectedHash: realHash, // the real, pinned hash of the REAL contract
      verifyPayoutFn: maliciousVerifier,
    }),
    /does not match the expected, pinned/,
    'a real, different source must never be registered under a trusted name, no matter what it claims to be'
  );
});

test('SECURITY: a real mismatch never leaves a partial or silent registration — the real, existing registry is genuinely unchanged', async () => {
  const existingRegistry = { 'some-other-real-contract-v1': () => 'unrelated' };
  const realHash = await computeContractHash(realGenerousTransferSource);
  try {
    await registerVerifiedContract(existingRegistry, {
      contractId: 'aiwa-generous-transfer-v1', sourceCode: 'not the real source at all', expectedHash: realHash, verifyPayoutFn: () => {},
    });
    assert.fail('must have thrown');
  } catch {
    // expected
  }
  assert.deepEqual(Object.keys(existingRegistry), ['some-other-real-contract-v1'], 'the real, pre-existing registry must never be mutated by a failed real registration attempt');
});

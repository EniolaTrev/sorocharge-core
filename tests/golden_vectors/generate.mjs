// Generates golden-vector fixtures from the pinned @stellar/stellar-sdk
// (see package.json for the exact version) and writes them to fixtures/*.json.
// sorocharge-signer's Rust tests diff their own XDR output against these
// fixtures byte-for-byte; this script is dev-only tooling, never a runtime
// dependency of the Rust crates.
//
// All inputs below (keys, amounts, ledger, nonce) are fixed rather than
// randomly generated so this script produces byte-identical output on every
// run, which is what lets CI regenerate the fixtures and diff them against
// what's committed.

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  Address,
  Keypair,
  Networks,
  StrKey,
  xdr,
  nativeToScVal,
  authorizeEntry,
  buildWithDelegatesEntry,
} from "@stellar/stellar-sdk";

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, "fixtures");
mkdirSync(fixturesDir, { recursive: true });

function fixedSeed(byte) {
  return Buffer.alloc(32, byte);
}

const payerKeypair = Keypair.fromRawEd25519Seed(fixedSeed(0x11));
const recipientKeypair = Keypair.fromRawEd25519Seed(fixedSeed(0x22));
const payer = payerKeypair.publicKey();
const recipient = recipientKeypair.publicKey();
const assetContract = StrKey.encodeContract(fixedSeed(0x33));

const amount = 1000000000n; // 100.0000000 units of a 7-decimal SEP-41 asset
// The two numeric boundaries of the i128 amount field: the smallest
// possible positive transfer, and the largest representable value. Each
// exercises a different edge of Int128Parts' hi/lo split (hi = 0, lo = 1
// versus hi = i64::MAX, lo = u64::MAX), where an off-by-one would silently
// corrupt the amount.
const minAmount = 1n;
const maxAmount = (1n << 127n) - 1n; // i128::MAX
const validUntilLedger = 123456;
const nonce = 42n; // fixed for reproducibility; a real client uses a random nonce

function buildTransferInvocation(amount) {
  const invokeArgs = new xdr.InvokeContractArgs({
    contractAddress: new Address(assetContract).toScAddress(),
    functionName: "transfer",
    args: [
      nativeToScVal(payer, { type: "address" }),
      nativeToScVal(recipient, { type: "address" }),
      nativeToScVal(amount, { type: "i128" }),
    ],
  });

  return new xdr.SorobanAuthorizedInvocation({
    function:
      xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
        invokeArgs,
      ),
    subInvocations: [],
  });
}

function buildLegacyEntry(amount) {
  const addressCredentials = new xdr.SorobanAddressCredentials({
    address: new Address(payer).toScAddress(),
    nonce,
    signatureExpirationLedger: validUntilLedger,
    signature: xdr.ScVal.scvVec([]),
  });

  return new xdr.SorobanAuthorizationEntry({
    credentials:
      xdr.SorobanCredentials.sorobanCredentialsAddress(addressCredentials),
    rootInvocation: buildTransferInvocation(amount),
  });
}

function buildAddressV2Entry() {
  const addressCredentials = new xdr.SorobanAddressCredentials({
    address: new Address(payer).toScAddress(),
    nonce,
    signatureExpirationLedger: validUntilLedger,
    signature: xdr.ScVal.scvVec([]),
  });

  return new xdr.SorobanAuthorizationEntry({
    credentials:
      xdr.SorobanCredentials.sorobanCredentialsAddressV2(addressCredentials),
    rootInvocation: buildTransferInvocation(amount),
  });
}

function buildDelegatedEntry() {
  const delegateAKeypair = Keypair.fromRawEd25519Seed(fixedSeed(0x44));
  const delegateBKeypair = Keypair.fromRawEd25519Seed(fixedSeed(0x55));

  const addressCredentials = new xdr.SorobanAddressCredentials({
    address: new Address(payer).toScAddress(),
    nonce,
    signatureExpirationLedger: validUntilLedger,
    signature: xdr.ScVal.scvVoid(),
  });

  // Passed out of address order on purpose to exercise
  // buildWithDelegatesEntry's own ascending sort by address.
  const delegates = [
    { address: delegateBKeypair.publicKey() },
    { address: delegateAKeypair.publicKey() },
  ];

  const entryWithoutDelegates = new xdr.SorobanAuthorizationEntry({
    credentials:
      xdr.SorobanCredentials.sorobanCredentialsAddress(addressCredentials),
    rootInvocation: buildTransferInvocation(amount),
  });

  const entry = buildWithDelegatesEntry({
    entry: entryWithoutDelegates,
    validUntilLedgerSeq: validUntilLedger,
    delegates,
  });

  return {
    entry,
    delegateA: delegateAKeypair.publicKey(),
    delegateB: delegateBKeypair.publicKey(),
  };
}

function buildManyDelegatesEntry() {
  const delegateAKeypair = Keypair.fromRawEd25519Seed(fixedSeed(0x44));
  const delegateCKeypair = Keypair.fromRawEd25519Seed(fixedSeed(0x66));
  const delegateDKeypair = Keypair.fromRawEd25519Seed(fixedSeed(0x99));

  const addressCredentials = new xdr.SorobanAddressCredentials({
    address: new Address(payer).toScAddress(),
    nonce,
    signatureExpirationLedger: validUntilLedger,
    signature: xdr.ScVal.scvVoid(),
  });

  // Three delegates, listed in the exact reverse of their XDR-encoded
  // address-byte order (0x44 > 0x66 > 0x99 once encoded), so this fixture
  // only reproduces the reference SDK's bytes if the builder really
  // reorders them: the two-signer fixture's input happens to already be in
  // ascending order, so it can't prove a sort happened. This trio is also
  // chosen so that sorting by the G-address string would produce a
  // different order than sorting by XDR bytes — the fixture is proof of
  // the right sort key, not merely of some reorder.
  const delegates = [
    { address: delegateAKeypair.publicKey() },
    { address: delegateCKeypair.publicKey() },
    { address: delegateDKeypair.publicKey() },
  ];

  const entryWithoutDelegates = new xdr.SorobanAuthorizationEntry({
    credentials:
      xdr.SorobanCredentials.sorobanCredentialsAddress(addressCredentials),
    rootInvocation: buildTransferInvocation(amount),
  });

  const entry = buildWithDelegatesEntry({
    entry: entryWithoutDelegates,
    validUntilLedgerSeq: validUntilLedger,
    delegates,
  });

  return {
    entry,
    delegateSigners: delegates.map((delegate) => delegate.address),
  };
}

function writeFixture(
  name,
  entry,
  extra = {},
  xdrField = "unsigned_entry_xdr_base64",
) {
  // `extra.amount` (a BigInt) overrides the module-level default amount;
  // it must be stringified here because JSON.stringify cannot serialize a
  // BigInt, and is pulled out of `extra` before the spread below.
  const { amount: fixtureAmount = amount, ...rest } = extra;
  const fixture = {
    description: `${name}: a SorobanAuthorizationEntry for a SEP-41 transfer`,
    sdk_version: "17.2.0",
    asset_contract: assetContract,
    payer,
    recipient,
    amount: fixtureAmount.toString(),
    valid_until_ledger: validUntilLedger,
    nonce: nonce.toString(),
    ...rest,
    [xdrField]: entry.toXdr("base64"),
  };
  const path = join(fixturesDir, `${name}.json`);
  writeFileSync(path, `${JSON.stringify(fixture, null, 2)}\n`);
  console.log(`wrote ${path}`);
}

writeFixture("legacy_transfer", buildLegacyEntry(amount));
writeFixture("address_v2_transfer", buildAddressV2Entry());

// The two numeric boundaries of the i128 amount field, both through the
// same legacy-credential builder so the only variable under test is the
// amount's Int128Parts hi/lo encoding.
writeFixture("legacy_transfer_min_amount", buildLegacyEntry(minAmount), {
  description:
    "legacy_transfer_min_amount: a transfer of 1 base unit, the smallest possible positive i128 amount, exercising the Int128Parts hi/lo split at its lower boundary (hi = 0, lo = 1)",
  amount: minAmount,
});
writeFixture("legacy_transfer_max_amount", buildLegacyEntry(maxAmount), {
  description:
    "legacy_transfer_max_amount: a transfer of i128::MAX, the largest representable i128 amount, exercising the Int128Parts hi/lo split at its upper boundary (hi = i64::MAX, lo = u64::MAX)",
  amount: maxAmount,
});

const delegated = buildDelegatedEntry();
writeFixture("delegated_transfer", delegated.entry, {
  // Listed out of sort order on purpose; the fixture's XDR reflects the
  // sorted order buildWithDelegatesEntry actually produced.
  delegate_signers: [delegated.delegateB, delegated.delegateA],
});

const manyDelegates = buildManyDelegatesEntry();
writeFixture("delegated_transfer_many_signers", manyDelegates.entry, {
  description:
    "delegated_transfer_many_signers: three delegate signers listed in deliberately unsorted order, exercising the XDR-address-byte sort and duplicate detection at a scale the two-signer fixture cannot distinguish from an already-sorted input",
  // Listed in the exact reverse of XDR-encoded address-byte order on
  // purpose; the fixture's XDR reflects the sorted order
  // buildWithDelegatesEntry actually produced.
  delegate_signers: manyDelegates.delegateSigners,
});

const networkPassphrase = Networks.TESTNET;
const signedLegacyEntry = await authorizeEntry(
  buildLegacyEntry(amount),
  payerKeypair,
  validUntilLedger,
  networkPassphrase,
);
writeFixture(
  "legacy_transfer_signed",
  signedLegacyEntry,
  { network_passphrase: networkPassphrase },
  "signed_entry_xdr_base64",
);

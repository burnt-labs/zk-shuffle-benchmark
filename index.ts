import { createRequire } from "module";
import { resolve } from "path";
import { readFileSync } from "fs";
import { ARTIFACTS_DIR, ensureArtifactsDownloaded } from "./utils.ts";

const require = createRequire(import.meta.url);
const {
  shuffleEncryptV2Plaintext,
} = require("@zk-shuffle/proof/dist/src/shuffle/plaintext.js");
const {
  generateDecryptProof,
  generateShuffleEncryptV2Proof,
} = require("@zk-shuffle/proof/dist/src/shuffle/proof.js");
const {
  initDeck,
  keyGen,
  sampleFieldElements,
  samplePermutation,
  compressDeck,
  recoverDeck,
  assert,
} = require("@zk-shuffle/proof/dist/src/shuffle/utilities.js");
const { buildBabyjub } = require("circomlibjs");
const snarkjs = require("snarkjs");

const numBits = 251n;
const numCards = 52n;
const iterations = Number(process.env.ITERATIONS ?? 1);

const timer = async (label: string, fn: () => Promise<unknown>) => {
  const start = Date.now();
  for (let i = 0; i < iterations; i++) {
    await fn();
  }
  const elapsed = (Date.now() - start) / (1000 * iterations);
  console.log(`${label}: ${elapsed} seconds`);
};

const loadVKey = async (file: string) =>
  snarkjs.zKey.exportVerificationKey(new Uint8Array(readFileSync(file)));

async function main() {
  await ensureArtifactsDownloaded();

  const babyjub = await buildBabyjub();
  const keys = keyGen(babyjub, numBits);
  const pkString = [
    babyjub.F.toString(keys.pk[0]),
    babyjub.F.toString(keys.pk[1]),
  ];

  const encryptWasm = resolve(ARTIFACTS_DIR, "wasm/encrypt.wasm");
  const encryptZkey = resolve(ARTIFACTS_DIR, "zkey/encrypt.zkey");
  const encryptVkey = await loadVKey(encryptZkey);

  const initialDeck = initDeck(babyjub, Number(numCards));
  const compressed = compressDeck(initialDeck);
  const permutation = samplePermutation(Number(numCards));
  const randomness = sampleFieldElements(babyjub, numBits, numCards);
  const deckDelta = recoverDeck(babyjub, compressed.X0, compressed.X1);

  const plaintext = shuffleEncryptV2Plaintext(
    babyjub,
    Number(numCards),
    permutation,
    randomness,
    keys.pk,
    compressed.X0,
    compressed.X1,
    deckDelta.Delta0,
    deckDelta.Delta1,
    compressed.selector,
  );

  const encryptProof = await generateShuffleEncryptV2Proof(
    pkString,
    permutation,
    randomness,
    compressed.X0,
    compressed.X1,
    deckDelta.Delta0,
    deckDelta.Delta1,
    compressed.selector,
    plaintext.X0,
    plaintext.X1,
    plaintext.delta0,
    plaintext.delta1,
    plaintext.selector,
    encryptWasm,
    encryptZkey,
  );

  assert(
    await snarkjs.groth16.verify(
      encryptVkey,
      encryptProof.publicSignals,
      encryptProof.proof,
    ),
    "Encrypt proof verification failed",
  );

  await timer("Shuffle Encrypt proof generation", () =>
    generateShuffleEncryptV2Proof(
      pkString,
      permutation,
      randomness,
      compressed.X0,
      compressed.X1,
      deckDelta.Delta0,
      deckDelta.Delta1,
      compressed.selector,
      plaintext.X0,
      plaintext.X1,
      plaintext.delta0,
      plaintext.delta1,
      plaintext.selector,
      encryptWasm,
      encryptZkey,
    ),
  );

  await timer("Shuffle Encrypt proof verification", () =>
    snarkjs.groth16.verify(
      encryptVkey,
      encryptProof.publicSignals,
      encryptProof.proof,
    ),
  );

  const decryptWasm = resolve(ARTIFACTS_DIR, "wasm/decrypt.wasm");
  const decryptZkey = resolve(ARTIFACTS_DIR, "zkey/decrypt.zkey");
  const decryptVkey = await loadVKey(decryptZkey);

  const encryptedDecks = encryptProof.publicSignals.slice(
    0,
    Number(numCards) * 4,
  );
  const Y: bigint[] = [];
  for (let i = 0; i < 4; i++) {
    Y.push(BigInt(encryptedDecks[i * Number(numCards)]));
  }

  const decryptProof = await generateDecryptProof(
    Y,
    keys.sk,
    pkString,
    decryptWasm,
    decryptZkey,
  );

  assert(
    await snarkjs.groth16.verify(
      decryptVkey,
      decryptProof.publicSignals,
      decryptProof.proof,
    ),
    "Decrypt proof verification failed",
  );

  await timer("Decrypt proof generation", () =>
    generateDecryptProof(Y, keys.sk, pkString, decryptWasm, decryptZkey),
  );

  await timer("Decrypt proof verification", () =>
    snarkjs.groth16.verify(
      decryptVkey,
      decryptProof.publicSignals,
      decryptProof.proof,
    ),
  );

  console.log("Benchmark complete");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

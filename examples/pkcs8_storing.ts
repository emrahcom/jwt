// -----------------------------------------------------------------------------
// Run:
//   deno run pkcs8_storing.ts
// -----------------------------------------------------------------------------

// Check the commented import option if you dont have deno.json
import { decodeBase64, encodeBase64 } from "@std/encoding";

// If you dont have deno.json and @std/encoding is not in its import list
// then use these import line:
//import { decodeBase64, encodeBase64 } from "jsr:@std/encoding@^1.0.10";

/*
  Import a PEM encoded RSA private key, to use for RSA-PSS signing.
  Takes a string containing the PEM encoded key, and returns a Promise
  that will resolve to a CryptoKey representing the private key.
  */
function importPrivateKey(pem: string) {
  // fetch the part of the PEM string between header and footer
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  const pemContents = pem.substring(
    pemHeader.length,
    pem.length - pemFooter.length,
  );
  const pemStr = pemContents.replace(/\n/g, "");
  const binaryDer = decodeBase64(pemStr);

  return crypto.subtle.importKey(
    "pkcs8",
    binaryDer,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-384",
    },
    true,
    ["sign"],
  );
}

async function exportKeyToPem(privateKey: CryptoKey) {
  const exportedKey = await crypto.subtle.exportKey("pkcs8", privateKey);
  const exportedAsBase64 = encodeBase64(exportedKey);
  return `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----`;
}

const keyPair = await crypto.subtle.generateKey(
  {
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 4096,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-384",
  },
  true,
  ["verify", "sign"],
);

const { privateKey } = keyPair;

console.log("Generated crypto key:");
console.log(privateKey);
console.log();

const pemExported = await exportKeyToPem(privateKey);
const importedCryptoKey = await importPrivateKey(pemExported);

console.log("Imported crypto key from PEM:");
console.log(importedCryptoKey);
console.log();

const areEqualKeys = pemExported === await exportKeyToPem(importedCryptoKey);
console.log("Are PEMs equal:");
console.log(areEqualKeys);

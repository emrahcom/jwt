/**
 * @module
 * This module contains types and functions related with cryptographic
 * algorithms.
 *
 * @example
 * ```ts
 * import { getAlgorithm } from "jsr:@emrahcom/jwt/algorithm";
 * import { type Algorithm } from "jsr:@emrahcom/jwt/algorithm";
 *
 * const alg = "HS256" as Algorithm;
 * console.log(getAlgorithm(alg));
 * ```
 */

import { isNotNull, isString } from "./util.ts";

/**
 * JSW §1: Cryptographic algorithms and identifiers for use with this specification
 * are described in the separate JSON Web Algorithms (JWA) specification:
 * https://www.rfc-editor.org/rfc/rfc7518
 */
export type Algorithm =
  | "HS256"
  | "HS384"
  | "HS512"
  | "PS256"
  | "PS384"
  | "PS512"
  | "RS256"
  | "RS384"
  | "RS512"
  | "ES256"
  | "ES384"
  // https://github.com/denoland/deno/blob/main/ext/crypto/00_crypto.js
  // | "ES512" //is not yet supported.
  | "none";

/**
 * Represents the HMAC (Hash-based Message Authentication Code) algorithm.
 */
export interface HmacAlgorithm {
  name: "HMAC";
  hash: { name: "SHA-256" | "SHA-384" | "SHA-512" };
}

/**
 * Represents the RSA (Rivest–Shamir–Adleman) encryption algorithm.
 */
export interface RsaAlgorithm {
  name: "RSASSA-PKCS1-v1_5";
  hash: { name: "SHA-256" | "SHA-384" | "SHA-512" };
}

/**
 * Represents the Probabilistic Signature Scheme (PSS) algorithm.
 */
export interface PssAlgorithm {
  name: "RSA-PSS";
  hash: { name: "SHA-256" | "SHA-384" | "SHA-512" };
  saltLength: number;
}

/**
 * Represents the ECDSA (Elliptic Curve Digital Signature Algorithm).
 */
export interface EcdsaAlgorithm {
  name: "ECDSA";
  hash: { name: "SHA-256" | "SHA-384" | "SHA-512" };
  namedCurve: "P-256" | "P-384";
}

/**
 * Represents the configuration parameters for supported cryptographic
 * algorithms. This type encompasses various algorithm-specific configurations,
 * including:
 * - HMAC: Uses a specific hash function (SHA-256, SHA-384, SHA-512).
 * - RSA-PSS: Includes hash function and salt length.
 * - RSASSA-PKCS1-v1_5: Uses a specific hash function.
 * - ECDSA: Includes hash function and named curve (P-256, P-384).
 *
 * Used to define and handle different types of cryptographic algorithms in the
 * context of signing and verifying operations.
 */
export type AlgorithmDefinition =
  | HmacAlgorithm
  | RsaAlgorithm
  | PssAlgorithm
  | EcdsaAlgorithm;

// Still needs an 'any' type! Does anyone have an idea?
// https://github.com/denoland/deno/blob/main/ext/crypto/lib.deno_crypto.d.ts
function isHashedKeyAlgorithm(
  // deno-lint-ignore no-explicit-any
  algorithm: Record<string, any>,
): algorithm is HmacAlgorithm | RsaAlgorithm | PssAlgorithm {
  return isString(algorithm.hash?.name);
}

function isEcKeyAlgorithm(
  // deno-lint-ignore no-explicit-any
  algorithm: Record<string, any>,
): algorithm is EcdsaAlgorithm {
  return isString(algorithm.namedCurve);
}

/**
 * Verifies if the algorithm of `key` matches the given algorithm `alg`
 */
export function verify(alg: Algorithm, key: CryptoKey | null): boolean {
  if (alg === "none") {
    if (isNotNull(key)) {
      throw new Error(`The alg '${alg}' does not allow a key.`);
    } else return true;
  } else {
    if (!key) throw new Error(`The alg '${alg}' demands a key.`);
    const keyAlgorithm = key.algorithm;
    const algAlgorithm = getAlgorithm(alg);
    if (keyAlgorithm.name === algAlgorithm.name) {
      if (isHashedKeyAlgorithm(keyAlgorithm)) {
        return keyAlgorithm.hash.name === algAlgorithm.hash.name;
      } else if (
        isEcKeyAlgorithm(keyAlgorithm) && isEcKeyAlgorithm(algAlgorithm)
      ) {
        return keyAlgorithm.namedCurve === algAlgorithm.namedCurve;
      }
    }
    return false;
  }
}

/**
 * Returns the algorithm definition for the given `alg`
 */
export function getAlgorithm(alg: Algorithm): AlgorithmDefinition {
  switch (alg) {
    case "HS256":
      return { hash: { name: "SHA-256" }, name: "HMAC" };
    case "HS384":
      return { hash: { name: "SHA-384" }, name: "HMAC" };
    case "HS512":
      return { hash: { name: "SHA-512" }, name: "HMAC" };
    case "PS256":
      return {
        hash: { name: "SHA-256" },
        name: "RSA-PSS",
        saltLength: 256 >> 3,
      };
    case "PS384":
      return {
        hash: { name: "SHA-384" },
        name: "RSA-PSS",
        saltLength: 384 >> 3,
      };
    case "PS512":
      return {
        hash: { name: "SHA-512" },
        name: "RSA-PSS",
        saltLength: 512 >> 3,
      };
    case "RS256":
      return { hash: { name: "SHA-256" }, name: "RSASSA-PKCS1-v1_5" };
    case "RS384":
      return { hash: { name: "SHA-384" }, name: "RSASSA-PKCS1-v1_5" };
    case "RS512":
      return { hash: { name: "SHA-512" }, name: "RSASSA-PKCS1-v1_5" };
    case "ES256":
      return { hash: { name: "SHA-256" }, name: "ECDSA", namedCurve: "P-256" };
    case "ES384":
      return { hash: { name: "SHA-384" }, name: "ECDSA", namedCurve: "P-384" };
    // case "ES512":
    // return { hash: { name: "SHA-512" }, name: "ECDSA", namedCurve: "P-521" };
    default:
      throw new Error(`The jwt's alg '${alg}' is not supported.`);
  }
}

import MD5 from "crypto-js/md5";
import SHA1 from "crypto-js/sha1";
import SHA256 from "crypto-js/sha256";
import encUtf8 from "crypto-js/enc-utf8";

export type HashAlgo = "md5" | "sha1" | "sha256";

export function generateHash(algo: HashAlgo, text: string): string {
  const bytes = encUtf8.parse(text);
  switch (algo) {
    case "md5":
      return MD5(bytes).toString();
    case "sha1":
      return SHA1(bytes).toString();
    case "sha256":
      return SHA256(bytes).toString();
  }
}

// Ported from identify_hash_type() in src/threatpad.py — length/charset only,
// so ambiguous lengths (e.g. 32 hex chars could be MD5) report every candidate.
export function identifyHashTypes(input: string): string[] {
  const value = input.trim();
  const types: string[] = [];
  if (/^[a-fA-F0-9]{32}$/.test(value)) types.push("MD5");
  if (/^[a-fA-F0-9]{40}$/.test(value)) types.push("SHA1");
  if (/^[a-fA-F0-9]{64}$/.test(value)) types.push("SHA256");
  if (/^[a-fA-F0-9]{96}$/.test(value)) types.push("SHA384");
  if (/^[a-fA-F0-9]{128}$/.test(value)) types.push("SHA512");
  return types;
}

export function base64Encode(text: string): string {
  return btoa(unescape(encodeURIComponent(text)));
}

export function base64Decode(text: string): string {
  return decodeURIComponent(escape(atob(text.trim())));
}

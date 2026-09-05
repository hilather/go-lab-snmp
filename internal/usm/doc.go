// Package usm is bounded SNMPv3 USM (auth, priv, engine ID, time window).
//
// Allowed algorithms are HMAC-MD5-96, HMAC-SHA-96, HMAC-SHA-256-192,
// CBC-DES, and CFB128-AES-128. HMAC and decrypt live here;
// internal/snmpwire keeps ciphertext as an OCTET STRING.
package usm

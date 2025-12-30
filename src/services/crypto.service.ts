import { Injectable } from '@angular/core';
import { WORDLIST } from './wordlist';
import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import * as bs58 from 'bs58';
// Fix: Import `Buffer` to make it available in the browser environment, as it's required by the `bs58` library.
import { Buffer } from 'buffer';

export interface DerivedWalletData {
  privateKeyHex: string;
  wifCompressed: string;
  addressCompressed: string;
  wifUncompressed: string;
  addressUncompressed: string;
}

@Injectable({ providedIn: 'root' })
export class CryptoService {

  private bufferToBinary(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    bytes.forEach(byte => {
      binary += byte.toString(2).padStart(8, '0');
    });
    return binary;
  }

  private arrayBufferToHex(buffer: ArrayBuffer | Uint8Array): string {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
  
  private hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        const hexSlice = hex.substring(i * 2, i * 2 + 2);
        if (hexSlice.length < 2) continue;
        bytes[i] = parseInt(hexSlice, 16);
    }
    return bytes;
  }

  private bs58checkEncode(payload: Uint8Array): string {
    const doubleSha = sha256(sha256(payload));
    const checksum = doubleSha.slice(0, 4);

    const taggedPayload = new Uint8Array(payload.length + 4);
    taggedPayload.set(payload);
    taggedPayload.set(checksum, payload.length);
    
    // The bs58 library expects a Buffer, so we convert the final Uint8Array.
    // The CJS module is wrapped in a 'default' property by esm.sh.
    return bs58.default.encode(Buffer.from(taggedPayload));
  }

  async generateMnemonic(strength: 128 | 256): Promise<string> {
    if (!crypto || !crypto.subtle) {
      throw new Error('Web Crypto API is not available in this browser.');
    }

    const entropyBytes = strength / 8;
    const entropy = crypto.getRandomValues(new Uint8Array(entropyBytes));

    const hashBuffer = await crypto.subtle.digest('SHA-256', entropy);

    const entropyBits = this.bufferToBinary(entropy);
    const hashBits = this.bufferToBinary(hashBuffer);

    const checksumLength = strength / 32;
    const checksumBits = hashBits.slice(0, checksumLength);

    const allBits = entropyBits + checksumBits;

    const words: string[] = [];
    for (let i = 0; i < allBits.length; i += 11) {
      const chunk = allBits.slice(i, i + 11);
      const index = parseInt(chunk, 2);
      if (index >= WORDLIST.length) {
        throw new Error('Calculated index is out of bounds of the wordlist.');
      }
      words.push(WORDLIST[index]);
    }

    return words.join(' ');
  }

  async mnemonicToSeed(mnemonic: string, passphrase = ''): Promise<string> {
    if (!crypto || !crypto.subtle) {
      throw new Error('Web Crypto API is not available in this browser.');
    }

    const encoder = new TextEncoder();
    const salt = encoder.encode('mnemonic' + passphrase);
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(mnemonic),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const seedBuffer = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 2048,
        hash: 'SHA-512',
      },
      keyMaterial,
      512 // 512 bits
    );

    return this.arrayBufferToHex(seedBuffer);
  }

  deriveWalletDataFromSeed(seedHex: string): DerivedWalletData {
    // Note: This derivation is simplified for educational purposes and is NOT BIP-32 compliant.
    // A common (but non-standard) approach is to take the first 32 bytes of the 64-byte seed as the master private key.
    const privateKeyBytes = this.hexToBytes(seedHex.substring(0, 64));

    if (privateKeyBytes.length !== 32) {
      throw new Error('Invalid private key length.');
    }

    // 1. Get Private Key Hex
    const privateKeyHex = this.arrayBufferToHex(privateKeyBytes);

    // 2. Get Compressed WIF
    const wifCompressedPayload = new Uint8Array(34);
    wifCompressedPayload[0] = 0x80; // Mainnet prefix
    wifCompressedPayload.set(privateKeyBytes, 1);
    wifCompressedPayload[33] = 0x01; // Compressed public key suffix
    const wifCompressed = this.bs58checkEncode(wifCompressedPayload);

    // 3. Get Compressed Address
    const publicKeyCompressedBytes = secp.getPublicKey(privateKeyBytes, true); // true for compressed
    const shaCompressed = sha256(publicKeyCompressedBytes);
    const ripCompressed = ripemd160(shaCompressed);
    const addressCompressedPayload = new Uint8Array(21);
    addressCompressedPayload[0] = 0x00; // Mainnet address prefix
    addressCompressedPayload.set(ripCompressed, 1);
    const addressCompressed = this.bs58checkEncode(addressCompressedPayload);

    // 4. Get Uncompressed WIF
    const wifUncompressedPayload = new Uint8Array(33);
    wifUncompressedPayload[0] = 0x80; // Mainnet prefix
    wifUncompressedPayload.set(privateKeyBytes, 1);
    const wifUncompressed = this.bs58checkEncode(wifUncompressedPayload);

    // 5. Get Uncompressed Address
    const publicKeyUncompressedBytes = secp.getPublicKey(privateKeyBytes, false); // false for uncompressed
    const shaUncompressed = sha256(publicKeyUncompressedBytes);
    const ripUncompressed = ripemd160(shaUncompressed);
    const addressUncompressedPayload = new Uint8Array(21);
    addressUncompressedPayload[0] = 0x00; // Mainnet address prefix
    addressUncompressedPayload.set(ripUncompressed, 1);
    const addressUncompressed = this.bs58checkEncode(addressUncompressedPayload);
    
    return { 
      privateKeyHex,
      wifCompressed,
      addressCompressed,
      wifUncompressed,
      addressUncompressed
    };
  }
}
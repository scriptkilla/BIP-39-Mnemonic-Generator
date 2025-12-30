import { Injectable } from '@angular/core';
import { WORDLIST } from './wordlist';
import { getPublicKey } from '@noble/secp256k1';
import { HDKey } from '@noble/hdw';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { keccak_256 } from '@noble/hashes/keccak';
import bs58 from 'bs58';
// Fix: Import `Buffer` to make it available in the browser environment, as it's required by the `bs58` library.
import { Buffer } from 'buffer';

export interface BitcoinDerivedData {
  chain: 'bitcoin';
  privateKeyHex: string;
  wifCompressed: string;
  addressCompressed: string;
  wifUncompressed: string;
  addressUncompressed: string;
}

export interface EthereumDerivedData {
  chain: 'ethereum';
  privateKeyHex: string;
  publicKeyHex: string;
  address: string;
}

export type DerivedWalletData = BitcoinDerivedData | EthereumDerivedData;


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
    return bs58.encode(Buffer.from(taggedPayload));
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

  deriveWalletData(seedHex: string, chain: 'bitcoin' | 'ethereum'): DerivedWalletData {
    if (chain === 'bitcoin') {
      return this.deriveBitcoinData(seedHex);
    } else {
      return this.deriveEthereumData(seedHex);
    }
  }

  private deriveBitcoinData(seedHex: string): BitcoinDerivedData {
    // Note: This derivation is simplified for educational purposes and is NOT BIP-32 compliant.
    const privateKeyBytes = this.hexToBytes(seedHex.substring(0, 64));
    if (privateKeyBytes.length !== 32) throw new Error('Invalid private key length.');
    
    const privateKeyHex = this.arrayBufferToHex(privateKeyBytes);
    
    const wifCompressedPayload = new Uint8Array([0x80, ...privateKeyBytes, 0x01]);
    const wifCompressed = this.bs58checkEncode(wifCompressedPayload);

    const publicKeyCompressedBytes = getPublicKey(privateKeyBytes, true);
    const ripCompressed = ripemd160(sha256(publicKeyCompressedBytes));
    const addressCompressedPayload = new Uint8Array([0x00, ...ripCompressed]);
    const addressCompressed = this.bs58checkEncode(addressCompressedPayload);

    const wifUncompressedPayload = new Uint8Array([0x80, ...privateKeyBytes]);
    const wifUncompressed = this.bs58checkEncode(wifUncompressedPayload);

    const publicKeyUncompressedBytes = getPublicKey(privateKeyBytes, false);
    const ripUncompressed = ripemd160(sha256(publicKeyUncompressedBytes));
    const addressUncompressedPayload = new Uint8Array([0x00, ...ripUncompressed]);
    // FIX: Corrected typo from bs8checkEncode to bs58checkEncode
    const addressUncompressed = this.bs58checkEncode(addressUncompressedPayload);
    
    return { 
      chain: 'bitcoin',
      privateKeyHex,
      wifCompressed,
      addressCompressed,
      wifUncompressed,
      addressUncompressed
    };
  }

  private deriveEthereumData(seedHex: string): EthereumDerivedData {
    const seedBytes = this.hexToBytes(seedHex);
    const masterKey = HDKey.fromMasterSeed(seedBytes);
    const childNode = masterKey.derive("m/44'/60'/0'/0/0");

    if (!childNode.privateKey) {
      throw new Error('Could not derive private key for Ethereum.');
    }
    const privateKeyBytes = childNode.privateKey;
    const privateKeyHex = this.arrayBufferToHex(privateKeyBytes);

    const publicKeyBytes = getPublicKey(privateKeyBytes, false);
    const publicKeyHex = this.arrayBufferToHex(publicKeyBytes);
    
    // Ethereum address derivation
    // The public key for address generation is uncompressed, and we drop the leading 0x04 byte
    const addressHash = keccak_256(publicKeyBytes.slice(1));
    const addressBytes = addressHash.slice(-20); // Last 20 bytes
    const address = '0x' + this.arrayBufferToHex(addressBytes);

    return {
      chain: 'ethereum',
      privateKeyHex,
      publicKeyHex,
      address
    };
  }
}
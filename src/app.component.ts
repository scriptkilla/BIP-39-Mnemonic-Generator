import { Component, ChangeDetectionStrategy, signal, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { CryptoService, DerivedWalletData } from './services/crypto.service';
import { BlockchainService } from './services/blockchain.service';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [CommonModule],
})
export class AppComponent {
  private cryptoService = inject(CryptoService);
  private blockchainService = inject(BlockchainService);

  strength = signal<128 | 256>(128);
  mnemonic = signal<string[]>([]);
  isLoading = signal(false);
  error = signal<string | null>(null);
  copied = signal<{ [key: string]: boolean }>({});
  passphrase = signal('');
  seed = signal('');
  passphraseVisible = signal(false);

  derivedData = signal<DerivedWalletData | null>(null);
  balance = signal<number | null>(null);
  txCount = signal<number | null>(null);
  isCheckingBalance = signal(false);

  async generateMnemonic(): Promise<void> {
    this.isLoading.set(true);
    this.error.set(null);
    this.mnemonic.set([]);
    this.seed.set('');
    this.derivedData.set(null);
    this.resetBalance();

    try {
      const phrase = await this.cryptoService.generateMnemonic(this.strength());
      this.mnemonic.set(phrase.split(' '));
      const seedHex = await this.cryptoService.mnemonicToSeed(phrase, this.passphrase());
      this.seed.set(seedHex);
      await this.deriveAndSetWalletData(seedHex);
    } catch (e) {
      console.error(e);
      this.error.set('Failed to generate mnemonic. Please ensure your browser supports the Web Crypto API.');
    } finally {
      this.isLoading.set(false);
    }
  }

  async onPassphraseInput(event: Event): Promise<void> {
    const newPassphrase = (event.target as HTMLInputElement).value;
    this.passphrase.set(newPassphrase);

    if (this.mnemonic().length > 0) {
      try {
        const phrase = this.mnemonic().join(' ');
        const seedHex = await this.cryptoService.mnemonicToSeed(phrase, newPassphrase);
        this.seed.set(seedHex);
        await this.deriveAndSetWalletData(seedHex);
      } catch (e) {
        console.error(e);
        this.error.set('Failed to update seed with new passphrase.');
      }
    }
  }

  async deriveAndSetWalletData(seed: string): Promise<void> {
    this.derivedData.set(null);
    this.resetBalance();
    if (!seed) return;

    try {
      const data = this.cryptoService.deriveWalletDataFromSeed(seed);
      this.derivedData.set(data);
    } catch (e) {
      this.error.set('Failed to derive wallet data from seed.');
      console.error(e);
    }
  }

  async checkAddressBalance(): Promise<void> {
    const address = this.derivedData()?.addressCompressed;
    if (!address) return;

    this.isCheckingBalance.set(true);
    this.resetBalance();

    try {
      const { balance, txCount } = await this.blockchainService.checkBalance(address);
      this.balance.set(balance);
      this.txCount.set(txCount);
    } catch (e) {
      this.error.set('Failed to check address balance.');
      console.error(e);
    } finally {
      this.isCheckingBalance.set(false);
    }
  }
  
  setStrength(value: string): void {
    const newStrength = parseInt(value, 10) as 128 | 256;
    if (newStrength === 128 || newStrength === 256) {
      this.strength.set(newStrength);
    }
  }

  copyValue(value: string | string[], key: string): void {
    const textToCopy = Array.isArray(value) ? value.join(' ') : value;
    if (!textToCopy) return;

    navigator.clipboard.writeText(textToCopy).then(() => {
        this.copied.update(c => ({ ...c, [key]: true }));
        setTimeout(() => {
            this.copied.update(c => ({ ...c, [key]: false }));
        }, 2000);
    });
  }

  togglePassphraseVisibility(): void {
    this.passphraseVisible.update(visible => !visible);
  }

  private resetBalance(): void {
    this.balance.set(null);
    this.txCount.set(null);
  }
}
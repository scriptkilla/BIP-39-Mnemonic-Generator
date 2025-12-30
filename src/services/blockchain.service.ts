import { Injectable } from '@angular/core';

export interface BalanceResponse {
    balance: number;
    txCount: number;
}

@Injectable({ providedIn: 'root' })
export class BlockchainService {
  async checkBalance(address: string, chain: 'bitcoin' | 'ethereum'): Promise<BalanceResponse> {
    if (chain === 'bitcoin') {
      return this.checkBitcoinBalance(address);
    } else {
      return this.checkEthereumBalance(address);
    }
  }

  private async checkBitcoinBalance(address: string): Promise<BalanceResponse> {
    const url = `https://mempool.space/api/address/${address}`;
    try {
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`API error: ${response.status} ${response.statusText}`);
      }
      const data = await response.json();
      const balanceSatoshis = data.chain_stats.funded_txo_sum - data.chain_stats.spent_txo_sum;
      return {
        balance: balanceSatoshis / 1e8,
        txCount: data.chain_stats.tx_count,
      };
    } catch (error) {
      console.error('Failed to fetch Bitcoin balance:', error);
      return { balance: 0, txCount: 0 };
    }
  }

  private async checkEthereumBalance(address: string): Promise<BalanceResponse> {
    // Using Etherscan's free, no-API-key-required endpoints.
    const balanceUrl = `https://api.etherscan.io/api?module=account&action=balance&address=${address}&tag=latest`;
    const txCountUrl = `https://api.etherscan.io/api?module=proxy&action=eth_getTransactionCount&address=${address}&tag=latest`;
    
    try {
      const [balanceResponse, txCountResponse] = await Promise.all([
        fetch(balanceUrl),
        fetch(txCountUrl)
      ]);

      if (!balanceResponse.ok || !txCountResponse.ok) {
        throw new Error('One or more Etherscan API requests failed.');
      }

      const balanceData = await balanceResponse.json();
      const txCountData = await txCountResponse.json();
      
      if (balanceData.status !== '1' || txCountData.result === null) {
         // Etherscan API returns status '0' for errors, like invalid address
        return { balance: 0, txCount: 0 };
      }
      
      const balanceWei = parseFloat(balanceData.result);
      const txCount = parseInt(txCountData.result, 16);

      return {
        balance: balanceWei / 1e18, // Convert Wei to ETH
        txCount: txCount || 0,
      };
    } catch (error) {
      console.error('Failed to fetch Ethereum balance:', error);
      return { balance: 0, txCount: 0 };
    }
  }
}
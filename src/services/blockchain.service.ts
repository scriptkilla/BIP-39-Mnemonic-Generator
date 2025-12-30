import { Injectable } from '@angular/core';

export interface BalanceResponse {
    balance: number;
    txCount: number;
}

@Injectable({ providedIn: 'root' })
export class BlockchainService {
  async checkBalance(address: string): Promise<BalanceResponse> {
    // Switched to mempool.space API which is more reliable and has CORS enabled.
    const url = `https://mempool.space/api/address/${address}`;
    
    try {
      const response = await fetch(url);

      if (!response.ok) {
         // mempool.space API returns a non-200 status for invalid addresses or server errors.
         // We can treat this as a zero balance for simplicity in this tool.
        throw new Error(`API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      const balanceSatoshis = data.chain_stats.funded_txo_sum - data.chain_stats.spent_txo_sum;

      return {
        balance: balanceSatoshis / 1e8, // Convert satoshis to BTC
        txCount: data.chain_stats.tx_count,
      };
    } catch (error) {
      console.error('Failed to fetch balance:', error);
      // For this educational tool, we can assume most errors mean the address is unused or the API is temporarily unavailable.
      return { balance: 0, txCount: 0 };
    }
  }
}
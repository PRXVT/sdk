/**
 * High-level API matching x402 but with privacy
 * Usage:
 *   import { px402 } from '@prxvt/sdk'
 *   await px402.pay({ amount: 100, recipient: merchant })
 */

import { buildPoseidon } from 'circomlibjs';
import * as snarkjs from 'snarkjs';
import { createPublicClient, createWalletClient, http, parseEther } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { base, baseSepolia } from 'viem/chains';

interface PX402Config {
  poolAddress: string;
  paymasterAddress: string;
  bundlerUrl: string;
  rpcUrl: string;
  privateKey?: string; // For deposits only
  storageAdapter?: StorageAdapter;
  network?: 'mainnet' | 'testnet';
}

export interface StorageAdapter {
  get(key: string): Promise<any>;
  set(key: string, value: any): Promise<void>;
  list(): Promise<any[]>;
}

interface Commitment {
  commitment: bigint;
  secret: bigint;
  nullifier: bigint;
  amount: number;
  spent: boolean;
  createdAt: number;
}

export class PX402 {
  private config: PX402Config;
  private poseidon: any;
  private storage: StorageAdapter;
  private initialized = false;

  // Fixed denominations in USDC (6 decimals)
  static DENOMS = [100000, 500000, 1000000, 5000000]; // 0.10, 0.50, 1.00, 5.00

  constructor(config: PX402Config) {
    this.config = config;
    this.storage = config.storageAdapter || new LocalStorageAdapter();
  }

  /**
   * Initialize SDK (call once before first use)
   */
  async init() {
    if (this.initialized) return;
    this.poseidon = await buildPoseidon();
    this.initialized = true;
  }

  /**
   * Deposit USDC into privacy pool
   * @param amount - Amount in USDC (e.g., 1.0 for 1 USDC)
   */
  async deposit(amount: number): Promise<{ commitment: string; txHash: string }> {
    this.ensureInitialized();

    const amountMicro = Math.floor(amount * 1000000);

    // Find nearest valid denomination
    const denom = this.findNearestDenom(amountMicro);
    if (!denom) {
      throw new Error(`Amount ${amount} USDC not supported. Use: 0.10, 0.50, 1.00, or 5.00`);
    }

    // Generate commitment
    const secret = this.randomField();
    const nullifier = this.randomField();
    const commitment = this.computeCommitment(secret, nullifier, BigInt(denom));

    // Store locally before on-chain deposit
    await this.storage.set(`commitment-${commitment}`, {
      commitment,
      secret: secret.toString(),
      nullifier: nullifier.toString(),
      amount: denom,
      spent: false,
      createdAt: Date.now()
    });

    // TODO: Call pool.deposit() on-chain
    // For now, return mock txHash
    const txHash = '0x' + Math.random().toString(16).slice(2);

    return {
      commitment: commitment.toString(),
      txHash
    };
  }

  /**
   * Make a private payment (mimics x402 API)
   * @param options - Payment options
   */
  async pay(options: {
    amount: number;          // Amount in USDC cents (e.g., 100 = $0.01)
    recipient: string;       // Merchant address
    metadata?: any;          // Optional payment metadata
  }): Promise<{
    success: boolean;
    proofHash: string;
    nullifierHash: string;
    change: number;
  }> {
    this.ensureInitialized();

    const { amount, recipient } = options;
    const amountMicro = amount * 10000; // Convert cents to 6-decimal USDC

    // Select suitable commitment
    const commitment = await this.selectCommitment(amountMicro);
    if (!commitment) {
      throw new Error(
        `Insufficient balance. Need ${amount / 100} USDC. ` +
        `Current balance: ${await this.getBalance()} USDC. ` +
        `Use px402.deposit() to add funds.`
      );
    }

    // Find nearest denomination to pay
    const paymentDenom = this.findNearestDenom(amountMicro);
    if (!paymentDenom) {
      throw new Error(`Payment amount ${amount / 100} USDC not supported`);
    }

    // Generate ZK proof
    const changeAmount = commitment.amount - paymentDenom;
    const newSecret = this.randomField();
    const newNullifier = this.randomField();

    const { proof, publicSignals } = await this.generateProof({
      commitment,
      paymentAmount: paymentDenom,
      changeAmount,
      newSecret,
      newNullifier,
      recipient
    });

    // Mark old commitment as spent
    commitment.spent = true;
    await this.storage.set(`commitment-${commitment.commitment}`, commitment);

    // Store new change commitment
    if (changeAmount > 0) {
      const changeCommitment = this.computeCommitment(newSecret, newNullifier, BigInt(changeAmount));
      await this.storage.set(`commitment-${changeCommitment}`, {
        commitment: changeCommitment.toString(),
        secret: newSecret.toString(),
        nullifier: newNullifier.toString(),
        amount: changeAmount,
        spent: false,
        createdAt: Date.now()
      });
    }

    // TODO: Submit UserOp to bundler
    const proofHash = '0x' + Math.random().toString(16).slice(2);
    const nullifierHash = publicSignals[1];

    return {
      success: true,
      proofHash,
      nullifierHash,
      change: changeAmount / 1000000
    };
  }

  /**
   * Get current balance across all unspent commitments
   */
  async getBalance(): Promise<number> {
    const commitments = await this.storage.list();
    const unspent = commitments.filter((c: Commitment) => !c.spent);
    const total = unspent.reduce((sum: number, c: Commitment) => sum + c.amount, 0);
    return total / 1000000; // Convert to USDC
  }

  /**
   * Get payment history
   */
  async getHistory(): Promise<any[]> {
    // TODO: Fetch from indexer or local logs
    return [];
  }

  /**
   * Clear all stored commitments (use with caution!)
   */
  async clearStorage(): Promise<void> {
    // TODO: Implement storage clear
  }

  // Private helper methods

  private ensureInitialized() {
    if (!this.initialized) {
      throw new Error('PX402 not initialized. Call await px402.init() first.');
    }
  }

  private async generateProof(params: {
    commitment: Commitment;
    paymentAmount: number;
    changeAmount: number;
    newSecret: bigint;
    newNullifier: bigint;
    recipient: string;
  }) {
    const { commitment, paymentAmount, changeAmount, newSecret, newNullifier } = params;

    // Build Merkle proof (simplified: single leaf tree)
    const pathElements = new Array(20).fill(0);
    const pathIndices = new Array(20).fill(0);

    let currentHash = BigInt(commitment.commitment);
    for (let i = 0; i < 20; i++) {
      currentHash = this.poseidon.F.toObject(this.poseidon([currentHash, 0]));
    }
    const root = currentHash;

    // Circuit input
    const input = {
      nullifier: commitment.nullifier,
      secret: commitment.secret,
      denomination: commitment.amount.toString(),
      newSecret: newSecret.toString(),
      newNullifier: newNullifier.toString(),
      pathElements: pathElements.map(x => x.toString()),
      pathIndices: pathIndices,
      root: root.toString(),
      paymentAmount: paymentAmount.toString(),
      changeAmount: changeAmount.toString()
    };

    // Generate proof using snarkjs
    const wasmPath = this.config.storageAdapter
      ? './build/eligibility_js/eligibility.wasm'
      : require.resolve('../build/eligibility_js/eligibility.wasm');
    const zkeyPath = require.resolve('../build/eligibility_final.zkey');

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input,
      wasmPath,
      zkeyPath
    );

    return { proof, publicSignals };
  }

  private async selectCommitment(requiredAmount: number): Promise<Commitment | null> {
    const commitments = await this.storage.list();
    const unspent = commitments.filter((c: Commitment) => !c.spent);

    // Find smallest commitment that covers the amount
    let best: Commitment | null = null;
    for (const c of unspent) {
      if (c.amount >= requiredAmount) {
        if (!best || c.amount < best.amount) {
          best = c;
        }
      }
    }

    return best;
  }

  private findNearestDenom(amount: number): number | null {
    // Find exact match or next larger denomination
    for (const denom of PX402.DENOMS) {
      if (denom >= amount) return denom;
    }
    return null;
  }

  private computeCommitment(secret: bigint, nullifier: bigint, amount: bigint): bigint {
    return this.poseidon.F.toObject(this.poseidon([secret, nullifier, amount]));
  }

  private randomField(): bigint {
    const bytes = new Uint8Array(31);
    if (typeof window !== 'undefined' && window.crypto) {
      window.crypto.getRandomValues(bytes);
    } else {
      require('crypto').randomFillSync(bytes);
    }
    return BigInt('0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''));
  }
}

/**
 * Default storage adapter (localStorage in browser, fs in Node.js)
 */
class LocalStorageAdapter implements StorageAdapter {
  private prefix = 'px402-';

  async get(key: string): Promise<any> {
    if (typeof window !== 'undefined' && window.localStorage) {
      const data = localStorage.getItem(this.prefix + key);
      return data ? JSON.parse(data) : null;
    } else {
      // Node.js: use filesystem
      const fs = require('fs').promises;
      const path = require('path');
      const file = path.join('.px402', key + '.json');
      try {
        const data = await fs.readFile(file, 'utf8');
        return JSON.parse(data);
      } catch {
        return null;
      }
    }
  }

  async set(key: string, value: any): Promise<void> {
    if (typeof window !== 'undefined' && window.localStorage) {
      localStorage.setItem(this.prefix + key, JSON.stringify(value));
    } else {
      const fs = require('fs').promises;
      const path = require('path');
      const dir = '.px402';
      const file = path.join(dir, key + '.json');

      try {
        await fs.mkdir(dir, { recursive: true });
      } catch {}

      await fs.writeFile(file, JSON.stringify(value, null, 2));
    }
  }

  async list(): Promise<any[]> {
    if (typeof window !== 'undefined' && window.localStorage) {
      const items: any[] = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key?.startsWith(this.prefix + 'commitment-')) {
          const data = localStorage.getItem(key);
          if (data) items.push(JSON.parse(data));
        }
      }
      return items;
    } else {
      const fs = require('fs').promises;
      const path = require('path');
      const dir = '.px402';

      try {
        const files = await fs.readdir(dir);
        const items: any[] = [];

        for (const file of files) {
          if (file.startsWith('commitment-')) {
            const data = await fs.readFile(path.join(dir, file), 'utf8');
            items.push(JSON.parse(data));
          }
        }

        return items;
      } catch {
        return [];
      }
    }
  }
}

/**
 * Singleton instance for simple usage
 */
export let px402: PX402;

/**
 * Configure and initialize px402
 */
export async function configurePX402(config: PX402Config): Promise<PX402> {
  px402 = new PX402(config);
  await px402.init();
  return px402;
}

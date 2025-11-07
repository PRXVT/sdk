import { buildPoseidon } from 'circomlibjs';
import * as snarkjs from 'snarkjs';
import { createPublicClient, createWalletClient, http, Address, Hash } from 'viem';
import { base, baseSepolia } from 'viem/chains';
import { MerkleTreeManager, MerkleProof } from './merkle';

export interface PX402Config {
  poolAddress: Address;
  paymasterAddress: Address;
  usdcAddress: Address;
  rpcUrl: string;
  zkeyPath: string;
  wasmPath: string;
  chainId?: number;
}

export interface CommitmentData {
  secret: bigint;
  nullifier: bigint;
  denomination: number;
  spent: boolean;
  leafIndex?: number;
}

export interface ProofData {
  proof: any;
  publicSignals: string[];
  merchant: Address;
  paymentAmount: bigint;
  changeCommitment: bigint;
  changeAmount: bigint;
}

/**
 * PX402 SDK - Privacy-preserving X402 payment client
 * @example
 * const sdk = new PX402SDK(config);
 * await sdk.init();
 * await sdk.deposit(1000000); // Deposit 1.00 USDC
 * const proof = await sdk.generateProof(100000, merchantAddress); // Pay 0.10 USDC
 */
export class PX402SDK {
  private poseidon: any;
  private commitments: Map<string, CommitmentData> = new Map();
  private merkleTree?: MerkleTreeManager;
  private publicClient: any;
  private walletClient?: any;

  // Fixed denominations in USDC (6 decimals)
  static DENOMS = [100000, 500000, 1000000, 5000000]; // 0.10, 0.50, 1.00, 5.00 USDC
  static DENOM_NAMES = ['0.10', '0.50', '1.00', '5.00'];

  constructor(private config: PX402Config) {
    const chain = config.chainId === 8453 ? base : baseSepolia;

    this.publicClient = createPublicClient({
      chain,
      transport: http(config.rpcUrl),
    });
  }

  /**
   * Initialize SDK (build Poseidon hash, create Merkle tree)
   */
  async init() {
    this.poseidon = await buildPoseidon();

    // Create Merkle tree with Poseidon hash
    const poseidonHash = (inputs: bigint[]): bigint => {
      return this.poseidon.F.toObject(this.poseidon(inputs));
    };

    this.merkleTree = new MerkleTreeManager(20, poseidonHash);

    console.log('PX402 SDK initialized');
  }

  /**
   * Deposit USDC to pool with a commitment
   * @param denomination Must be one of DENOMS (100000, 500000, 1000000, 5000000)
   * @param secret Optional secret (generated if not provided)
   * @param nullifier Optional nullifier (generated if not provided)
   * @returns Commitment data
   */
  async deposit(
    denomination: number,
    secret?: bigint,
    nullifier?: bigint
  ): Promise<{ commitment: bigint; secret: bigint; nullifier: bigint }> {
    if (!PX402SDK.DENOMS.includes(denomination)) {
      throw new Error(
        `Invalid denomination. Must be one of: ${PX402SDK.DENOM_NAMES.join(', ')}`
      );
    }

    if (!this.merkleTree) {
      throw new Error('SDK not initialized. Call init() first.');
    }

    // Generate secret and nullifier if not provided
    secret = secret || this.randomField();
    nullifier = nullifier || this.randomField();

    // Compute commitment: Poseidon(secret, nullifier, denomination)
    const commitment = this.computeCommitment(secret, nullifier, BigInt(denomination));

    // Add to local Merkle tree
    const leafIndex = this.merkleTree.addLeaf(commitment);

    // Store commitment locally
    this.commitments.set(commitment.toString(), {
      secret,
      nullifier,
      denomination,
      spent: false,
      leafIndex,
    });

    console.log(
      `Deposited ${this.formatDenom(denomination)} USDC (commitment: ${commitment.toString().slice(0, 10)}...)`
    );

    // TODO: Call pool.deposit() on-chain
    // await this.walletClient.writeContract({
    //   address: this.config.poolAddress,
    //   abi: poolABI,
    //   functionName: 'deposit',
    //   args: [commitment, BigInt(denomination)],
    // });

    return { commitment, secret, nullifier };
  }

  /**
   * Generate ZK proof for payment
   * @param paymentAmount Amount to pay (must be a valid denomination)
   * @param merchant Recipient address
   * @returns Proof data for paymaster
   */
  async generateProof(paymentAmount: number, merchant: Address): Promise<ProofData> {
    if (!PX402SDK.DENOMS.includes(paymentAmount)) {
      throw new Error(
        `Invalid payment amount. Must be one of: ${PX402SDK.DENOM_NAMES.join(', ')}`
      );
    }

    if (!this.merkleTree) {
      throw new Error('SDK not initialized. Call init() first.');
    }

    // Select suitable commitment (smallest unspent >= paymentAmount)
    const commitmentData = this.selectCommitment(paymentAmount);
    if (!commitmentData) {
      throw new Error(
        `Insufficient funds. Need ${this.formatDenom(paymentAmount)} USDC, have ${this.getBalance()} USDC`
      );
    }

    const changeAmount = commitmentData.denomination - paymentAmount;
    const newSecret = this.randomField();
    const newNullifier = this.randomField();

    // Generate Merkle proof
    const oldCommitment = this.computeCommitment(
      commitmentData.secret,
      commitmentData.nullifier,
      BigInt(commitmentData.denomination)
    );

    const merkleProof = this.merkleTree.generateProof(oldCommitment);

    // Compute change commitment
    const changeCommitment = this.computeCommitment(
      newSecret,
      newNullifier,
      BigInt(changeAmount)
    );

    // Prepare circuit inputs
    const circuitInput = {
      nullifier: commitmentData.nullifier.toString(),
      secret: commitmentData.secret.toString(),
      denomination: commitmentData.denomination.toString(),
      newSecret: newSecret.toString(),
      newNullifier: newNullifier.toString(),
      pathElements: merkleProof.pathElements,
      pathIndices: merkleProof.pathIndices,
      root: merkleProof.root,
      paymentAmount: paymentAmount.toString(),
      changeAmount: changeAmount.toString(),
    };

    console.log(`Generating ZK proof for ${this.formatDenom(paymentAmount)} USDC payment...`);

    // Generate proof using snarkjs
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInput,
      this.config.wasmPath,
      this.config.zkeyPath
    );

    console.log('Proof generated successfully');

    // Mark old commitment as spent
    commitmentData.spent = true;

    // Store change commitment if changeAmount > 0
    if (changeAmount > 0) {
      const changeLeafIndex = this.merkleTree.addLeaf(changeCommitment);
      this.commitments.set(changeCommitment.toString(), {
        secret: newSecret,
        nullifier: newNullifier,
        denomination: changeAmount,
        spent: false,
        leafIndex: changeLeafIndex,
      });

      console.log(`Change: ${this.formatDenom(changeAmount)} USDC`);
    }

    return {
      proof,
      publicSignals,
      merchant,
      paymentAmount: BigInt(paymentAmount),
      changeCommitment,
      changeAmount: BigInt(changeAmount),
    };
  }

  /**
   * Get current balance (sum of unspent commitments)
   */
  getBalance(): string {
    let total = 0;
    for (const [_, comm] of this.commitments) {
      if (!comm.spent) {
        total += comm.denomination;
      }
    }
    return this.formatDenom(total);
  }

  /**
   * List all unspent commitments
   */
  getCommitments(): CommitmentData[] {
    return Array.from(this.commitments.values()).filter((c) => !c.spent);
  }

  /**
   * Export commitments for backup/persistence
   */
  exportCommitments(): string {
    const data = {
      commitments: Array.from(this.commitments.entries()),
      merkleTree: this.merkleTree?.exportState(),
    };
    return JSON.stringify(data);
  }

  /**
   * Import commitments from backup
   */
  importCommitments(json: string) {
    const data = JSON.parse(json);

    // Restore commitments
    this.commitments = new Map(data.commitments);

    // Restore Merkle tree
    if (data.merkleTree && this.merkleTree) {
      this.merkleTree.importState(data.merkleTree);
    }

    console.log(`Imported ${this.commitments.size} commitments`);
  }

  // ========== PRIVATE METHODS ==========

  private computeCommitment(secret: bigint, nullifier: bigint, denomination: bigint): bigint {
    return this.poseidon.F.toObject(this.poseidon([secret, nullifier, denomination]));
  }

  private randomField(): bigint {
    // Generate random 31-byte value (248 bits, safe for BN254 field)
    const bytes = new Uint8Array(31);
    crypto.getRandomValues(bytes);
    return BigInt('0x' + Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join(''));
  }

  private selectCommitment(amount: number): CommitmentData | null {
    // Find smallest unspent commitment >= amount
    let best: CommitmentData | null = null;

    for (const [_, comm] of this.commitments) {
      if (!comm.spent && comm.denomination >= amount) {
        if (!best || comm.denomination < best.denomination) {
          best = comm;
        }
      }
    }

    return best;
  }

  private formatDenom(amount: number): string {
    return (amount / 1_000_000).toFixed(2);
  }
}

// Export types
export * from './merkle';

// Export simple API (recommended for most users)
export { PX402, configurePX402, type StorageAdapter } from './px402';

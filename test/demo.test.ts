import { describe, it, expect, beforeAll } from 'vitest';
import { PX402SDK } from '../src/index';

describe('PX402 SDK Tests', () => {
  let sdk: PX402SDK;

  beforeAll(async () => {
    // Initialize SDK with test config
    sdk = new PX402SDK({
      poolAddress: '0x0000000000000000000000000000000000000000', // Replace after deployment
      paymasterAddress: '0x0000000000000000000000000000000000000000', // Replace after deployment
      usdcAddress: '0x0000000000000000000000000000000000000000', // Replace after deployment
      rpcUrl: process.env.BASE_SEPOLIA_RPC || 'https://sepolia.base.org',
      zkeyPath: './build/eligibility_final.zkey',
      wasmPath: './build/eligibility_js/eligibility.wasm',
      chainId: 84532, // Base Sepolia
    });

    await sdk.init();
  });

  describe('Deposit', () => {
    it('should deposit 1.00 USDC', async () => {
      const { commitment, secret, nullifier } = await sdk.deposit(1000000);

      expect(commitment).toBeDefined();
      expect(typeof commitment).toBe('bigint');
      expect(secret).toBeDefined();
      expect(nullifier).toBeDefined();

      const balance = sdk.getBalance();
      expect(balance).toBe('1.00');
    });

    it('should reject invalid denomination', async () => {
      await expect(sdk.deposit(123456)).rejects.toThrow('Invalid denomination');
    });

    it('should deposit multiple amounts', async () => {
      await sdk.deposit(100000); // 0.10 USDC
      await sdk.deposit(500000); // 0.50 USDC
      await sdk.deposit(5000000); // 5.00 USDC

      const balance = sdk.getBalance();
      expect(balance).toBe('6.60'); // 1.00 + 0.10 + 0.50 + 5.00
    });
  });

  describe('Proof Generation', () => {
    it('should generate proof for 0.10 USDC payment', async () => {
      // First deposit
      await sdk.deposit(1000000); // 1.00 USDC

      // Generate proof
      const merchantAddress = '0x1234567890123456789012345678901234567890';
      const proofData = await sdk.generateProof(100000, merchantAddress as any);

      expect(proofData.proof).toBeDefined();
      expect(proofData.publicSignals).toBeDefined();
      expect(proofData.publicSignals.length).toBe(5);
      expect(proofData.paymentAmount).toBe(BigInt(100000));
      expect(proofData.changeAmount).toBe(BigInt(900000)); // 0.90 USDC change
      expect(proofData.merchant).toBe(merchantAddress);
    });

    it('should handle change correctly', async () => {
      await sdk.deposit(5000000); // 5.00 USDC

      const initialBalance = sdk.getBalance();
      const merchantAddress = '0x1234567890123456789012345678901234567890';

      await sdk.generateProof(500000, merchantAddress as any); // Pay 0.50 USDC

      const commitments = sdk.getCommitments();
      const changeCommitment = commitments.find((c) => c.denomination === 4500000);

      expect(changeCommitment).toBeDefined();
      expect(changeCommitment?.spent).toBe(false);
    });

    it('should reject payment with insufficient funds', async () => {
      const merchantAddress = '0x1234567890123456789012345678901234567890';

      await expect(sdk.generateProof(10000000, merchantAddress as any)).rejects.toThrow(
        'Insufficient funds'
      );
    });
  });

  describe('Balance Management', () => {
    it('should calculate balance correctly', async () => {
      const sdk2 = new PX402SDK({
        poolAddress: '0x0000000000000000000000000000000000000000',
        paymasterAddress: '0x0000000000000000000000000000000000000000',
        usdcAddress: '0x0000000000000000000000000000000000000000',
        rpcUrl: 'https://sepolia.base.org',
        zkeyPath: './build/eligibility_final.zkey',
        wasmPath: './build/eligibility_js/eligibility.wasm',
      });

      await sdk2.init();

      await sdk2.deposit(1000000); // 1.00 USDC
      await sdk2.deposit(500000); // 0.50 USDC

      expect(sdk2.getBalance()).toBe('1.50');

      const merchantAddress = '0x1234567890123456789012345678901234567890';
      await sdk2.generateProof(100000, merchantAddress as any); // Pay 0.10 USDC

      // Balance should now be 0.50 (original) + 0.90 (change) = 1.40
      expect(sdk2.getBalance()).toBe('1.40');
    });
  });

  describe('Backup & Restore', () => {
    it('should export and import commitments', async () => {
      const sdk3 = new PX402SDK({
        poolAddress: '0x0000000000000000000000000000000000000000',
        paymasterAddress: '0x0000000000000000000000000000000000000000',
        usdcAddress: '0x0000000000000000000000000000000000000000',
        rpcUrl: 'https://sepolia.base.org',
        zkeyPath: './build/eligibility_final.zkey',
        wasmPath: './build/eligibility_js/eligibility.wasm',
      });

      await sdk3.init();

      await sdk3.deposit(1000000);
      await sdk3.deposit(500000);

      const exported = sdk3.exportCommitments();
      expect(exported).toBeDefined();

      // Create new SDK and import
      const sdk4 = new PX402SDK({
        poolAddress: '0x0000000000000000000000000000000000000000',
        paymasterAddress: '0x0000000000000000000000000000000000000000',
        usdcAddress: '0x0000000000000000000000000000000000000000',
        rpcUrl: 'https://sepolia.base.org',
        zkeyPath: './build/eligibility_final.zkey',
        wasmPath: './build/eligibility_js/eligibility.wasm',
      });

      await sdk4.init();
      sdk4.importCommitments(exported);

      expect(sdk4.getBalance()).toBe('1.50');
      expect(sdk4.getCommitments().length).toBe(2);
    });
  });
});

/**
 * Bundler integration for submitting UserOps with ZK proofs
 * Supports Stackup, Pimlico, and any ERC-4337 bundler
 */

import { ethers, JsonRpcProvider, AbiCoder } from 'ethers';

export interface UserOpParams {
  sender: string;              // Account address (can be deterministic for first tx)
  nonce: bigint;
  initCode: string;            // '0x' if account already deployed
  callData: string;            // Empty for paymaster-only tx
  callGasLimit: bigint;
  verificationGasLimit: bigint;
  preVerificationGas: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  paymasterAndData: string;    // Contains proof + merchant + amounts
  signature: string;            // '0x' if using paymaster
}

export interface ProofData {
  proof: any;
  publicSignals: string[];
  merchant: string;
  paymentAmount: bigint;
  changeCommitment: bigint;
  changeAmount: bigint;
}

/**
 * Bundler client for submitting UserOps
 */
export class BundlerClient {
  private provider: JsonRpcProvider;
  private bundlerUrl: string;
  private entryPoint: string;

  constructor(bundlerUrl: string, rpcUrl: string, entryPoint: string) {
    this.bundlerUrl = bundlerUrl;
    this.provider = new JsonRpcProvider(rpcUrl);
    this.entryPoint = entryPoint;
  }

  /**
   * Submit UserOp to bundler
   */
  async submitUserOp(userOp: UserOpParams): Promise<string> {
    // Format UserOp for bundler (convert BigInts to hex strings)
    const formattedOp = {
      sender: userOp.sender,
      nonce: '0x' + userOp.nonce.toString(16),
      initCode: userOp.initCode,
      callData: userOp.callData,
      callGasLimit: '0x' + userOp.callGasLimit.toString(16),
      verificationGasLimit: '0x' + userOp.verificationGasLimit.toString(16),
      preVerificationGas: '0x' + userOp.preVerificationGas.toString(16),
      maxFeePerGas: '0x' + userOp.maxFeePerGas.toString(16),
      maxPriorityFeePerGas: '0x' + userOp.maxPriorityFeePerGas.toString(16),
      paymasterAndData: userOp.paymasterAndData,
      signature: userOp.signature
    };

    console.log('\nSubmitting UserOp to bundler...');
    console.log('  Bundler:', this.bundlerUrl);
    console.log('  Sender:', formattedOp.sender);
    console.log('  Paymaster:', userOp.paymasterAndData.slice(0, 42));

    try {
      // Call eth_sendUserOperation
      const response = await fetch(this.bundlerUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'eth_sendUserOperation',
          params: [formattedOp, this.entryPoint]
        })
      });

      const result: any = await response.json();

      if (result.error) {
        throw new Error(`Bundler error: ${result.error.message}`);
      }

      const userOpHash = result.result;
      console.log('  ✓ UserOp submitted');
      console.log('  UserOp hash:', userOpHash);

      return userOpHash;
    } catch (error: any) {
      console.error('  ✗ Bundler submission failed:', error.message);
      throw error;
    }
  }

  /**
   * Wait for UserOp to be included in a block
   */
  async waitForUserOp(userOpHash: string, timeout = 60000): Promise<{
    success: boolean;
    txHash?: string;
    blockNumber?: number;
  }> {
    console.log('\nWaiting for UserOp confirmation...');
    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      try {
        const response = await fetch(this.bundlerUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: 'eth_getUserOperationReceipt',
            params: [userOpHash]
          })
        });

        const result: any = await response.json();

        if (result.result) {
          const receipt = result.result;
          console.log('  ✓ UserOp confirmed!');
          console.log('  Tx hash:', receipt.receipt.transactionHash);
          console.log('  Block:', receipt.receipt.blockNumber);
          console.log('  Success:', receipt.success);

          return {
            success: receipt.success,
            txHash: receipt.receipt.transactionHash,
            blockNumber: parseInt(receipt.receipt.blockNumber, 16)
          };
        }
      } catch (error) {
        // Receipt not available yet, continue waiting
      }

      // Wait 2 seconds before polling again
      await new Promise(resolve => setTimeout(resolve, 2000));
    }

    throw new Error('UserOp confirmation timeout');
  }

  /**
   * Estimate gas for UserOp
   */
  async estimateUserOpGas(userOp: UserOpParams): Promise<{
    callGasLimit: bigint;
    verificationGasLimit: bigint;
    preVerificationGas: bigint;
  }> {
    const formattedOp = {
      sender: userOp.sender,
      nonce: '0x' + userOp.nonce.toString(16),
      initCode: userOp.initCode,
      callData: userOp.callData,
      paymasterAndData: userOp.paymasterAndData,
      signature: userOp.signature,
      maxFeePerGas: '0x' + userOp.maxFeePerGas.toString(16),
      maxPriorityFeePerGas: '0x' + userOp.maxPriorityFeePerGas.toString(16)
    };

    try {
      const response = await fetch(this.bundlerUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'eth_estimateUserOperationGas',
          params: [formattedOp, this.entryPoint]
        })
      });

      const result: any = await response.json();

      if (result.error) {
        console.warn('Gas estimation failed, using defaults');
        return {
          callGasLimit: BigInt(100000),
          verificationGasLimit: BigInt(300000),
          preVerificationGas: BigInt(50000)
        };
      }

      return {
        callGasLimit: BigInt(result.result.callGasLimit),
        verificationGasLimit: BigInt(result.result.verificationGasLimit),
        preVerificationGas: BigInt(result.result.preVerificationGas)
      };
    } catch (error) {
      console.warn('Gas estimation error, using defaults');
      return {
        callGasLimit: BigInt(100000),
        verificationGasLimit: BigInt(300000),
        preVerificationGas: BigInt(50000)
      };
    }
  }

  /**
   * Get current gas prices
   */
  async getGasPrices(): Promise<{
    maxFeePerGas: bigint;
    maxPriorityFeePerGas: bigint;
  }> {
    const feeData = await this.provider.getFeeData();

    return {
      maxFeePerGas: feeData.maxFeePerGas || BigInt(1000000000), // 1 gwei default
      maxPriorityFeePerGas: feeData.maxPriorityFeePerGas || BigInt(1000000000)
    };
  }
}

/**
 * Encode proof and payment data for paymasterAndData field
 */
export function encodePaymasterData(
  paymasterAddress: string,
  proofData: ProofData
): string {
  const { proof, publicSignals, merchant, paymentAmount, changeCommitment, changeAmount } = proofData;

  // Extract Groth16 proof elements
  const proofA = [proof.pi_a[0], proof.pi_a[1]];
  const proofB = [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]]];
  const proofC = [proof.pi_c[0], proof.pi_c[1]];

  // Flatten proof for ABI encoding
  const proofFlat = [
    ...proofA,
    ...proofB[0],
    ...proofB[1],
    ...proofC
  ];

  // Encode: address(paymaster) + proof + publicSignals + merchant + amounts
  const abiCoder = AbiCoder.defaultAbiCoder();

  const encodedProof = abiCoder.encode(
    ['uint256[8]', 'uint256[5]', 'address', 'uint256', 'bytes32', 'uint256'],
    [
      proofFlat,
      publicSignals,
      merchant,
      paymentAmount,
      changeCommitment,
      changeAmount
    ]
  );

  // paymasterAndData = address(20 bytes) + encodedData
  return paymasterAddress + encodedProof.slice(2);
}

/**
 * Create a deterministic sender address (Simple Account)
 * For first-time users without an account yet
 */
export function getDeterministicSender(
  owner: string,
  salt: number = 0
): string {
  // For MVP, just use owner address
  // In production, use CREATE2 to compute deterministic address
  return owner;
}

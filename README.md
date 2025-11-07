# @prxvt/sdk - Privacy-Preserving X402 Payments

Zero-knowledge privacy layer for X402 (Coinbase/Cloudflare's HTTP 402 payment protocol). Enables gasless, anonymous USDC payments on Base using ZK-SNARKs and ERC-4337 account abstraction.

## Features

- **Sender Anonymity**: Payments routed through paymaster, no user address on-chain
- **Fixed Denominations**: 0.10, 0.50, 1.00, 5.00 USDC (reduces amount leakage)
- **UTXO Model**: Deposit once, pay multiple times with change commitments
- **Gasless**: ERC-4337 paymaster sponsors all transactions
- **ZK Proofs**: Groth16 SNARKs prove commitment ownership without revealing secrets

## Architecture

```
User Deposit → MerklePool (commitment = Poseidon(secret, nullifier, amount))
                  ↓
              Merkle Tree (off-chain, 2^20 capacity)
                  ↓
Payment: Generate ZK proof → UserOp to Bundler → EntryPoint
                  ↓
         ZKPaymaster verifies proof → MerklePool sponsors payment
                  ↓
         USDC transferred to merchant, change commitment created
```

## Installation

### Prerequisites

1. **Node.js** (v18+)
2. **Circom** (for circuit compilation):
   ```bash
   curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
   git clone https://github.com/iden3/circom.git
   cd circom && cargo build --release && cargo install --path circom
   ```
3. **Foundry** (for contracts):
   ```bash
   curl -L https://foundry.paradigm.xyz | bash
   foundryup
   ```

### Setup

```bash
# Clone and install dependencies
git clone <repo-url>
cd sdk
npm install

# Install Foundry dependencies
forge install OpenZeppelin/openzeppelin-contracts
forge install eth-infinitism/account-abstraction

# Compile circuit
npm run circuits:compile

# Download Powers of Tau (ceremony file)
wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_20.ptau -O build/powersOfTau28_hez_final_20.ptau

# Run trusted setup
snarkjs groth16 setup build/eligibility.r1cs build/powersOfTau28_hez_final_20.ptau build/eligibility_0000.zkey
snarkjs zkey contribute build/eligibility_0000.zkey build/eligibility_final.zkey --name="First contributor" -v

# Export verifier contract
snarkjs zkey export solidityverifier build/eligibility_final.zkey contracts/Verifier.sol

# Build contracts
forge build
```

## Deployment (Base Sepolia)

```bash
# Set environment variables
export PRIVATE_KEY=<your-private-key>
export BASE_SEPOLIA_RPC=https://sepolia.base.org

# Deploy contracts
forge script scripts/Deploy.s.sol:DeployScript --rpc-url $BASE_SEPOLIA_RPC --broadcast --verify

# Save output addresses to .env
# POOL_ADDRESS=0x...
# PAYMASTER_ADDRESS=0x...
# USDC_ADDRESS=0x...
```

## Usage

### Initialize SDK

```typescript
import { PX402SDK } from '@prxvt/sdk';

const sdk = new PX402SDK({
  poolAddress: '0x...', // MerklePool contract
  paymasterAddress: '0x...', // ZKPaymaster contract
  usdcAddress: '0x...', // USDC token (or MockUSDC on testnet)
  rpcUrl: 'https://sepolia.base.org',
  zkeyPath: './build/eligibility_final.zkey',
  wasmPath: './build/eligibility_js/eligibility.wasm',
  chainId: 84532, // Base Sepolia
});

await sdk.init();
```

### Deposit USDC

```typescript
// Approve USDC first (via wallet)
// usdc.approve(poolAddress, amount)

// Deposit 1.00 USDC (1000000 = 1.00 USDC with 6 decimals)
const { commitment, secret, nullifier } = await sdk.deposit(1000000);

// IMPORTANT: Backup secret and nullifier! If lost, funds are unrecoverable.
console.log('Secret:', secret.toString());
console.log('Nullifier:', nullifier.toString());

// Check balance
console.log('Balance:', sdk.getBalance()); // "1.00"
```

### Make Payment

```typescript
// Generate ZK proof for 0.10 USDC payment
const merchantAddress = '0x1234...'; // X402 merchant address
const proofData = await sdk.generateProof(100000, merchantAddress);

// Submit UserOp via bundler (Stackup, Pimlico, etc.)
const userOp = {
  // ... standard ERC-4337 UserOp fields
  paymasterAndData: encodePaymasterData(proofData), // Encode proof for paymaster
};

// Bundler submits to EntryPoint → Paymaster verifies → Payment sponsored
```

### Backup & Restore

```typescript
// Export commitments (store securely!)
const backup = sdk.exportCommitments();
localStorage.setItem('px402_backup', backup);

// Restore on new device
const sdk2 = new PX402SDK(config);
await sdk2.init();
sdk2.importCommitments(localStorage.getItem('px402_backup'));

console.log('Restored balance:', sdk2.getBalance());
```

## Contract Addresses

### Base Sepolia (Testnet)

| Contract | Address |
|----------|---------|
| EntryPoint (ERC-4337) | `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789` |
| MerklePool | TBD (deploy with script) |
| ZKPaymaster | TBD (deploy with script) |
| MockUSDC | TBD (deploy with script) |
| Verifier | TBD (generated from circuit) |

### Base Mainnet

Coming soon.

## API Reference

### `PX402SDK`

#### `init(): Promise<void>`
Initialize SDK (build Poseidon hash, create Merkle tree). **Must call before any operations.**

#### `deposit(denomination: number, secret?: bigint, nullifier?: bigint): Promise<{commitment, secret, nullifier}>`
Deposit USDC to pool. `denomination` must be `100000`, `500000`, `1000000`, or `5000000` (0.10, 0.50, 1.00, 5.00 USDC).

#### `generateProof(paymentAmount: number, merchant: Address): Promise<ProofData>`
Generate ZK proof for payment. Returns proof data to submit via ERC-4337 bundler.

#### `getBalance(): string`
Get current balance (sum of unspent commitments) in USDC.

#### `getCommitments(): CommitmentData[]`
List all unspent commitments.

#### `exportCommitments(): string`
Export commitments as JSON for backup.

#### `importCommitments(json: string): void`
Import commitments from backup.

## Security

### Current Status: TESTNET ONLY

**DO NOT USE IN PRODUCTION.** This is experimental software with the following limitations:

1. **Trusted Setup**: Circuit uses single-party ceremony (insecure for production). Need multi-party MPC.
2. **Merkle Tree**: Uses keccak256 on-chain (gas inefficient). Should use Poseidon or off-chain indexer.
3. **No Audit**: Contracts and circuits not audited.
4. **Secret Management**: Secrets stored in-memory. Need secure enclave/hardware wallet integration.

### Best Practices

- **Backup secrets**: If lost, funds are **permanently** unrecoverable.
- **Use hardware wallet**: Don't expose private keys.
- **Test on Sepolia first**: Verify everything works before mainnet.
- **Limit deposits**: Start with small amounts (0.10-1.00 USDC).

## Development

```bash
# Run tests
npm test

# Build SDK
npm run build

# Compile contracts
forge build

# Run contract tests
forge test
```

## Troubleshooting

### "SDK not initialized"
Call `await sdk.init()` before any operations.

### "Invalid denomination"
Use only `100000`, `500000`, `1000000`, or `5000000` (0.10, 0.50, 1.00, 5.00 USDC).

### "Insufficient funds"
Deposit more USDC or use smaller payment denomination.

### "Commitment not found in tree"
Merkle tree desync. Re-import commitments or check on-chain events.

### Circuit compilation fails
Ensure Circom installed: `circom --version`. Check `circomlib` in `node_modules`.

## License

MIT

## Contributing

Issues and PRs welcome! Please test thoroughly on Sepolia.

## Acknowledgments

- **Coinbase/Cloudflare** - X402 protocol
- **Ethereum Foundation** - ERC-4337 account abstraction
- **iden3** - Circom, snarkjs, circomlib
- **Pimlico/Stackup** - ERC-4337 bundlers
- **Tornado Cash** - Merkle tree + nullifier design inspiration

---

**Built with**: Circom, Groth16, Poseidon, ERC-4337, Base L2, USDC

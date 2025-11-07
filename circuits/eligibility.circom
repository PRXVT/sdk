pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/mux1.circom";
include "circomlib/circuits/comparators.circom";

// Merkle tree inclusion proof with proper path ordering
template MerkleTreeInclusion(nLevels) {
    signal input leaf;
    signal input root;
    signal input pathElements[nLevels];
    signal input pathIndices[nLevels]; // 0 or 1 for left/right

    signal currentHash[nLevels + 1];
    currentHash[0] <== leaf;

    component hashers[nLevels];
    component mux[nLevels];

    for (var i = 0; i < nLevels; i++) {
        // Order sibling based on path index
        // If pathIndex == 0: current is left, sibling is right
        // If pathIndex == 1: sibling is left, current is right
        mux[i] = MultiMux1(2);
        mux[i].c[0][0] <== currentHash[i];
        mux[i].c[0][1] <== pathElements[i];
        mux[i].c[1][0] <== pathElements[i];
        mux[i].c[1][1] <== currentHash[i];
        mux[i].s <== pathIndices[i];

        // Hash ordered pair
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== mux[i].out[0];
        hashers[i].inputs[1] <== mux[i].out[1];
        currentHash[i + 1] <== hashers[i].out;
    }

    // Final hash must equal root
    root === currentHash[nLevels];
}

// Main eligibility proof circuit with UTXO model
template EligibilityProof(nLevels) {
    // Private inputs (secrets)
    signal input nullifier;
    signal input secret;
    signal input denomination; // Original denomination (e.g., 1000000 = 1.00 USDC)
    signal input newSecret; // For change commitment
    signal input newNullifier;
    signal input pathElements[nLevels];
    signal input pathIndices[nLevels];

    // Public inputs
    signal input root; // From root buffer
    signal input paymentAmount; // Fixed denomination being spent (0.10, 0.50, 1.00, 5.00)
    signal input changeAmount; // denomination - paymentAmount

    // Public outputs
    signal output changeCommitment;
    signal output nullifierHash; // Prevents double-spend

    // 1. Compute original commitment: Poseidon(secret, nullifier, denomination)
    component commitment = Poseidon(3);
    commitment.inputs[0] <== secret;
    commitment.inputs[1] <== nullifier;
    commitment.inputs[2] <== denomination;

    // 2. Prove Merkle inclusion of commitment
    component inclusion = MerkleTreeInclusion(nLevels);
    inclusion.leaf <== commitment.out;
    inclusion.root <== root;
    for (var i = 0; i < nLevels; i++) {
        inclusion.pathElements[i] <== pathElements[i];
        inclusion.pathIndices[i] <== pathIndices[i];
    }

    // 3. Verify change math: denomination = paymentAmount + changeAmount
    component sumCheck = IsEqual();
    sumCheck.in[0] <== paymentAmount + changeAmount;
    sumCheck.in[1] <== denomination;
    sumCheck.out === 1;

    // 4. Ensure changeAmount >= 0 (no negative change)
    component changePositive = GreaterEqThan(64);
    changePositive.in[0] <== changeAmount;
    changePositive.in[1] <== 0;
    changePositive.out === 1;

    // 5. Compute change commitment: Poseidon(newSecret, newNullifier, changeAmount)
    component changeComm = Poseidon(3);
    changeComm.inputs[0] <== newSecret;
    changeComm.inputs[1] <== newNullifier;
    changeComm.inputs[2] <== changeAmount;
    changeCommitment <== changeComm.out;

    // 6. Hash nullifier to prevent linkability (double-spend protection)
    component nullHash = Poseidon(1);
    nullHash.inputs[0] <== nullifier;
    nullifierHash <== nullHash.out;
}

component main { public [root, paymentAmount, changeAmount] } = EligibilityProof(20); // 2^20 leaves (1M capacity)

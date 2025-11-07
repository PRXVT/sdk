import { IncrementalMerkleTree } from '@zk-kit/incremental-merkle-tree';

export interface MerkleProof {
  root: string;
  pathElements: string[];
  pathIndices: number[];
  leaf: bigint;
  leafIndex: number;
}

/**
 * Merkle tree manager for commitments
 * Uses Poseidon hash matching the Circom circuit
 */
export class MerkleTreeManager {
  private tree: IncrementalMerkleTree;
  private leaves: Map<string, number>; // commitment -> leafIndex

  /**
   * @param depth Tree depth (default 20 for 2^20 = 1M leaves)
   * @param poseidonHash Poseidon hash function from circomlibjs
   */
  constructor(
    private depth: number = 20,
    private poseidonHash: (inputs: bigint[]) => bigint
  ) {
    // Initialize incremental Merkle tree with Poseidon hash
    this.tree = new IncrementalMerkleTree(
      ((a: bigint, b: bigint) => this.poseidonHash([a, b])) as any,
      depth,
      BigInt(0), // Zero value
      2 // Arity (binary tree)
    );
    this.leaves = new Map();
  }

  /**
   * Add commitment to tree
   * @param commitment Poseidon(secret, nullifier, denomination)
   * @returns Leaf index
   */
  addLeaf(commitment: bigint): number {
    const leafIndex = this.tree.indexOf(commitment);

    if (leafIndex === -1) {
      // Leaf doesn't exist, insert it
      this.tree.insert(commitment);
      const newIndex = this.tree.leaves.length - 1;
      this.leaves.set(commitment.toString(), newIndex);
      return newIndex;
    }

    // Leaf already exists
    return leafIndex;
  }

  /**
   * Generate Merkle proof for a commitment
   * @param commitment The commitment to generate proof for
   * @returns Merkle proof with root, path, and indices
   */
  generateProof(commitment: bigint): MerkleProof {
    const leafIndex = this.leaves.get(commitment.toString());

    if (leafIndex === undefined) {
      throw new Error(`Commitment not found in tree: ${commitment}`);
    }

    const proof = this.tree.createProof(leafIndex);

    return {
      root: this.tree.root.toString(),
      pathElements: proof.siblings.map((s) => s[0].toString()),
      pathIndices: proof.pathIndices,
      leaf: commitment,
      leafIndex,
    };
  }

  /**
   * Get current root
   */
  getRoot(): string {
    return this.tree.root.toString();
  }

  /**
   * Get total number of leaves
   */
  getLeafCount(): number {
    return this.tree.leaves.length;
  }

  /**
   * Check if commitment exists
   */
  hasLeaf(commitment: bigint): boolean {
    return this.leaves.has(commitment.toString());
  }

  /**
   * Export tree state for persistence
   */
  exportState(): {
    leaves: [string, number][];
    depth: number;
  } {
    return {
      leaves: Array.from(this.leaves.entries()),
      depth: this.depth,
    };
  }

  /**
   * Import tree state from persistence
   */
  importState(state: { leaves: [string, number][]; depth: number }) {
    if (state.depth !== this.depth) {
      throw new Error('Tree depth mismatch');
    }

    // Reconstruct tree by inserting leaves in order
    const sortedLeaves = state.leaves.sort((a, b) => a[1] - b[1]);

    for (const [commitment, index] of sortedLeaves) {
      const leaf = BigInt(commitment);
      this.tree.insert(leaf);
      this.leaves.set(commitment, index);
    }
  }
}

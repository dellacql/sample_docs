AlmaGill: A Proof-of-Stake pBFT Blockchain

## Introduction

AlmaGill is a cryptocurrency implemented with a Proof-of-Stake (PoS) Practical Byzantine Fault Tolerance (pBFT) consensus mechanism.  This design is intended to achieve an efficient consensus mechanism that increases throughput rate of blocks while maintaining the security of the network.  This document provides a high-level overview of the AlmaGill implementation.

## Key Features
Coin quantity is initated from the creation of the Data object. After the tokens are initiated they are never created or destroyed, instead coin is divided into new accounts indefinitely. With a highly divisible token there is no limit to how many accounts can be created or the number of transactions the coin can embrace.
There is no intrinsic constraint on the number of blocks that can be verified at any given time. The only limitation to throughput is the capacity of verifying nodes.
Validator selection is based on the amount of AlmaGill tokens held (staked).  This mechanism promotes decentralization and energy efficiency. With a minimal stake required we can resist attacks from malevolent users and because new tokens can never be created or destroyed we can ensure that a bad actors cannot infiltrate.
*   **Practical Byzantine Fault Tolerance (pBFT):** A consensus algorithm that allows the network to tolerate up to a third of malicious or faulty nodes, ensuring data integrity and security.
*   **Transactions:** Supports standard cryptocurrency transactions including sending and receiving AlmaGill.  New account creation is also supported via transactions. By creating a mechanism where only an existing account holder can create a new account through a transaction we can ensure that only trusted parties are able to transact.
*   **Simplified Implementation:** This is a simplified simulation that focuses on core PoS pBFT concepts.
*   **Networking:**  Nodes communicate with each other over TCP sockets. Obviously once we achieve full production mechanism we will ensure a more robust method of communication between verifiers.

## Architecture

The AlmaGill blockchain consists of the following key components:

*   **Node:**  Represents a participant in the AlmaGill network.
    *   Manages transactions.
    *   Participates in the consensus process (PoS pBFT).
    *   Maintains a local copy of the blockchain.
*   **DataObject:**  Represents the state of the blockchain.
    *   Maintains account balances.
    *   Validates transactions.
    *   Applies valid transactions to update the state.
    *   Determines eligible validators based on stake.
*   **Transaction:**  Represents a transfer of AlmaGill tokens between accounts.
*   **Block:**  A collection of transactions, along with metadata (timestamp, previous hash, etc.).
*   **Consensus (PoS pBFT):**
    *   **Leader Election (PoS):** The primary node (leader) is selected based on stake and view number.
    *   **Proposal Phase:** The primary node proposes a new block.
    *   **Prepare Phase:** Validators agree on the proposed block.
    *   **Commit Phase:** Validators commit to the block, making it part of the blockchain.

## How it Works

1.  **Staking:** Users stake AlmaGill tokens to become eligible validators.  A minimum stake is required.
2.  **Leader Election:**  The system deterministically elects a primary node (leader) based on the staked tokens and the current view number.
3.  **Block Proposal:** The leader proposes a new block containing pending transactions.
4.  **Consensus:** The pBFT consensus mechanism is used to ensure agreement on the new block among the validators.
5.  **Block Addition:**  Once the block is committed, it is added to the blockchain, and the state is updated.
6.  **View Change:** The system advances to the next view, and a new leader is elected.

## Running the Simulation

1.  **Prerequisites:**
    *   Python 3.6 or higher.
    *   Cryptography library: `pip install cryptography`

2.  **Configuration:**
    *   `NODE_ADDRESSES`: Configure the IP addresses and ports for each node in the `NODE_ADDRESSES` list.  Ensure that the ports are open on your system.  The current configuration uses localhost addresses (127.0.0.1) on different ports.
    *   `initial_balances`: Modify the initial balances for each node in the `initial_balances` dictionary.
    *   `validator_addresses`: Change which keys you want to use as validators.

3.  **Execution:**
    *   Run the `AlmaGill.py` script.  This will start the simulation, creating three nodes that participate in the blockchain network.

## Notes and Limitations

*   **Simplified Implementation:** This is a simplified simulation for educational and demonstrative purposes.  It lacks features found in real-world blockchains (e.g., networking discovery, persistence, advanced transaction types).
*   **Local Simulation:** The current implementation runs all nodes on a single machine (localhost).  A production blockchain would require nodes to be distributed across multiple machines.
*   **Security Considerations:**  The cryptography used in this simulation is for demonstration purposes only.  A real-world blockchain would require more robust security measures.
*   **No Persistence:** The blockchain data is lost when the simulation is stopped.

## Future Development

*   Implement Merkle Root Calculation
*   Implement a Gossip Protocol for node discovery
*   Implement a Staking and Delegation mechanism.
*   Implement more complex transaction types (e.g., smart contracts).
*   Improve the networking layer for scalability and reliability.
*   Implement persistence to store the blockchain data on disk.

## License

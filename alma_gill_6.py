# -*- coding: utf-8 -*-
"""
Created on Sun Mar 23 18:58:40 2025

@author: Lucian
"""

import hashlib
import json
import time
import socket
import threading
import random
from threading import Lock
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature

# --- Constants ---
NODE_ADDRESSES = ["127.0.0.1:8001", "127.0.0.1:8002", "127.0.0.1:8003"]
# --- Cryptography and Hashing ---

def hash_block(block):
    block_string = json.dumps(block, sort_keys=True).encode()
    return hashlib.sha256(block_string).hexdigest()

def verify_signature(public_key, signature, message):
    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False

# --- Data Structures ---

class Transaction:
    def __init__(self, sender_address, recipient_address, amount, signature=None, new_account_address=None):
        self.sender_address = sender_address
        self.recipient_address = recipient_address
        self.amount = amount
        self.signature = signature
        self.new_account_address = new_account_address

    def sign_transaction(self, private_key):
        message = str(self.sender_address) + str(self.recipient_address) + str(self.amount) + str(self.new_account_address)
        message = message.encode('utf-8')
        signature = private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        self.signature = signature

    def to_dict(self):
        return {
            'sender_address': self.sender_address,
            'recipient_address': self.recipient_address,
            'amount': self.amount,
            'signature': self.signature.hex() if self.signature else None,
            'new_account_address': self.new_account_address
        }

    @classmethod
    def from_dict(cls, data):
        signature = bytes.fromhex(data['signature']) if data['signature'] else None
        return cls(data['sender_address'], data['recipient_address'], data['amount'], signature, data['new_account_address'])

    def __str__(self):
        return f"Transaction(sender={self.sender_address}, recipient={self.recipient_address}, amount={self.amount}, new_account={self.new_account_address}, signature={self.signature})"

class Block:
    def __init__(self, timestamp, transactions, previous_hash, merkle_root, bft_signatures=None):  # No nonce
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.merkle_root = merkle_root
        self.bft_signatures = bft_signatures if bft_signatures is not None else []

    def to_dict(self):
        return {
            'timestamp': self.timestamp,
            'transactions': [tx.to_dict() for tx in self.transactions],
            'previous_hash': self.previous_hash,
            'merkle_root': self.merkle_root,
            'bft_signatures': self.bft_signatures
        }

    @classmethod
    def from_dict(cls, data):
        transactions = [Transaction.from_dict(tx_data) for tx_data in data['transactions']]
        return cls(data['timestamp'], transactions, data['previous_hash'], data['merkle_root'], data['bft_signatures'])
    
    
# --- Data Object and Validation ---

class DataObject:
    def __init__(self, initial_balances, validator_addresses):
        self.balances = initial_balances
        self.total_supply = sum(self.balances.values())
        self.lock = Lock()
        self.validator_addresses = validator_addresses # Public keys of BFT validators

    def validate_transaction(self, transaction, public_keys):
        # Verify Signature
        try:
            public_key = serialization.load_pem_public_key(transaction.sender_address.encode('utf-8'))
            message = str(transaction.sender_address) + str(transaction.recipient_address) + str(transaction.amount) + str(transaction.new_account_address)
            message = message.encode('utf-8')
            public_key.verify(
                transaction.signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
        except InvalidSignature:
            print("Invalid signature")
            return False

        # Sender Existence
        if transaction.sender_address not in self.balances:
            print("Sender does not exist")
            return False

        # Sufficient Balance
        if self.balances[transaction.sender_address] < transaction.amount:
            print("insufficient funds")
            return False

        # New Account Creation Check
        if transaction.new_account_address:
            if transaction.new_account_address in self.balances:
                print("Account already exists")
                return False
        return True

    def apply_transaction(self, transaction, public_keys):
        with self.lock:
            if not self.validate_transaction(transaction, public_keys):
                return False

            # Transfer Funds
            self.balances[transaction.sender_address] -= transaction.amount
            if transaction.recipient_address in self.balances:
                self.balances[transaction.recipient_address] += transaction.amount
            else:
                self.balances[transaction.recipient_address] = transaction.amount

            # Create New Account
            if transaction.new_account_address:
                self.balances[transaction.new_account_address] = 0.0

            # Total Balance Check
            current_total = sum(self.balances.values())
            if abs(current_total - self.total_supply) > 1e-9:
                print(f"Total balance mismatch! Was {self.total_supply}, now {current_total}")
                # Revert the Transaction
                return False
            return True

    def get_balance(self, address):
        with self.lock:
            return self.balances.get(address, 0.0)

    def to_json(self):
        with self.lock:
            return json.dumps(self.balances)

    def from_json(self, json_str):
        with self.lock:
            self.balances = json.loads(json_str)

# --- BFT Consensus (Simplified Tendermint-like) ---

# Messages
PREVOTE = "PREVOTE"
PRECOMMIT = "PRECOMMIT"
PROPOSE = "PROPOSE"

BFT_THRESHOLD = 0.66  # Required percentage of signatures for BFT

# --- Node Implementation (with Networking) ---

class Node:
    def __init__(self, data_object, private_key, address, initial_validators):
        self.data_object = data_object
        self.private_key = private_key
        self.public_key = self.private_key.public_key()
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        self.address = address  # IP:Port
        self.pending_transactions = []
        self.last_block_hash = "0"  # Genesis block's hash
        self.all_keys = []  # All private keys this node has access to
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ip, port_str = self.address.split(":")  # Split into IP and port string
        port = int(port_str)  # Convert port to integer
        self.server_socket.bind((ip, port))  # Bind with IP and integer port
        self.server_socket.listen()
        self.peers = initial_validators  # List of known node addresses, should be updated through a Gossip protocol
        self.lock = threading.Lock()
        self.current_round = 0 #Track which round we are in
        self.votes = {PREVOTE: {}, PRECOMMIT: {}} #Track votes
        self.is_proposer = False
        self.leader_election()
        self.start_listening()

    def create_transaction(self, recipient_address, amount, new_account_address=None):
        transaction = Transaction(self.public_key_pem, recipient_address, amount, new_account_address=new_account_address)
        transaction.sign_transaction(self.private_key)
        self.pending_transactions.append(transaction)
        self.broadcast_transaction(transaction)
        return transaction

    def broadcast_transaction(self, transaction):
      # Broadcast transaction to all known peers
      for peer_address in self.peers:
        if peer_address != self.address:
          self.send_message(peer_address, {"type": "TRANSACTION", "transaction": transaction.to_dict()})

    def leader_election(self):
        """Simple round-robin leader election"""
        leader_index = self.current_round % len(self.peers)
        if self.address == self.peers[leader_index]:
            self.is_proposer = True
            print(f"{self.address} is the proposer for round {self.current_round}")
        else:
            self.is_proposer = False
            print(f"{self.address} is NOT the proposer for round {self.current_round}")


    def create_block(self):
        timestamp = time.time()
        merkle_root = "Not Implemented"  # Implement Merkle Root Calculation
        block = Block(timestamp, self.pending_transactions, self.last_block_hash, merkle_root)
        return block

    def propose_block(self, block):
      """Propose the block and broadcast to all other nodes"""
      if not self.is_proposer:
          print("I am not proposer")
          return
      print(f"{self.address} is proposing a block in round {self.current_round} with {len(block.transactions)} transactions")
      message = {"type": PROPOSE, "block": block.to_dict(), "round": self.current_round}
      self.broadcast_message(message)

    def sign_message(self, message):
        """Sign a given message"""
        message_str = json.dumps(message, sort_keys=True).encode()
        signature = self.private_key.sign(
            message_str,
            ec.ECDSA(hashes.SHA256())
        )
        return signature.hex()

    def verify_message(self, message, signature, public_key):
        """Verify signature on a given message"""
        try:
            message_str = json.dumps(message, sort_keys=True).encode()
            public_key.verify(
                bytes.fromhex(signature),
                message_str,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False

    def handle_pre_vote(self, message, peer_address):
        """Handle pre-vote message"""
        block_hash = message["block_hash"]
        signature = message["signature"]
        round_number = message["round"]
        # Verify signature and round number
        public_key = serialization.load_pem_public_key(message["public_key"].encode('utf-8'))
        is_verified = self.verify_message(message["message"], signature, public_key)

        if not is_verified:
            print("Signature is not valid")
            return

        with self.lock:
            # Ensure round number and create list for this round if required
            if round_number != self.current_round:
                print("Wrong round number")
                return

            #Add a pre-vote from the validator if we don't already have one
            if peer_address not in self.votes[PREVOTE]:
                #Save a pre-vote message and signature
                self.votes[PREVOTE][peer_address] = (message["message"], signature)

            if len(self.votes[PREVOTE]) > len(self.peers)*BFT_THRESHOLD:
                self.handle_pre_commit(block_hash, peer_address, round_number)

    def handle_pre_commit(self, block_hash, peer_address, round_number):
        """Handle pre-commit message"""
        signature = peer_address
        with self.lock:
            if round_number != self.current_round:
                print("Wrong round number")
                return

            #Add a pre-commit from the validator if we don't already have one
            if peer_address not in self.votes[PRECOMMIT]:
                #Save a pre-commit message and signature
                self.votes[PRECOMMIT][peer_address] = signature

            if len(self.votes[PRECOMMIT]) > len(self.peers)*BFT_THRESHOLD:
                #Once we have enough, apply the block and start the next round
                print(f"{self.address} is committing the block")
                #Construct a block
                self.apply_block(block_hash)
                self.next_round()

    def handle_propose(self, message, peer_address):
        """Handle propose message from the proposer"""
        block_dict = message["block"]
        round_number = message["round"]
        block = Block.from_dict(block_dict)
        #Verify the message
        public_keys = [key.public_key() for key in self.all_keys]
        public_keys_pem = []
        for public_key in public_keys:
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            public_keys_pem.append(public_key_pem)
        #Validate transactions
        for transaction in block.transactions:
            is_valid = self.data_object.validate_transaction(transaction, public_keys_pem)
            if not is_valid:
                return

        # Hash the block
        block_hash = hash_block(block.to_dict())

        #Create pre-vote message
        pre_vote_message = {"type": PREVOTE,
                            "block_hash": block_hash,
                            "signature": None,
                            "round": round_number,
                            "message": "Sending a pre-vote",
                            "public_key": self.public_key_pem}
        #Sign the block and broadcast
        self.send_pre_vote(pre_vote_message, block_hash, round_number)

    def send_pre_vote(self, message, block_hash, round_number):
        """Sign and broadcast pre-vote message"""
        #Sign the message
        signature = self.sign_message(message["message"])
        message["signature"] = signature
        self.broadcast_message(message)
        #Call handle pre-vote so we have one
        self.handle_pre_vote(message, self.address)
        print(f"{self.address} is sending a pre-vote for {block_hash}")

    def apply_block(self, block_hash):
        """Applies the block to the data object and discards the block data."""
        public_keys = [key.public_key() for key in self.all_keys]
        public_keys_pem = []
        for public_key in public_keys:
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            public_keys_pem.append(public_key_pem)
        for transaction in self.pending_transactions:
            is_applied = self.data_object.apply_transaction(transaction, public_keys_pem)
            if not is_applied:
                return

        self.last_block_hash = block_hash
        self.pending_transactions = []  # Clear pending transactions

    def next_round(self):
      """Move to the next round"""
      with self.lock:
        # Clear votes and go to the next round
        self.votes[PREVOTE] = {}
        self.votes[PRECOMMIT] = {}
        self.current_round += 1
        self.leader_election()
        print(f"{self.address} has started round {self.current_round}")

        #Propose a block
        if self.is_proposer:
          block = self.create_block()
          self.propose_block(block)

    def send_message(self, peer_address, message):
        """Send a message to a peer."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(tuple(peer_address.split(":")))
            message_str = json.dumps(message)
            sock.sendall(message_str.encode())
            sock.close()
        except Exception as e:
            print(f"Error sending message to {peer_address}: {e}")

    def broadcast_message(self, message):
        """Broadcast a message to all known peers."""
        for peer_address in self.peers:
            if peer_address != self.address:
                self.send_message(peer_address, message)

    def handle_connection(self, client_socket, client_address):
        """Handle an incoming connection."""
        try:
            data = client_socket.recv(4096).decode()
            if data:
                message = json.loads(data)
                message_type = message["type"]
                if message_type == "TRANSACTION":
                    transaction_data = message["transaction"]
                    transaction = Transaction.from_dict(transaction_data)
                    self.pending_transactions.append(transaction)
                elif message_type == PROPOSE:
                    print(f"{self.address} has received a new propose for block")
                    self.handle_propose(message, client_address[0] + ":"+ str(client_address[1]))
                elif message_type == PREVOTE:
                    self.handle_pre_vote(message, client_address[0] + ":"+ str(client_address[1]))
                elif message_type == PRECOMMIT:
                    block_hash = message["block_hash"]
                    self.handle_pre_commit(block_hash, client_address[0] + ":"+ str(client_address[1]), message["round"])
            client_socket.close()
        except Exception as e:
            print(f"Error handling connection from {client_address}: {e}")
            client_socket.close()

    def start_listening(self):
        """Start listening for incoming connections."""
        threading.Thread(target=self.listen, daemon=True).start()

    def listen(self):
        """Listen for incoming connections."""
        while True:
            try:
                client_socket, client_address = self.server_socket.accept()
                threading.Thread(target=self.handle_connection, args=(client_socket, client_address), daemon=True).start()
            except Exception as e:
                print(f"Error accepting connection: {e}")
                break

# --- Helper Functions ---
def generate_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key

# --- Main Simulation ---
# Example Usage:
if __name__ == '__main__':
    # 1. Generate Keys
    private_key1 = generate_key()
    public_key1 = private_key1.public_key()
    public_key_pem1 = public_key1.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    private_key2 = generate_key()
    public_key2 = private_key2.public_key()
    public_key_pem2 = public_key2.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    private_key3 = generate_key()
    public_key3 = private_key3.public_key()
    public_key_pem3 = public_key3.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    # 2. Initialize Data Object (Validator Addresses)
    initial_balances = {
        public_key_pem1: 0.4,
        public_key_pem2: 0.3,
        public_key_pem3: 0.3
    }
    #Define the validators, this would come from the user and require them to stake some coins.
    validator_addresses = [public_key_pem1, public_key_pem2, public_key_pem3]
    data_object = DataObject(initial_balances, validator_addresses)

    # 3. Create Nodes
    node1 = Node(data_object, private_key1, NODE_ADDRESSES[0], NODE_ADDRESSES)
    node1.all_keys = [private_key1, private_key2, private_key3]

    node2 = Node(data_object, private_key2, NODE_ADDRESSES[1], NODE_ADDRESSES)
    node2.all_keys = [private_key1, private_key2, private_key3]

    node3 = Node(data_object, private_key3, NODE_ADDRESSES[2], NODE_ADDRESSES)
    node3.all_keys = [private_key1, private_key2, private_key3]
    time.sleep(3)
    # 4. Simulate Transactions and Consensus
    # Node1 creates a transaction to send to Node2, and also create a new account!
    private_key4 = generate_key()
    public_key4 = private_key4.public_key()
    public_key_pem4 = public_key4.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    time.sleep(1)
    transaction1 = node1.create_transaction(public_key_pem2, 0.1, new_account_address=public_key_pem4)
    transaction2 = node1.create_transaction(public_key_pem2, 0.1)

    time.sleep(5)
    print("balances")
    print(f"Node 1 Balance: {data_object.get_balance(public_key_pem1)}")
    print(f"Node 2 Balance: {data_object.get_balance(public_key_pem2)}")
    print(f"Node 3 Balance: {data_object.get_balance(public_key_pem3)}")
    print(f"Node 4 Balance: {data_object.get_balance(public_key_pem4)}")
    print("last block hash")
    print(node1.last_block_hash)
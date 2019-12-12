# 1.Flask Server
# 2.Blockchain:
# Mine a block
# Get a chain
# Check if chain is valid


import datetime
import hashlib
import json
from flask import Flask, jsonify, request
import requests
from urllib.parse import urlparse
from uuid import uuid4


class Blockchain:
    def __init__(self):
        self.chain = []
        self.transactions = []
        self.create_block(nonce=1, previous_hash=0)
        self.nodes = set()

    def create_block(self, nonce, previous_hash):
        block = {
            'index': len(self.chain)+1,
            'timestamp': str(datetime.datetime.now()),
            'nonce': nonce,
            'previous_hash': previous_hash,
            'transactions': self.transactions
        }
        self.chain.append(block)
        self.transactions = []
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def nonce_of_work(self, previous_hash):
        new_nonce = 1
        check_nonce = False
        while (check_nonce):
            hash_operation = hashlib.sha256(
                str(pow(new_nonce, 2) - pow(previous_hash, 2)).encode()).hexdigest()
            if(hash_operation[:4] == '0000'):
                print(hash_operation)
                check_nonce = True
            else:
                new_nonce += 1
        return new_nonce

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if(block['previous_hash'] != self.hash(previous_block)):
                return False
            previous_nonce = previous_block['nonce']
            nonce = block['nonce']
            hash_operation = hashlib.sha256(
                str(pow(nonce, 2) - pow(previous_nonce, 2)).encode()).hexdigest()
            if hash_operation[:4] != '0000':
                return False
            previous_block = block
            block_index += 1
        return True

    def add_transaction(self, sender, receiver, amount):  # Transactions
        self.transactions.append(
            {'sender': sender,
             'receiver': receiver,
             'amount': amount
             })
        previous_block = self.get_previous_block()
        return previous_block['index'] + 1

    def add_node(self, address):  # Decentralization =>Nodes
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)

    def replace_chain(self):  # Concensus=>Longet chain wins
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            response = requests.get('http://'+node+'/get_chain')
            if(response.status_code == 200):
                length = response.json()['length']
                chain = response.json()['chain']
                if length > max_length and self.is_chain_valid(chain):
                    max_length = length
                    longest_chain = chain
        if longest_chain:
            self.chain = longest_chain
            return True
        return False


# Creating Flask server object
app = Flask(__name__)

node_address = str(uuid4()).replace('-', "")


# Initiating Blockchain
blockchain = Blockchain()


@app.route("/mine_block", methods=['GET'])
def mine_block():
    previous_block = blockchain.get_previous_block()
    previous_nonce = previous_block['nonce']
    nonce = blockchain.nonce_of_work(previous_nonce)
    previous_hash = blockchain.hash(previous_block)
    blockchain.add_transaction(
        sender=node_address, receiver='Lakshay', amount=1)
    block = blockchain.create_block(nonce, previous_hash)
    response = {
        'message': 'You just mined a block!',
        'index': block['index'],
        'timestamp': block['timestamp'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
        'transactions': block['transactions']

    }
    return jsonify(response), 200


@app.route("/get_chain", methods=['GET'])
def get_chain():

    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)

    }
    return jsonify(response), 200


@app.route('/is_valid', methods=['GET'])
def is_valid():
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
        response = {'message': 'The chain is valid'}
    else:
        response = {'message': 'The chain has been compromised'}
    return jsonify(response), 200


@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    json = request.get_json()
    transaction_keys = ['sender', 'receiver', 'amount']
    if not all(key in json for key in transaction_keys):
        return 'Some of the keys are missing', 400
    index = blockchain.add_transaction(
        json['sender'], json['receiver'], json['amount'])
    response = {'message': 'This transaction will be added in block'+index}
    return jsonify(response), 201


@app.route('/connect_node', methods=['POST'])
def connect_node():
    json = request.get_json()
    nodes = json.get('nodes')
    if nodes is None:
        return 'No node', 400
    for node in nodes:
        blockchain.add_node(node)
    response = {'message': 'All nodes are now connected, NCUCoin has the following nodes',
                'total_nodes': list(blockchain.nodes)}
    return jsonify(response), 201


@app.route('/replace_chain', methods=['GET'])
def replace_chain():
    is_chain_replaced = blockchain.replace_chain()
    if is_chain_replaced:
        response = {'message': 'The nodes have different chain so the node was replaced',
                    'new_chain': blockchain.chain}
    else:
        response = {'message': 'All good, the chain is the largest one',
                    'actual chain': blockchain.chain}
    return jsonify(response), 200


app.run(debug=True, port="5000")

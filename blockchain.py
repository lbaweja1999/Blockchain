# 1.Flask Server
# 2.Blockchain:
# Mine a block
# Get a chain
# Check if chain is valid


import datetime
import hashlib
import json
from flask import Flask, jsonify


class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_block(nonce=1, previous_hash=0)

    def create_block(self, nonce, previous_hash):
        block = {
            'index': len(self.chain)+1,
            'timestamp': str(datetime.datetime.now()),
            'nonce': nonce,
            'previous_hash': previous_hash
        }
        self.chain.append(block)
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


# Creating Flask server object
app = Flask(__name__)

# Initiating Blockchain
blockchain = Blockchain()


@app.route("/mine_block", methods=['GET'])
def mine_block():
    previous_block = blockchain.get_previous_block()
    previous_nonce = previous_block['nonce']
    nonce = blockchain.nonce_of_work(previous_nonce)
    previous_hash = blockchain.hash(previous_block)
    block = blockchain.create_block(nonce, previous_hash)
    response = {
        'message': 'You just mined a block!',
        'index': block['index'],
        'timestamp': block['timestamp'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash']

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


app.run(debug=True, port="5000")

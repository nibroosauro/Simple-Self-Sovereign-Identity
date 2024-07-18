import hashlib
import json
from time import time

class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.dids = []
        self.new_block(previous_hash='1', proof=100)  # Genesis block

    def new_block(self, proof, previous_hash=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }
        self.current_transactions = []
        self.chain.append(block)
        return block

    def new_transaction(self, transaction_type, data):
        """
        Creates a new transaction to go into the next mined Block.

        :param transaction_type: <str> Type of the transaction (e.g., 'DID_REGISTRATION', 'VC_ISSUANCE', 'VC_REVOCATION')
        :param data: <dict> Data related to the transaction
        """
        self.current_transactions.append({
            'type': transaction_type,
            'data': data,
        })
        return self.last_block['index'] + 1

    def add_did(self, did, name):
        self.dids.append({
            'did': did,
            'name': name,
        })
        self.new_transaction('DID_REGISTRATION', {'did': did, 'name': name})

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        return self.chain[-1]


# import hashlib
# import json
# from time import time

# class Blockchain:
#     def __init__(self):
#         self.chain = []
#         self.current_transactions = []
#         self.dids = []
#         self.new_block(previous_hash='1', proof=100)

#     def new_block(self, proof, previous_hash=None):
#         block = {
#             'index': len(self.chain) + 1,
#             'timestamp': time(),
#             'transactions': self.current_transactions,
#             'proof': proof,
#             'previous_hash': previous_hash or self.hash(self.chain[-1]),
#         }
#         self.current_transactions = []
#         self.chain.append(block)
#         return block

#     def new_transaction(self, sender, recipient, credential):
#         self.current_transactions.append({
#             'sender': sender,
#             'recipient': recipient,
#             'credential': credential,
#         })
#         return self.last_block['index'] + 1

#     def add_did(self, did, name):
#         self.dids.append({
#             'did': did,
#             'name': name,
#         })

#     @staticmethod
#     def hash(block):
#         block_string = json.dumps(block, sort_keys=True).encode()
#         return hashlib.sha256(block_string).hexdigest()

#     @property
#     def last_block(self):
#         return self.chain[-1]
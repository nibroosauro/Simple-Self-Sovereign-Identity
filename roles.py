import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from did import DID
from vc import VerifiableCredential

class Issuer:
    def __init__(self, name, did=None):
        self.did_manager = DID()
        self.did = did or self.did_manager.create_issuer_did(name)
        self.name = name

    def issue_credential(self, subject_did, credential_data):
        vc_manager = VerifiableCredential()
        return vc_manager.create_credential(self.did, subject_did, credential_data)

class Holder:
    def __init__(self, name):
        self.did_manager = DID()
        self.did = self.did_manager.create_holder_did(name)
        self.name = name

    def get_did(self):
        return self.did

class Verifier:
    def __init__(self, verifier_did=None, name=None):
        self.verifier_did = verifier_did
        self.name = name
        self.did_manager = DID()

    def get_verifier_did(self):
        return self.verifier_did

    @property
    def did(self):
        return self.did_manager.get_did_document(self.verifier_did)

    @property
    def did_name(self):
        return self.did_manager.get_did_name(self.verifier_did)

    def verify_credential(self, credential_id):
        vc_manager = VerifiableCredential()
        credential = vc_manager.credentials.get(credential_id)
        if not credential:
            return False
        credential_data = credential['credential']
        signature = credential['signature']
        return vc_manager.verify_credential(credential_data, signature)

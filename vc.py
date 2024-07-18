import json
import uuid
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime

class VerifiableCredential:
    def __init__(self):
        self.credentials = {}
        self.presented_credentials = {}

    def create_credential(self, issuer_did, subject_did, credential_data):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()

        credential = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "issuer": issuer_did,
            "issuanceDate": datetime.utcnow().isoformat() + 'Z',
            "credentialSubject": {
                "id": subject_did,
                **credential_data,
            }
        }

        credential_json = json.dumps(credential).encode('utf-8')
        signature = private_key.sign(
            credential_json,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        credential_id = str(uuid.uuid4())
        serialized_public_key = self.serialize_key(public_key)  # Serialize public key
        self.credentials[credential_id] = {
            "credential": credential,
            "signature": signature,
            "public_key": serialized_public_key,  # Store serialized public key
        }
        return {"credential_id": credential_id, **self.credentials[credential_id]}

    def serialize_key(self, key):
        if isinstance(key, rsa.RSAPublicKey):
            return key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
        raise TypeError("Unsupported key type for serialization")

    def verify_credential(self, credential_id):
        credential_data = self.credentials.get(credential_id)
        if not credential_data:
            return False
        
        credential = credential_data['credential']
        signature = credential_data['signature']
        public_key_pem = credential_data['public_key']

        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )

            credential_json = json.dumps(credential).encode('utf-8')
            public_key.verify(
                signature,
                credential_json,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Verification failed: {str(e)}")
            return False

    def present_credential(self, credential_id, verifier_did):
        if credential_id not in self.presented_credentials:
            self.presented_credentials[credential_id] = []
        self.presented_credentials[credential_id].append(verifier_did)

    def revoke_credential(self, credential_id):
        if credential_id in self.credentials:
            del self.credentials[credential_id]

    def revoke_access_credential(self, credential_id, verifier_did):
        if credential_id in self.presented_credentials:
            self.presented_credentials[credential_id].remove(verifier_did)

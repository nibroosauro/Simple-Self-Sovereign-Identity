import uuid

class DID:
    def __init__(self):
        self.did_registry = {}

    def create_issuer_did(self, name):
        did = f"{uuid.uuid4()}"
        self.did_registry[did] = {"name": name, "type": "issuer"}
        return did

    def create_holder_did(self, name):
        did = f"{uuid.uuid4()}"
        self.did_registry[did] = {"name": name, "type": "holder"}
        return did
    
    def create_verifier_did(self, name):
        did = f"{uuid.uuid4()}"
        self.did_registry[did] = {"name": name, "type": "verifier"}  # Corrected type to 'verifier'
        return did

    def get_did_document(self, did):
        return self.did_registry.get(did, None)

    def get_did_name(self, did):
        did_doc = self.did_registry.get(did, None)
        return did_doc.get("name") if did_doc else None

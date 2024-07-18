from flask import Flask, jsonify, request
from utils import blockchain, did_manager, vc_manager
import json
from roles import Issuer, Holder, Verifier
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

@app.route('/create_issuer_did', methods=['POST'])
def create_issuer_did():
    name = request.args.get('name')
    issuer = Issuer(name)
    issuer_did = issuer.did
    blockchain.add_did(issuer_did, name)
    blockchain.new_block(proof=12345)  # Create a new block for the DID registration
    return jsonify({"issuer_did": issuer_did, "name": name}), 201

@app.route('/create_holder_did', methods=['POST'])
def create_holder_did():
    name = request.args.get('name')
    holder = Holder(name)
    holder_did = holder.did
    blockchain.add_did(holder_did, name)
    blockchain.new_block(proof=12345)  # Create a new block for the DID registration
    return jsonify({"holder_did": holder_did, "name": name}), 201

@app.route('/create_verifier_did', methods=['POST'])
def create_verifier_did():
    name = request.args.get('name')
    verifier = Verifier(name=name)
    verifier_did = verifier.did_manager.create_verifier_did(name)
    blockchain.add_did(verifier_did, name)
    blockchain.new_block(proof=12345)  # Create a new block for the DID registration
    return jsonify({"verifier_did": verifier_did, "name": name}), 201

def serialize_key(key):
    if isinstance(key, rsa.RSAPublicKey):
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    return key

@app.route('/issue_credential', methods=['POST'])
def issue_credential():
    issuer_did = request.args.get('issuer_did')
    subject_did = request.args.get('subject_did')
    diploma_name = request.args.get('passport_name_country')
    graduation_date = request.args.get('valid_date')

    if not all([issuer_did, subject_did, diploma_name, graduation_date]):
        error_message = {"error": "Missing required parameters"}
        app.logger.error(f"Error: {error_message}")
        return jsonify(error_message), 400

    credential_data = {
        'passport_name_country': diploma_name,
        'valid_date': graduation_date,
    }

    issuer_name = next((did['name'] for did in blockchain.dids if did['did'] == issuer_did), "unknown issuer")
    app.logger.debug(f"Issuer Name: {issuer_name}")

    credential = vc_manager.create_credential(issuer_did, subject_did, credential_data)
    blockchain.new_transaction('VC_ISSUANCE', {
        'issuer_did': issuer_did,
        'subject_did': subject_did,
        'credential_id': credential['credential_id'],
    })
    blockchain.new_block(proof=12345)  # Create a new block for the credential issuance

    app.logger.debug("Credential issued successfully.")
    app.logger.debug(f"Credential Data: {credential}")

    response_data = {
        "credential_id": credential["credential_id"],
        "credential": credential["credential"]
    }

    return jsonify(response_data), 201

@app.route('/present_credential', methods=['POST'])
def present_credential():
    holder_did = request.args.get('holder_did')
    verifier_did = request.args.get('verifier_did')
    credential_id = request.args.get('credential_id')
    credential = vc_manager.credentials.get(credential_id)
    if credential and credential['credential']['credentialSubject']['id'] == holder_did:
        vc_manager.present_credential(credential_id, verifier_did)
        return jsonify({"message": "Credential presented to verifier"}), 200
    return jsonify({"message": "Credential not found or unauthorized"}), 404

@app.route('/verify_credential', methods=['POST'])
def verify_credential():
    verifier_did = request.args.get('verifier_did')
    credential_id = request.args.get('credential_id')
    
    if not all([verifier_did, credential_id]):
        app.logger.error("Missing verifier_did or credential_id")
        return jsonify({"error": "Missing verifier_did or credential_id"}), 400
    
    verifier = Verifier(verifier_did=verifier_did)
    is_valid = verifier.verify_credential(credential_id)

    app.logger.debug(f"Verification result for credential {credential_id}: {is_valid}")
    
    return jsonify({"valid": is_valid}), 200

@app.route('/revoke_credential', methods=['POST'])
def revoke_credential():
    issuer_did = request.args.get('issuer_did')
    credential_id = request.args.get('credential_id')
    credential = vc_manager.credentials.get(credential_id)
    if credential and credential['credential']['issuer'] == issuer_did:
        vc_manager.revoke_credential(credential_id)
        blockchain.new_transaction('VC_REVOCATION', {
            'issuer_did': issuer_did,
            'credential_id': credential_id,
        })
        blockchain.new_block(proof=12345)  # Create a new block for the credential revocation
        return jsonify({"message": "Credential revoked"}), 200
    return jsonify({"message": "Credential not found or unauthorized"}), 404

@app.route('/revoke_access_credential', methods=['POST'])
def revoke_access_credential():
    holder_did = request.args.get('holder_did')
    verifier_did = request.args.get('verifier_did')
    credential_id = request.args.get('credential_id')
    credential = vc_manager.credentials.get(credential_id)
    if credential and credential['credential']['credentialSubject']['id'] == holder_did:
        vc_manager.revoke_access_credential(credential_id, verifier_did)
        blockchain.new_transaction('VC_ACCESS_REVOCATION', {
            'holder_did': holder_did,
            'verifier_did': verifier_did,
            'credential_id': credential_id,
        })
        blockchain.new_block(proof=12345)  # Create a new block for the access revocation
        return jsonify({"message": "Credential access revoked from verifier"}), 200
    return jsonify({"message": "Credential not found or unauthorized"}), 404

@app.route('/show_blockchain', methods=['GET'])
def show_blockchain():
    # Ensure all byte data is properly serialized
    chain = json.loads(json.dumps(blockchain.chain, default=str))
    return jsonify(chain), 200

@app.route('/show_dids', methods=['GET'])
def show_dids():
    return jsonify(blockchain.dids), 200

if __name__ == '__main__':
    app.run(debug=True)

# from flask import Flask, jsonify, request
# from utils import blockchain, did_manager, vc_manager
# from roles import Issuer, Holder, Verifier
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.primitives import serialization

# app = Flask(__name__)

# @app.route('/create_issuer_did', methods=['POST'])
# def create_issuer_did():
#     name = request.args.get('name')
#     issuer = Issuer(name)
#     issuer_did = issuer.did
#     blockchain.add_did(issuer_did, name)
#     return jsonify({"issuer_did": issuer_did, "name": name}), 201

# @app.route('/create_holder_did', methods=['POST'])
# def create_holder_did():
#     name = request.args.get('name')
#     holder = Holder(name)
#     holder_did = holder.did
#     blockchain.add_did(holder_did, name)
#     return jsonify({"holder_did": holder_did, "name": name}), 201

# @app.route('/create_verifier_did', methods=['POST'])
# def create_verifier_did():
#     name = request.args.get('name')
#     verifier = Verifier(name=name)
#     verifier_did = verifier.did_manager.create_verifier_did(name)
#     blockchain.add_did(verifier_did, name)
#     return jsonify({"verifier_did": verifier_did, "name": name}), 201

# def serialize_key(key):
#     if isinstance(key, rsa.RSAPublicKey):
#         return key.public_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo
#         ).decode('utf-8')
#     return key

# @app.route('/issue_credential', methods=['POST'])
# def issue_credential():
#     issuer_did = request.args.get('issuer_did')
#     subject_did = request.args.get('subject_did')
#     diploma_name = request.args.get('diploma_name')
#     graduation_date = request.args.get('graduation_date')

#     if not all([issuer_did, subject_did, diploma_name, graduation_date]):
#         error_message = {"error": "Missing required parameters"}
#         app.logger.error(f"Error: {error_message}")
#         return jsonify(error_message), 400

#     credential_data = {
#         'diploma_name': diploma_name,
#         'graduation_date': graduation_date,
#     }

#     issuer_name = next((did['name'] for did in blockchain.dids if did['did'] == issuer_did), "unknown issuer")
#     app.logger.debug(f"Issuer Name: {issuer_name}")

#     credential = vc_manager.create_credential(issuer_did, subject_did, credential_data)
#     blockchain.new_transaction(issuer_did, subject_did, credential)
#     new_block = blockchain.new_block(proof=12345)  # Example proof for demonstration

#     app.logger.debug("Credential issued successfully.")
#     app.logger.debug(f"Credential Data: {credential}")

#     # Convert signature to a serializable format (e.g., base64 encoded string)
#     # credential_signature = credential["credential"].pop("signature")
#     # credential_signature_str = credential_signature.decode('utf-8')  # Assuming signature is in bytes

#     # Prepare JSON response
#     response_data = {
#         "credential_id": credential["credential_id"],
#         "credential": credential["credential"]
#         #"signature": credential_signature_str
#     }

#     return jsonify(response_data), 201

# @app.route('/present_credential', methods=['POST'])
# def present_credential():
#     holder_did = request.args.get('holder_did')
#     verifier_did = request.args.get('verifier_did')
#     credential_id = request.args.get('credential_id')
#     credential = vc_manager.credentials.get(credential_id)
#     if credential and credential['credential']['credentialSubject']['id'] == holder_did:
#         vc_manager.present_credential(credential_id, verifier_did)
#         return jsonify({"message": "Credential presented to verifier"}), 200
#     return jsonify({"message": "Credential not found or unauthorized"}), 404

# @app.route('/verify_credential', methods=['POST'])
# def verify_credential():
#     verifier_did = request.args.get('verifier_did')
#     credential_id = request.args.get('credential_id')
    
#     if not all([verifier_did, credential_id]):
#         app.logger.error("Missing verifier_did or credential_id")
#         return jsonify({"error": "Missing verifier_did or credential_id"}), 400
    
#     verifier = Verifier(verifier_did=verifier_did)
#     is_valid = verifier.verify_credential(credential_id)

#     app.logger.debug(f"Verification result for credential {credential_id}: {is_valid}")
    
#     return jsonify({"valid": is_valid}), 200

# @app.route('/revoke_credential', methods=['POST'])
# def revoke_credential():
#     issuer_did = request.args.get('issuer_did')
#     credential_id = request.args.get('credential_id')
#     credential = vc_manager.credentials.get(credential_id)
#     if credential and credential['credential']['issuer'] == issuer_did:
#         vc_manager.revoke_credential(credential_id)
#         blockchain.add_transaction("system", credential['credential']['credentialSubject']['id'], "revocation", None)
#         return jsonify({"message": "Credential revoked"}), 200
#     return jsonify({"message": "Credential not found or unauthorized"}), 404

# @app.route('/revoke_access_credential', methods=['POST'])
# def revoke_access_credential():
#     holder_did = request.args.get('holder_did')
#     verifier_did = request.args.get('verifier_did')
#     credential_id = request.args.get('credential_id')
#     credential = vc_manager.credentials.get(credential_id)
#     if credential and credential['credential']['credentialSubject']['id'] == holder_did:
#         vc_manager.revoke_access_credential(credential_id, verifier_did)
#         blockchain.add_transaction("system", holder_did, "access_revocation", None)
#         return jsonify({"message": "Credential access revoked from verifier"}), 200
#     return jsonify({"message": "Credential not found or unauthorized"}), 404

# @app.route('/show_blockchain', methods=['GET'])
# def show_blockchain():
#     return jsonify(blockchain.chain), 200

# @app.route('/show_dids', methods=['GET'])
# def show_dids():
#     return jsonify(blockchain.dids), 200

# if __name__ == '__main__':
#     app.run(debug=True)

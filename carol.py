"""
Carol is an employee at ENU. She is responsible for signing diplomas on behalf of the university.

In the implemented scenario, Carol generates a public/private key pair via Ed25519, generates a diploma claim for Alice and signs it. Carol's public key is distributed for verification purposes.
"""

import nacl
import base64
import json
from nacl.signing import SigningKey

def sign_claim_Ed25519(claim):
    '''
    Function to allow Carol to sign a claim. A public/private key pair is generated using Ed25519. The claim is then signed.

            Parameters:
                    claim (str): the claim to be signed in base64 format
                    
            Returns:
                    signed_claim (nacl.signing.SignedMessage): Object which represents the signed claim. Contains properties of claim (original message) and signature.
                    verify_key_bytes (bytes) : verification key of signed claim. Can be distributed to third party to verify authenticity of claim.
    '''
    # Generate a new random signing key (private key)
    signing_key = SigningKey.generate()

    # Sign a message with the signing key
    signed_claim = signing_key.sign(claim)

    # Obtain the verify key (public key) for a given signing key
    verify_key = signing_key.verify_key
    # Serialize the verify key to send it to a third party
    verify_key_bytes = verify_key.encode()

    return signed_claim, verify_key_bytes

def generate_claim():
    '''
    Generate a new claim (diploma details) for Alice. Values of diploma are hardcoded for now.

            Returns:
                    claim(bytes): Alice's diploma (claim), a JSON str encoded in base64 and represented as bytes.
    '''
    #Generate a new claim (diploma) for Alice (hardcoded values for now)
    claim = {
            "awardedTo": "Alice J Doe",
            "university": "University of Glass",
            "department": "School of Computing",
            "degreeAwarded": "Software Engineer",
            "dateOfAward" : "01/11/2019",
            }
    js_claim = json.dumps(claim)
    claim = base64.b64encode(js_claim.encode("utf-8"))
    return claim
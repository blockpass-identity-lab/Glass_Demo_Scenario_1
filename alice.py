"""
Alice is a graduate at ENU. She is looking to obtain employment from Bob but needs to first prove the validity of her claim (diploma) to her new potential employer.

In the implemented scenario, Alice receives a signed claim from her university via Carol. 
Alice generates a public/private key pair using ECIES (ecies_pub_key, ecies_priv_key). The ecies_pub_key is used to derived a symmetric AES-256-GCM key.
Alice encrypt her signed claim (received from Carol) as follows: ECIES_ENC(ecies_pub_key, signed_claim). Internally, the ECIES_ENC function will derive and output an encrypted common secret (encrypted version of AES-256-GCM key).
Alice generates a security triplet (cid, meta, uri) where meta = ECIES encrypted common secret.
Alice distributes her encrypted signed credential to a distribution protocol (e.g. IPFS, Dropbox etc).
Alice records the triplet on Hyperledger Fabric for future lookup.

In the future, when Alice wishes to present her signed claim (diploma) to Bob for employment, she retrieves the encrypted signed credential from IPFS (or dropbox etc).
Alice queries Hyperledger Fabric to obtain 'meta' (ECIES encrypted common secret) value.
Alice uses her ECIES private key to decrypt 'meta' ECIES encrypted common secret --(which derives to)--> AES-256-GCM key --(used to decrypt)--> encrypted signed claim.
Alice presents her decrypted signed claim to Bob.
Bob can then verify the claim.
"""

import pickle

from nacl.signing import VerifyKey
from ecies.utils import generate_eth_key
from ecies import encrypt, decrypt
import binascii

hlf = { }

ipfs = { }


def verify_claim(signed_claim, pub_key):
    '''
    Verify a signed claim using the signers public key (Ed25519).

            Parameters:
                    signed_claim (nacl.signing.SignedMessage): Object which represents the signed claim. Contains properties of claim (original message) and signature.
                    pub_key (bytes) : verification key (public key) of signed claim.
                    
            Returns:
                    (bool) : True if verification was successful. Else False is returned.
    '''
    try:
        verify_key = VerifyKey(pub_key)
        verify_key.verify(signed_claim)
        return True
    except Exception:
        return False

def generate_key_ecies():
    '''
    Generate a public and private key pair using ECIES (Elliptic Curve Integrated Encryption Scheme). 
    The public key is used by Alice to derive a symmetric key. The library used in this implementation (ecies) combines secp256k1 and AES-256-GCM.
    The derived symmetric key is used to encrypt Alice's signed claim so it can be securely distributed to a distribution protocol (IPFS, Dropbox, etc).

            Returns:
                    ecies_priv_key (str), ecies_pub_key (str): The generated ECIES key pair in hex.
    '''
    privKey = generate_eth_key()
    ecies_priv_key = privKey.to_hex()
    ecies_pub_key = privKey.public_key.to_hex()

    return ecies_priv_key, ecies_pub_key

def encrypt_claim_ecies(signed_claim, ecies_pub_key):
    '''
    Encrypts a signed claim using ECIES.

            Parameters:
                signed_claim (nacl.signing.SignedMessage): Object which represents the signed claim. Contains properties of claim (original message) and signature.
                ecies_pub_key (str) : ECIES public key, which will be used to derived an AES-256-GCM secret key used to encrypt the signed claim.

            Returns:
                    encrypted_claim (bytes): holds 4 values {cipherPubKey, AES-nonce, authTag, AES-ciphertext} in binary. See https://wizardforcel.gitbooks.io/practical-cryptography-for-developers-book/content/asymmetric-key-ciphers/ecies-example.html for details.
    '''
    serialised_signed_claim = pickle.dumps(signed_claim) #use in-built python module, pickle, to serialise the signed_claim object into binary stream form.
    encrypted_claim = encrypt(ecies_pub_key, serialised_signed_claim)
    
    return encrypted_claim

def decrypt_claim_ecies(encrypted_claim, ecies_priv_key):
    '''
    Decrypt an encrypted signed claim using AES EAX. The encrypted AES secret key first decrypted using Alice's RSA private key. The decrypted AES key is then used to decrypt the encrypted signed claim.

            Parameters:
                encrypted_claim (bytes) : The encrypted claim (including encrypted common secret key used to encrypt the claim).
                ecies_priv_key (str) : The ECIES private key which is paired to the common secret. Used to 'unlock' encrypted common secret which can then be used to decrypt claim.

            Returns:
                    decrypted_claim (bytes) : Decrypted signed claim (Alice's diploma details in plaintext).
    '''
    decrypted_claim = decrypt(ecies_priv_key, encrypted_claim)
    decrypted_claim = pickle.loads(decrypted_claim) #deserialise from byte back to nacl obj

    return decrypted_claim

def distribute_claim(cipher):
    '''
    TODO: Interface into the real IPFS in this function.
    In reality, input cipher should be added to IPFS (or sharepoint, dropbox etc) and a unique CID will be generated.
    A unique URI will also be generated to define where the cipher (encrypted claim) has been saved to. 
    For now, we hardcode and return a mockup CID and URI for demo purposes.

            Parameters:
                cipher (bytes) : Encrypted signed claim to distribute to IPFS/Dropbox/Sharepoint etc. Consists of 3 values {AES-nonce, authTag, AES-ciphertext} in binary.

            Returns:
                    cid (str), uri (str) : Generated CID of claim and URI (pointer) to where claim may be retrieved from.
    '''
    # TODO: Interface into the real IPFS in this function
    # In reality, encrypted_claim.hex() should be added to IPFS (or sharepoint, dropbox etc) and a unique CID will be generated.
    # A unique URI will also be generated to define where the claim encrypted_claim.hex() has been saved to. 
    # For now, we hardcode a mockup CID and URI for demo purposes.

    #Below is example of how this function will work if interacting with a live instance of (private) IPFS
    #cid = interface.add_to_ipfs(encrypted_claim.hex())
    #uri = "ipfs://"" + cid

    cid = "QmT5NvUtoM5nWFfrQdVrFtvGfKFmG7AHd8P34isapyhCxX"
    ipfs[cid] = cipher #simulation of adding cipher to IPFS occurs here.
    uri = "ipfs://QmT5NvUtoM5nWFfrQdVrFtvGfKFmG7AHd8P34isapyhCxX"

    return cid, uri

def generate_triplet(encrypted_claim):
    '''
    Generate a security triplet (CID, meta and URI) and distribute encrypted claim to a distribution protocol (IPFS).

            Parameters:
                encrypted_claim (bytes) : The encrypted signed claim. Expected to holds 4 values: {cipherPubKey, AES-nonce, authTag, AES-ciphertext} in binary. 

            Returns:
                    cid (str), meta (byte), uri (str) : CID, meta and URI of encrypted claim (i.e. unique ID of a signed claim, common encrypted secret which can 'unlock' the signed claim, and location of where the signed claim is stored) 
    '''
    # As noted above, the input of encrypted_claim is expected to hold 4 values: {cipherPubKey, AES-nonce, authTag, AES-ciphertext} in binary.
    # The links below show how we can index the binary values to split/extract <cipherPubKey> and <AES-nonce, authTag, AES-ciphertext> into two components.
    # Recall that cipherPubKey = common encrypted secret (i.e. encrypted version of AES-256-GCM key used to encrypt the sign claim)
    #             AES-nonce, authTag, AES-ciphertext = Encrypted sign claim itself plus auth tag/nonce.
    #
    # https://github.com/ecies/py/blob/9f0f33ace4550aabf7598560c0dc4bb10a9798b6/ecies/__init__.py#L61
    # https://wizardforcel.gitbooks.io/practical-cryptography-for-developers-book/content/asymmetric-key-ciphers/ecies-example.html
    # msg = equivalent to encrypted_claim
    # pubkey = msg[0:65]  # uncompressed pubkey's length is 65 bytes
    # encrypted = msg[65:]
    #
    # https://github.com/ecies/py/blob/9f0f33ace4550aabf7598560c0dc4bb10a9798b6/ecies/utils.py#L209-L211
    # iv = encrypted[:16]
    # tag = encrypted[16:32]
    # ciphered_data = encrypted[32:]

    meta = encrypted_claim[0:65] #Should consist of cipherPubKey (common encrypted secret) only.
    cipher = encrypted_claim[65:] #Should consist of AES-nonce + authTag + AES-ciphertext
   
    #Distribute the encrypted claim onto IPFS (or dropbox, sharepoint etc)
    cid, uri = distribute_claim(cipher)

    #return our generated triplet of cid, meta, uri. meta consists of the public key used to encrypt the AES key only.
    return cid, meta, uri

def record_triplet_hyperledger(cid, meta, uri):
    '''
    TODO: implement and test. Function should record the security triplet onto an instance of HLF. For now, we simulate recording record to HLF.
    '''
    hlf[cid] = (meta, uri)
    #interface.record_to_hlf(cid, meta, uri)
    
def read_key_hyperledger(cid):
    '''
    TODO: implement and test. Function should retrieve the meta data of an encrypted signed claim from HLF. Used to retrieve metadata (ECIES common encrypted secret) to allow Alice to decrypt a signed claim. Lookup is simulated for now.
    '''
    #meta = interface.read_from_hlf(cid, "org1.org")
    return hlf[cid][0]

def retrieve_encrypted_claim_ipfs(cid):
    '''
    TODO: implement and test. Function should retrieve the encrypted signed claim from IPFS (or other distribution protocol in future). Simulated retrieval for now.
    '''
    #meta = interface.get_from_ipfs(cid, "org1.org")
    return ipfs[cid]
    
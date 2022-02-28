"""
Alice is a graduate at ENU. She is looking to obtain employment from Bob but needs to first prove the validity of her claim (diploma) to her new potential employer.

In the implemented scenario, Alice receives a signed claim from her university via Carol. 
Alice generates a public/private key pair via RSA (RSA_pub, RSA_priv). She also generates a secret key AES_sec, using AES.
Alice encrypt her signed claim (received from Carol) as follows: Enc(AES_sec, signed_claim). She then encrypts the AES_sec using RSA: Enc(RSA_pub, AES_sec).
Alice generates a security triplet (cid, meta, uri) where meta = Enc(RSA_pub, AES_sec).
Alice distributes her encrypted signed credential to a distribution protocol (e.g. IPFS, Dropbox etc).
Alice records the triplet on Hyperledger Fabric for future lookup.

In the future, when Alice wishes to present her signed claim (diploma) to Bob for employment, she retrieves the encrypted signed credential from IPFS (or dropbox etc).
Alice queries Hyperledger Fabric to obtain meta (encrypted AES key) value.
Alice uses her RSA private key to decrypt meta:  Dec(RSA_priv, Enc(RSA_pub, AES_sec)) = AES_sec.
Alice uses  AES_sec to decrypt her signed claim. 
Alice presents her signed claim to Bob.
Bob can then verify the claim.
"""

import pickle

from nacl.signing import VerifyKey
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

meta = {}
encrypted_claim = None

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

def generate_key(): #gen rsa public/private key pair
    '''
    Generate a public and private key pair using RSA (2048 bits). 
    The RSA public key is used by Alice to encrypt her symmetric key (AES). 
    The symmetric key is used to encrypt her signed claim so it can be securely distributed to a distribution protocol (IPFS, Dropbox, etc).

            Returns:
                    rsa_private_key (bytes), rsa_public_key (bytes): The generated RSA private key and public key respectively.
    '''
    rsa_key = RSA.generate(2048)
    rsa_private_key = rsa_key.export_key() #Export private key, saved in-memory for now.
    rsa_public_key = rsa_key.publickey().export_key() #Export public key, saved in-memory for now.
    
    return rsa_private_key, rsa_public_key

def encrypt_claim(signed_claim, rsa_public_key):
    '''
    Encrypts a signed claim using AES EAX. The AES secret key is then encrypted using Alice's RSA public key.

            Parameters:
                signed_claim (nacl.signing.SignedMessage): Object which represents the signed claim. Contains properties of claim (original message) and signature.
                rsa_public_key (bytes) : RSA public key to be used to encrypt the AES secret key.

            Returns:
                    enc_session_key (bytes), cipher_aes.nonce (bytes), tag (bytes), encrypted_claim (bytes): The encrypted AES EAX key, AES EAX nonce, AES EAX tag and encrypted signed claim respectively.
    '''
    serialised_signed_claim = pickle.dumps(signed_claim) #use in-built python module, pickle, to serialise the signed_claim object into binary stream form.

    rsa_public_key = RSA.import_key(rsa_public_key)
    aes_key = get_random_bytes(16)

    # Encrypt the AES key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    enc_session_key = cipher_rsa.encrypt(aes_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    encrypted_claim, tag = cipher_aes.encrypt_and_digest(serialised_signed_claim)

    return enc_session_key, cipher_aes.nonce, tag, encrypted_claim

def decrypt_claim(enc_session_key, nonce, encrypted_claim, tag, rsa_private_key):
    '''
    Decrypt an encrypted signed claim using AES EAX. The encrypted AES secret key first decrypted using Alice's RSA private key. The decrypted AES key is then used to decrypt the encrypted signed claim.

            Parameters:
                enc_session_key (bytes) : The encrypted AES EAX secret key.
                nonce (bytes) : The AES EAX nonce value.
                encrypted_claim (bytes) : The encrypted signed claim.
                tag (bytes) : The AES EAX tag value.
                rsa_private_key (bytes) : The RSA private key to to decrypt enc_session_key

            Returns:
                    decrypted_claim (bytes) : Decrypted signed claim (Alice's diploma details in plaintext).
    '''
    rsa_private_key = RSA.import_key(rsa_private_key)
    
    # Decrypt the AES key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    aes_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(encrypted_claim, tag)
    decrypted_claim = pickle.loads(data)

    return decrypted_claim

def distribute_claim(encrypted_claim):
    '''
    TODO: Interface into the real IPFS in this function.
    In reality, encrypted_claim.hex() should be added to IPFS (or sharepoint, dropbox etc) and a unique CID will be generated.
    A unique URI will also be generated to define where the claim encrypted_claim.hex() has been saved to. 
    For now, we hardcode and return a mockup CID and URI for demo purposes.

            Parameters:
                encrypted_claim (bytes) : Encrypted signed claim to distribute to IPFS/Dropbox/Sharepoint etc.

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

    encrypted_claim = encrypted_claim # Set the encrypted_claim to global encrypted_claim (equivelent of distributing to IPFS)
    cid = "QmT5NvUtoM5nWFfrQdVrFtvGfKFmG7AHd8P34isapyhCxX"
    uri = "ipfs://QmT5NvUtoM5nWFfrQdVrFtvGfKFmG7AHd8P34isapyhCxX"

    return cid, uri

def generate_triplet(enc_session_key, nonce, tag, encrypted_claim):
    '''
    Generate a security triplet based and distribute on distribution protocol (IPFS, Sharepoint, Dropbox etc).

            Parameters:
                enc_session_key (bytes) : The encrypted AES EAX key used to encrypted the signed claim.
                nonce (bytes) : The AES EAX nonce value.
                tag (bytes) : The AES EAX tag value.
                encrypted_claim (bytes) : The encrypted signed claim.

            Returns:
                    cid (str), meta (dict), uri (str) : CID, encryption meta data and URI of encrypted claim (i.e. unique ID of a signed claim, encrypted key metadata which can 'unlock' the signed claim, and location of where the signed claim is stored) 
    '''
    global meta
    #DO NOT confuse meta with triplet. Meta simply contains the encrypted AES key and related nonce,tags (i.e. metadata).
    meta = {"encrypted_session_key" : enc_session_key.hex(), 
            "nonce" : nonce.hex(), 
            "tag" : tag.hex(),
           }

    #Distribute the encrypted claim onto IPFS (or dropbox, sharepoint etc)
    cid, uri = distribute_claim(encrypted_claim.hex())

    #return our generated triplet of cid, meta, uri. meta is the encrypted aes key (+ related meta data)
    return cid, meta, uri

def record_triplet_hyperledger(cid, meta, uri):
    '''
    TODO: implement and test. Function should record the security triplet onto an instance of HLF.
    '''
    pass
    #interface.record_to_hlf(cid, meta, uri)
    
def read_key_hyperledger(cid):
    '''
    TODO: implement and test. Function should retrieve the meta data of an encrypted signed claim from HLF. Used to retrieve metadata (incl. encrypted secret key) to allow Alice to decrypt a signed claim.
    '''
    #meta = interface.read_from_hlf(cid, "org1.org")
    return meta
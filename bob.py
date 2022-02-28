"""
Bob is an employee looking to recruit Alice. Before he does so, he needs to verify Alice's claim (diploma).
Bob receives Alice's decrypted claim alongside the universities public key.

Using these two components, Bob is able to verify the validity of Alice's diploma.
"""

from nacl.signing import VerifyKey

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
"""
Design Philosophy:
- We only ever store verifiable credentials
- We have a whitelist of orgs that can sign for certain scenarios (tax, diploma, id etc)
- Issuer (Carol) issues Alice a verifiable credential

Scenario:
 Step 1: Carol (issuer) generates a signed a x.509 cert (note: current implementation does NOT use x.509, the credential is just a base64 encoded dictionary of values for now)
 Step 2: Alice (citizen) receives credential, verifies it and encrypts it with her Public Key.
 Step 3: Alice generate security triplet:cid, encrypted credential and uri
    Step 3a: Alice distributes encrypted claim to a distrution protocol (e.g. IPFS, dropbox etc) (mock for now)
    Step 3b: Record the triplet onto Hyperledger Fabric (mock for now)
 Step 5: Bob (employer) requests Alice’s credential
 Step 6: Alice reads from HLF to determine location of encrypted credential based on CID lookup. She retrieves her encrypted claim.
 Step 7: Alice decrypts the encrypted VC with her own private key.
 Step 8: Alice provides decrypted VC to Bob (employer) and confirms her credentials.
"""

import carol, alice, bob
import base64
if __name__ == "__main__":
    #Step 1: Carol (issuer) generates a signed credential of Alice's diploma
    claim = carol.generate_claim()
    signed_claim, pub_key = carol.sign_claim(claim)

    #Step 2: Alice (citizen) receives credential, verifies it and encrypts it with her Public Key.
    if alice.verify_claim(signed_claim, pub_key):
        rsa_private_key, rsa_public_key = alice.generate_key()
        enc_session_key, nonce, tag, encrypted_claim = alice.encrypt_claim(signed_claim, rsa_public_key)

        #Step 3: Alice generate security triplet:cid, encrypted claim and uri
        #Step 3a: Alice distributes encrypted claim to a distrution protocol (e.g. IPFS, dropbox etc)
        cid, meta, uri = alice.generate_triplet(enc_session_key, nonce, tag, encrypted_claim)

        #Step 3b: Record the triplet onto Hyperledger Fabric
        alice.record_triplet_hyperledger(cid, meta, uri)
    else:
        print("Error! Claim failed to verify. Terminating workflow")
        pass

    #Step 5: (Assume that) Bob (employer) requests Alice’s credential
    #Step 6: Alice reads from HLF to determine location of encrypted credential based on CID lookup. She retrieves her encrypted claim.
    meta = alice.read_key_hyperledger(cid)
    
    #Step 7: Alice decrypts the encrypted VC with her own private key.
    dec_claim = alice.decrypt_claim(enc_session_key, nonce, encrypted_claim, tag, rsa_private_key)

    #Step 8: Alice provides decrypted VC to Bob (employer) and confirms her credentials.
    if bob.verify_claim(dec_claim, pub_key):
        print("Bob's verification of Alice's claim was successful.\nThe message: \n{0}\n is valid.".format(base64.urlsafe_b64decode(dec_claim.message)))
    else:
         print("Bob verification failed.\nThe message {0} is invalid.".format(dec_claim.message))

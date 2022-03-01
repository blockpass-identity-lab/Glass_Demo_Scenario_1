"""
Design Philosophy:
- We only ever store verifiable credentials
- We have a whitelist of orgs that can sign for certain scenarios (tax, diploma, id etc)
- Issuer (Carol) issues Alice a verifiable credential

Scenario:
 Step 1: Carol (issuer) generates a signed a x.509 cert (note: current implementation does NOT use x.509, the credential is just a base64 encoded dictionary of values for now)
 Step 2: Alice (citizen) receives credential, verifies it and encrypts it with her her public key (via ECIES).
 Step 3: Alice generate security triplet: cid, meta and uri
    Step 3a: Alice distributes encrypted claim to a distrution protocol (e.g. IPFS, dropbox etc) (simulated for now)
    Step 3b: Record the triplet onto Hyperledger Fabric (simulated for now)
 Step 5: Bob (employer) requests Alice’s credential
 Step 6: Alice reads from HLF to determine location of encrypted credential based on CID lookup. She retrieves her encrypted claim.
 Step 7: Alice decrypts the encrypted VC with her own private key.
 Step 8: Alice provides decrypted VC to Bob (employer) and confirms her credentials.
"""

from tarfile import PAX_NUMBER_FIELDS
import carol, alice, bob
import base64
import random

if __name__ == "__main__":
    #Step 1: Carol (issuer) generates a signed credential of Alice's diploma 
    claim = carol.generate_claim()
    signed_claim, pub_key = carol.sign_claim_Ed25519(claim)

    #Step 2: Alice (citizen) receives credential, verifies it and encrypts it with ecies derived symmetric key.
    if alice.verify_claim(signed_claim, pub_key):
        ecies_priv_key, ecies_pub_key = alice.generate_key_ecies()
        encrypted_claim = alice.encrypt_claim_ecies(signed_claim, ecies_pub_key)

        #Step 3: Alice generate security triplet: <CID, meta and URI>
        #Step 3a: Alice distributes encrypted claim to a distrution protocol (e.g. IPFS, dropbox etc)
        #The above two steps are simulated for now.
        cid, meta, uri = alice.generate_triplet(encrypted_claim)

        #Step 3b: Record the triplet onto Hyperledger Fabric
        alice.record_triplet_hyperledger(cid, meta, uri)
    else:
        print("Error! Claim failed to verify. Terminating workflow")
        pass

    #Step 5: (Assume that) Bob (employer) requests Alice’s credential
    #Step 6: Alice reads from HLF to determine location of encrypted credential based on CID lookup. She also retrieves her encrypted claim from IPFS.
    meta = alice.read_key_hyperledger(cid)
    encrypted_claim = alice.retrieve_encrypted_claim_ipfs(cid)
    #Step 7: Alice decrypts the encrypted VC with her own private key.
    dec_claim = alice.decrypt_claim_ecies(meta+encrypted_claim, ecies_priv_key) #Note we're joining the meta (common shared secret) + encrypted signed claim back together here. The ecies lib takes care of parsing this joined binary value.

    #Step 8: Alice provides decrypted VC to Bob (employer) and confirms her credentials.

    #Below is a randomly generated public key which should NOT match Carol's original public key. Include this line to test example of failed verification.
    #pub_key = b'\xb3q\x1c\x16\xb3\x90\x35\x86\xea\xad\xfd|L\x85\xb7J\xcdG\xdd\xe8Z\xdbZ\x80u\xd3!a\xfep\x9c\xaa'

    if bob.verify_claim(dec_claim, pub_key):
        print("Bob's verification of Alice's claim was successful.\nThe message: \n{0}\n is valid.".format(base64.urlsafe_b64decode(dec_claim.message)))
    else:
         print("Bob verification failed.\nThe message {0} is invalid.".format(dec_claim.message))

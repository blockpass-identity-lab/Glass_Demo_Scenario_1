# Glass_Demo_Scenario_1
Proof of concept of Glass Demo.

# Description:

```
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
```

# Usage

Run the following commands in your Python (3.x) environment:

```
git clone https://github.com/blockpass-identity-lab/Glass_Demo_Scenario_1.git
cd Glass_Demo_Scenario_1
pip install -r requirements.txt
python main.py
```

Example output (successful verification of Alice's signed claim):

```
Bob's verification of Alice's claim was successful.
The message: 
b'{"awardedTo": "Alice J Doe", "university": "University of Glass", "department": "School of Computing", "degreeAwarded": "Software Engineer", "dateOfAward": "01/11/2019"}'
 is valid.
```

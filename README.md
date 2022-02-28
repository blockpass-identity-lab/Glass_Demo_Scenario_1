# Glass_Demo_Scenario_1
Proof of concept of Glass Demo. See https://replit.com/@owenlo/GlassDemoScenario1#main.py for live demo.

Description of demo:

```
Design Philosophy:

- We only ever store verifiable credentials
- We have a whitelist of orgs that can sign for certain scenarios (tax, diploma, id etc)
- Issuer (Carol) issues Alice a verifiable credential

Scenario (currently implemented):

1. Carol (issuer) generates a signed a x.509 cert (note: current implementation does NOT use x.509, the credential is just a base64 encoded dictionary of values for now)
2. Alice (citizen) receives credential, verifies it and encrypts it with her Public Key.
3. Alice generate security triplet:cid, encrypted credential and uri
  3a. Alice distributes encrypted claim to a distrution protocol (e.g. IPFS, dropbox etc) (mock for now)
  3b. Record the triplet onto Hyperledger Fabric (mock for now)
4. Bob (employer) requests Alice’s credential
5. Alice reads from HLF to determine location of encrypted credential based on CID lookup. She retrieves her encrypted claim.
6. Alice decrypts the encrypted VC with her own private key.
7. Alice provides decrypted VC to Bob (employer) and confirms her credentials.
```

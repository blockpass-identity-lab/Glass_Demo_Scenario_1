"""
interface.py provides the main 'hook-ups' to alllow us to interact with both IPFS (assumed to be private) and HLF.

A simple approach is taken whereby ipfs and hlf actions are simply invoked via a command line approach using python's
subprocess library. See example implementations below. These functions have not been tested yet (as the infrastructure is being updated)
however, they are based on the previous glass-portal.py demo (https://gitlab.ubitech.eu/glass-project/distributed-ledger/-/blob/master/glass-portal.py)
so should be functional once the new HLF infrastructure is ready...
"""
import subprocess
import base64
import re
import json

def add_to_ipfs(file):
    #TODO: integrate and test.
    result = subprocess.run(["ipfs", "add", "{0}".format(file), "--quieter" ], stdout=subprocess.PIPE, text=True)
    return result.stdout.strip('\n')

def record_to_hlf(cid, meta, uri):
    """
    Encode cid, meta and uri into base64 and record onto HLF by invoking the 'createGlassResource' chaincode.
    """
    #TODO: integrate and test.
    params = base64.b64encode(bytes('{{"CID":"{0}","key":"{1}","uri":"{2}"}}'.format(cid, meta, uri), 'utf-8'))
    params = params.decode('ascii')
    result = subprocess.run(["./minifab", "invoke", "-p", '"createGlassResource"', "-t",  '{{"GlassResource" : "{0}" }}'.format(params), "-o", organisation ], stdout=subprocess.PIPE, text=True)

    #Naive approach to determine success. If any "error" text is observed, we simply assume the command failed for now.
    if ("error" in result.stdout):
        return False
    return True


def read_from_hlf(cid, org):
    """
    Retrieves an encrypted AES secret key (and related metadata) from HLF. Alice can then use her RSA priv key to unlock the metadata, then decrypt her signed claim using the decrypted AES secret key.
    """
    #TODO: integrate and test.
    organisation = org
    result = subprocess.run(["./minifab", "query", "-p", '"readGlassResourceKey","{0}"'.format(cid), "-t", "''", "-o", organisation], stdout=subprocess.PIPE, text=True)
    result = extractResult(result.stdout)
    return result

def extractResult(text):
    res = re.findall("{\"cid\":.*}", text)
    if (res):
        return json.loads(res[0])
    else:
        return json.loads( '{ "Status" : "Fail", "Message" : "The CID could not be found or read permission was denied." }' )

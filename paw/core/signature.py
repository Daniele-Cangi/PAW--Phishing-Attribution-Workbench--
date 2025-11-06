import os
from pgpy import PGPKey, PGPMessage, PGPSignature

def sign_file_pgp(path: str, pgp_priv_path: str, passphrase: str | None, out_sig: str) -> str:
    """Sign a file with PGP private key and save signature to out_sig."""
    # Load private key
    with open(pgp_priv_path, 'r') as f:
        priv_key, _ = PGPKey.from_blob(f.read())
    
    if passphrase:
        with priv_key.unlock(passphrase):
            # Read file content
            with open(path, 'rb') as f:
                data = f.read()
            
            # Create signature
            message = PGPMessage.new(data)
            signature = priv_key.sign(message)
            
            # Save signature
            with open(out_sig, 'w') as f:
                f.write(str(signature))
    else:
        # Read file content
        with open(path, 'rb') as f:
            data = f.read()
        
        # Create signature
        message = PGPMessage.new(data)
        signature = priv_key.sign(message)
        
        # Save signature
        with open(out_sig, 'w') as f:
            f.write(str(signature))
    
    return out_sig
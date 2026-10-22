"""Recoverable client credentials, encrypted using a local persistent Fernet key."""
import os, tempfile
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken

def load_cipher(data_dir, encrypted_rows=False):
    key_path=Path(data_dir)/'credential.key'
    if not key_path.exists():
        if encrypted_rows:raise RuntimeError('credential.key is missing: restore the matching encryption key before starting')
        fd,temp_path=tempfile.mkstemp(prefix='.credential-',dir=data_dir)
        try:
            with os.fdopen(fd,'wb') as f:
                f.write(Fernet.generate_key());f.flush();os.fsync(f.fileno())
            try:os.link(temp_path,key_path)
            except FileExistsError:pass
        finally:os.unlink(temp_path)
    return Fernet(key_path.read_bytes())

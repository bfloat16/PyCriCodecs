from typing import Optional

__all__ = ["decrypt"]

def decrypt(data: bytes, mainkey: int, subkey: Optional[int] = ...) -> bytes:
    """
    HCA decryptor (no audio decode): decrypt to ciph=0 and rebuild CRCs.

    Decrypt an HCA file (bytes) to a new HCA with ciph=0, rebuilding header & per-frame CRCs.

    Args:
        data: original .hca file content (bytes)
        mainkey: base keycode (int)
        subkey: optional subkey (int); combined as:
            key' = key * (((subkey << 16) | ((~subkey + 2) & 0xFFFF))) then low 56 bits

    Returns:
        bytes of the decrypted .hca file
    """
    ...

"""
TLS 1.3 record layer (RFC 8446 Section 5.2).

Every post-ServerHello record is TLSCiphertext (content type 0x17).
Inner plaintext = data || inner_content_type (1 byte).
Nonce = IV XOR left-padded sequence number.
AAD  = the 5-byte outer TLS record header.
"""

import constants


def _make_nonce(iv: bytes, seq_num: int) -> bytes:
    padded = seq_num.to_bytes(len(iv), 'big')
    return bytes(a ^ b for a, b in zip(iv, padded))


def encrypt_record(key: bytes, iv: bytes, seq_num: int,
                   inner_content_type: bytes, plaintext: bytes,
                   cipher_suite_name: str = '') -> bytes:
    """
    Returns raw ciphertext (no TLS record header).
    Caller wraps with: CONTENT_TYPE_DATA || 0x03 0x03 || length(2) || result
    """
    nonce = _make_nonce(iv, seq_num)
    inner = plaintext + inner_content_type          # append real content type
    ciphertext_len = len(inner) + 16                # +16 for AEAD tag
    aad = constants.CONTENT_TYPE_DATA + b'\x03\x03' + ciphertext_len.to_bytes(2, 'big')
    return _aead_encrypt(key, nonce, inner, aad, cipher_suite_name)


def decrypt_record(key: bytes, iv: bytes, seq_num: int,
                   record_header: bytes, encrypted: bytes,
                   cipher_suite_name: str = '') -> tuple:
    """
    record_header: the 5-byte TLS record header (used as AAD).
    Returns (inner_content_type: bytes, plaintext: bytes).
    """
    nonce = _make_nonce(iv, seq_num)
    inner = _aead_decrypt(key, nonce, encrypted, record_header, cipher_suite_name)
    return inner[-1:], inner[:-1]


def _aead_encrypt(key, nonce, plaintext, aad, cipher_suite_name):
    if 'CHACHA20' in cipher_suite_name:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def _aead_decrypt(key, nonce, ciphertext, aad, cipher_suite_name):
    if 'CHACHA20' in cipher_suite_name:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key).decrypt(nonce, ciphertext, aad)

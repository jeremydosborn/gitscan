# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jeremy D. Osborn

"""
Bundle survey responses for secure transmission.

Security architecture:
1. Payload contains ONLY: version + single score + submission_id (no other identifying info)
2. Padded to fixed size (prevents length fingerprinting)
3. Encrypted with research team's public key (age)
4. Split into shares via Shamir secret sharing (2-of-3 threshold)
5. Each share destined for different infrastructure provider

Even if an attacker compromises one provider AND obtains the private key,
they cannot reconstruct submissions without a second provider.

Note: The Shamir secret sharing implementation is work-in-progress and subject to change. It should not be
considered production-ready.
"""

import json
import secrets
import subprocess
import tempfile
from pathlib import Path
from typing import List, Tuple
import hashlib
import hmac
from itertools import combinations

# Fixed payload size to prevent length fingerprinting
PADDED_SIZE = 4096

# Default public key path - survey admin sets this during init
DEFAULT_PUBKEY_PATH = Path.home() / ".gitgap-admin" / "survey" / "public.key"

def pad_payload(data: bytes, size: int = PADDED_SIZE) -> bytes:
    """
    Pad payload to fixed size with random bytes.
    
    This prevents attackers from inferring anything about the payload
    based on encrypted blob size.
    
    Format: [4-byte length][payload][random padding]
    """
    if len(data) > size - 4:  # Reserve space for length prefix
        raise ValueError(f"Payload too large: {len(data)} bytes (max {size - 4})")
    
    length_prefix = len(data).to_bytes(4, 'big')
    padding_needed = size - 4 - len(data)
    padding = secrets.token_bytes(padding_needed)
    
    return length_prefix + data + padding


def unpad_payload(padded_data: bytes) -> bytes:
    """Remove padding from a padded payload."""
    length = int.from_bytes(padded_data[:4], 'big')
    return padded_data[4:4 + length]


def encrypt_age(plaintext: bytes, public_key: str) -> bytes:
    """
    Encrypt data using age.
    
    Args:
        plaintext: Data to encrypt
        public_key: age public key (age1...)
        
    Returns:
        Encrypted bytes (age armor format)
    """
    # Write plaintext to temp file
    with tempfile.NamedTemporaryFile(delete=False) as tmp_in:
        tmp_in.write(plaintext)
        tmp_in_path = tmp_in.name
    
    tmp_out_path = tmp_in_path + ".age"
    
    try:
        result = subprocess.run(
            ["age", "-r", public_key, "-o", tmp_out_path, tmp_in_path],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"age encryption failed: {result.stderr}")
        
        with open(tmp_out_path, "rb") as f:
            return f.read()
            
    finally:
        Path(tmp_in_path).unlink(missing_ok=True)
        Path(tmp_out_path).unlink(missing_ok=True)


def decrypt_age(ciphertext: bytes, private_key_path: str) -> bytes:
    """
    Decrypt data using age.
    
    Args:
        ciphertext: Encrypted data
        private_key_path: Path to age private key file
        
    Returns:
        Decrypted bytes
    """
    with tempfile.NamedTemporaryFile(delete=False) as tmp_in:
        tmp_in.write(ciphertext)
        tmp_in_path = tmp_in.name
    
    try:
        result = subprocess.run(
            ["age", "-d", "-i", private_key_path, tmp_in_path],
            capture_output=True
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"age decryption failed: {result.stderr.decode()}")
        
        return result.stdout
        
    finally:
        Path(tmp_in_path).unlink(missing_ok=True)


def shamir_split(data: bytes, n: int = 3, threshold: int = 2) -> List[Tuple[int, bytes]]:
    """
    Split data into n shares where threshold shares are needed to reconstruct.
    
    Uses GF(256) arithmetic for byte-level Shamir secret sharing.
    
    Args:
        data: Data to split
        n: Number of shares to create
        threshold: Minimum shares needed to reconstruct
        
    Returns:
        List of (index, share_bytes) tuples
    """
    if threshold > n:
        raise ValueError(f"threshold ({threshold}) cannot exceed n ({n})")
    if threshold < 2:
        raise ValueError("threshold must be at least 2")
    if n > 255:
        raise ValueError("n must be <= 255 for GF(256)")
    
    # GF(256) with primitive polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)
    def gf_mul(a: int, b: int) -> int:
        """Multiply two numbers in GF(256)."""
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi = a & 0x80
            a = (a << 1) & 0xFF
            if hi:
                a ^= 0x1B  # Reduce by primitive polynomial
            b >>= 1
        return p
    
    def eval_poly(coeffs: List[int], x: int) -> int:
        """Evaluate polynomial at x in GF(256)."""
        result = 0
        for coeff in reversed(coeffs):
            result = gf_mul(result, x) ^ coeff
        return result
    
    shares = [bytearray() for _ in range(n)]
    
    # Process each byte of input
    for byte in data:
        # Generate random polynomial with secret as constant term
        # coeffs[0] = secret, coeffs[1..threshold-1] = random
        coeffs = [byte] + [secrets.randbelow(256) for _ in range(threshold - 1)]
        
        # Evaluate polynomial at points 1, 2, ..., n
        for i in range(n):
            x = i + 1  # Use 1-indexed points (0 would reveal secret)
            shares[i].append(eval_poly(coeffs, x))
    
    return [(i + 1, bytes(share)) for i, share in enumerate(shares)]


def shamir_reconstruct(shares: List[Tuple[int, bytes]], threshold: int = 2) -> bytes:
    """
    Reconstruct data from Shamir shares using Lagrange interpolation.
    
    Args:
        shares: List of (index, share_bytes) tuples
        threshold: Minimum shares needed (for validation)
        
    Returns:
        Reconstructed data
    """
    if len(shares) < threshold:
        raise ValueError(f"Need at least {threshold} shares, got {len(shares)}")
    
    # Use only threshold shares
    shares = shares[:threshold]
    
    # Verify all shares are same length
    length = len(shares[0][1])
    if not all(len(s[1]) == length for s in shares):
        raise ValueError("All shares must be same length")
    
    # GF(256) operations
    def gf_mul(a: int, b: int) -> int:
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi = a & 0x80
            a = (a << 1) & 0xFF
            if hi:
                a ^= 0x1B
            b >>= 1
        return p
    
    def gf_inv(a: int) -> int:
        """Multiplicative inverse in GF(256) using extended Euclidean algorithm."""
        if a == 0:
            raise ValueError("Cannot invert 0")
        # Use Fermat's little theorem: a^(-1) = a^(254) in GF(256)
        result = 1
        power = a
        exp = 254
        while exp:
            if exp & 1:
                result = gf_mul(result, power)
            power = gf_mul(power, power)
            exp >>= 1
        return result
    
    def gf_div(a: int, b: int) -> int:
        return gf_mul(a, gf_inv(b))
    
    # Reconstruct each byte using Lagrange interpolation
    result = bytearray()
    xs = [s[0] for s in shares]
    
    for byte_idx in range(length):
        ys = [s[1][byte_idx] for s in shares]
        
        # Lagrange interpolation at x=0
        secret = 0
        for i, (xi, yi) in enumerate(zip(xs, ys)):
            # Compute Lagrange basis polynomial at x=0
            num = 1
            den = 1
            for j, xj in enumerate(xs):
                if i != j:
                    num = gf_mul(num, xj)  # (0 - xj) = xj in GF(256)
                    den = gf_mul(den, xi ^ xj)  # (xi - xj)
            
            basis = gf_div(num, den)
            secret ^= gf_mul(yi, basis)
        
        result.append(secret)
    
    return bytes(result)


def load_public_key(key_path: Path = None) -> str:
    """Load the survey public key."""
    if key_path is None:
        key_path = DEFAULT_PUBKEY_PATH
    
    if not key_path.exists():
        raise FileNotFoundError(
            f"Public key not found at {key_path}. "
            "Run 'gitgap-admin init' to create a survey."
        )
    
    key = key_path.read_text().strip()
    if not key.startswith("age1"):
        raise ValueError(f"Invalid age public key: {key[:20]}...")
    
    return key


def prepare_submission(payload: dict, public_key: str = None) -> list:
    """
    Full pipeline: serialize -> pad -> encrypt -> split
    """
    # Load public key if not provided
    if public_key is None:
        public_key = load_public_key()
    
    # Serialize
    json_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    
    # Checksum to avoid single share compromise data loss
    checksum = hashlib.sha256(json_bytes).digest()[:4]
    json_bytes = checksum + json_bytes

    # Pad to fixed size
    padded = pad_payload(json_bytes)
    
    # Encrypt
    encrypted = encrypt_age(padded, public_key)
    
    # Split into shares
    shares = shamir_split(encrypted, n=3, threshold=2)
    
    return shares


def reconstruct_submission(shares: List[Tuple[int, bytes]], private_key_path: str) -> dict:
    """
    Reverse pipeline: reconstruct -> decrypt -> unpad -> verify -> deserialize

    Tries all combinations of threshold shares to handle corrupted shares.
    
    Args:
        shares: List of (shard_index, encrypted_share) tuples
        private_key_path: Path to age private key
        
    Returns:
        Original payload dict
    """
    for combo in combinations(shares, 2):
        try:
            encrypted = shamir_reconstruct(list(combo), threshold=2)
            padded = decrypt_age(encrypted, private_key_path)
            json_bytes = unpad_payload(padded)

            checksum = json_bytes[:4]
            json_bytes = json_bytes[4:]
            expected = hashlib.sha256(json_bytes).digest()[:4]

            if not hmac.compare_digest(checksum, expected):
                continue

            return json.loads(json_bytes.decode('utf-8'))

        except (RuntimeError, ValueError):
            continue

    raise ValueError("Reconstruction failed - all share combinations invalid")

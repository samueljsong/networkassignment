#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

PASSLIB_AVAILABLE = False
try:
    from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt
    PASSLIB_AVAILABLE = True
except Exception:
    PASSLIB_AVAILABLE = False

BCRYPT_AVAILABLE = False
try:
    import bcrypt as pybcrypt
    BCRYPT_AVAILABLE = True
except Exception:
    BCRYPT_AVAILABLE = False

YESCRYPT_WRAP_AVAILABLE = False
try:
    from yescrypt_wrap import verify_yescrypt
    YESCRYPT_WRAP_AVAILABLE = True
except Exception:
    YESCRYPT_WRAP_AVAILABLE = False


class HashVerifier(Protocol):
    def verify(self, candidate: str) -> bool: ...


@dataclass
class Md5CryptVerifier:
    full_hash: str

    def verify(self, candidate: str) -> bool:
        try:
            return md5_crypt.verify(candidate, self.full_hash)
        except Exception:
            return False


@dataclass
class Sha256CryptVerifier:
    full_hash: str

    def verify(self, candidate: str) -> bool:
        try:
            return sha256_crypt.verify(candidate, self.full_hash)
        except Exception:
            return False


@dataclass
class Sha512CryptVerifier:
    full_hash: str

    def verify(self, candidate: str) -> bool:
        try:
            return sha512_crypt.verify(candidate, self.full_hash)
        except Exception:
            return False


@dataclass
class BcryptVerifier:
    full_hash: str

    def verify(self, candidate: str) -> bool:
        try:
            candidate_bytes = candidate.encode("utf-8")

            # bcrypt only uses the first 72 bytes
            if len(candidate_bytes) > 72:
                return False

            return pybcrypt.checkpw(candidate_bytes, self.full_hash.encode("utf-8"))
        except Exception:
            return False


@dataclass
class YescryptVerifier:
    full_hash: str

    def verify(self, candidate: str) -> bool:
        try:
            return verify_yescrypt(candidate, self.full_hash)
        except Exception:
            return False


def detect_algorithm_name(full_hash: str) -> str:
    if full_hash.startswith("$1$"):
        return "md5_crypt"
    if full_hash.startswith("$5$"):
        return "sha256_crypt"
    if full_hash.startswith("$6$"):
        return "sha512_crypt"
    if full_hash.startswith("$2a$") or full_hash.startswith("$2b$") or full_hash.startswith("$2y$"):
        return "bcrypt"
    if full_hash.startswith("$y$"):
        return "yescrypt"
    return "unknown"


def build_verifier(full_hash: str) -> HashVerifier:
    algo = detect_algorithm_name(full_hash)

    if algo == "md5_crypt":
        if not PASSLIB_AVAILABLE:
            raise RuntimeError("md5_crypt requires passlib. Install with: pip install passlib")
        return Md5CryptVerifier(full_hash)

    if algo == "sha256_crypt":
        if not PASSLIB_AVAILABLE:
            raise RuntimeError("sha256_crypt requires passlib. Install with: pip install passlib")
        return Sha256CryptVerifier(full_hash)

    if algo == "sha512_crypt":
        if not PASSLIB_AVAILABLE:
            raise RuntimeError("sha512_crypt requires passlib. Install with: pip install passlib")
        return Sha512CryptVerifier(full_hash)

    if algo == "bcrypt":
        if not BCRYPT_AVAILABLE:
            raise RuntimeError("bcrypt requires bcrypt. Install with: pip install bcrypt")
        return BcryptVerifier(full_hash)

    if algo == "yescrypt":
        if not YESCRYPT_WRAP_AVAILABLE:
            raise RuntimeError(
                "yescrypt requires yescrypt_wrap.py and libyescrypt_wrap.so "
                "to be present in the same directory."
            )
        return YescryptVerifier(full_hash)

    raise RuntimeError(f"Unsupported hash algorithm: {algo}")
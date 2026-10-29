#!/usr/bin/env python3
"""Secure examination-paper exchange demo using hybrid encryption and signatures.

This workshop implementation uses RSA-3072, AES-256-GCM, RSA-OAEP-SHA256,
and RSA-PSS-SHA256. Private keys are stored as password-encrypted PKCS#8 PEM.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = 1
RSA_BITS = 3072
AES_KEY_BITS = 256
GCM_NONCE_BYTES = 12
GCM_TAG_BYTES = 16
EXPECTED_ALGORITHMS = {
    "content_encryption": "AES-256-GCM",
    "key_encryption": "RSA-OAEP-SHA256",
    "signature": "RSA-PSS-SHA256",
}
PACKAGE_FIELDS = {
    "version", "algorithms", "metadata", "encrypted_session_key",
    "nonce", "ciphertext", "tag", "signature",
}
METADATA_FIELDS = {"filename", "size_bytes", "created_utc"}


class SecureExchangeError(Exception):
    """Expected, user-safe error in the secure exchange workflow."""


def canonical_json(value: Any) -> bytes:
    """Stable representation used for signing and as AES-GCM AAD."""
    try:
        text = json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise SecureExchangeError("Package contains invalid JSON-compatible data.") from exc
    return text.encode("utf-8")


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(value: Any, field_name: str) -> bytes:
    if not isinstance(value, str):
        raise SecureExchangeError(f"Package field '{field_name}' must be Base64 text.")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise SecureExchangeError(f"Package field '{field_name}' is not valid Base64.") from exc


def _set_private_permissions(path: Path) -> None:
    # POSIX permissions are best-effort; Windows uses its own ACL model.
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _atomic_write(path: Path, data: bytes, *, private: bool = False, overwrite: bool = False) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise SecureExchangeError(f"Refusing to overwrite existing file: {path}")
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    temp_path = Path(temp_name)
    try:
        if private:
            _set_private_permissions(temp_path)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists() and not overwrite:
            raise SecureExchangeError(f"Refusing to overwrite existing file: {path}")
        os.replace(temp_path, path)
        if private:
            _set_private_permissions(path)
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass


def _generate_rsa_key_pair(private_path: Path, public_path: Path, passphrase: str) -> None:
    if not passphrase or len(passphrase) < 12:
        raise SecureExchangeError("Private-key passphrases must contain at least 12 characters.")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _atomic_write(private_path, private_pem, private=True, overwrite=True)
    _atomic_write(public_path, public_pem, private=False, overwrite=True)


def _load_private_key(path: Path, passphrase: str):
    try:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=passphrase.encode("utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise SecureExchangeError(
            f"Could not load private key '{path}'. Check the passphrase and key file."
        ) from exc
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < RSA_BITS:
        raise SecureExchangeError(f"Private key '{path}' is not an RSA-{RSA_BITS} (or larger) key.")
    return key


def _load_public_key(path: Path):
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise SecureExchangeError(f"Could not load trusted public key '{path}'.") from exc
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < RSA_BITS:
        raise SecureExchangeError(f"Public key '{path}' is not an RSA-{RSA_BITS} (or larger) key.")
    return key


def setup_workspace(workspace: Path, sender_passphrase: str, recipient_passphrase: str, *, force: bool = False) -> None:
    """Create sender/recipient folders and model a trusted public-key exchange."""
    workspace = Path(workspace).resolve()
    if not sender_passphrase or len(sender_passphrase) < 12:
        raise SecureExchangeError("Sender private-key passphrase must contain at least 12 characters.")
    if not recipient_passphrase or len(recipient_passphrase) < 12:
        raise SecureExchangeError("Recipient private-key passphrase must contain at least 12 characters.")
    sender_private = workspace / "sender/keys/sender_private.pem"
    sender_public = workspace / "sender/keys/sender_public.pem"
    recipient_private = workspace / "recipient/keys/recipient_private.pem"
    recipient_public = workspace / "recipient/keys/recipient_public.pem"
    key_paths = [sender_private, sender_public, recipient_private, recipient_public]
    existing = [p for p in key_paths if p.exists()]
    if existing and not force:
        raise SecureExchangeError(
            "Key files already exist. Use a fresh workspace or pass --force to replace keys "
            "(which makes packages created with the old keys undecryptable)."
        )

    for relative in (
        "sender/keys", "sender/trusted", "sender/input", "sender/outgoing",
        "recipient/keys", "recipient/trusted", "recipient/incoming", "recipient/received",
    ):
        (workspace / relative).mkdir(parents=True, exist_ok=True)

    _generate_rsa_key_pair(sender_private, sender_public, sender_passphrase)
    _generate_rsa_key_pair(recipient_private, recipient_public, recipient_passphrase)

    # Copies model public keys delivered over a trusted channel before the exchange.
    _atomic_write(
        workspace / "sender/trusted/recipient_public.pem", recipient_public.read_bytes(), overwrite=True
    )
    _atomic_write(
        workspace / "recipient/trusted/sender_public.pem", sender_public.read_bytes(), overwrite=True
    )

    sample_source = Path(__file__).resolve().parent / "sample_data/examination_paper_sample.txt"
    target_sample = workspace / "sender/input/examination_paper_sample.txt"
    if sample_source.exists() and not target_sample.exists():
        shutil.copyfile(sample_source, target_sample)
    print(f"Workspace initialised: {workspace}")
    print("Generated RSA-3072 key pairs with password-encrypted private PEM files.")
    print("Copied only public keys into each peer's trusted/ folder to model trusted key exchange.")


def _safe_filename(filename: str) -> str:
    if not isinstance(filename, str) or not filename or filename in {".", ".."}:
        raise SecureExchangeError("Package metadata contains an invalid filename.")
    # Disallow both POSIX and Windows path separators in output filenames.
    if "/" in filename or "\\" in filename or Path(filename).name != filename:
        raise SecureExchangeError("Unsafe filename in package metadata; no file was written.")
    if "\x00" in filename:
        raise SecureExchangeError("Invalid filename in package metadata; no file was written.")
    return filename


def create_package(plaintext: bytes, filename: str, recipient_public_key, sender_private_key) -> dict[str, Any]:
    """Encrypt bytes and sign every security-relevant package field."""
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    filename = _safe_filename(Path(filename).name)
    session_key = AESGCM.generate_key(bit_length=AES_KEY_BITS)
    nonce = os.urandom(GCM_NONCE_BYTES)
    metadata = {
        "filename": filename,
        "size_bytes": len(plaintext),
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    aad = canonical_json(metadata)
    ciphertext_and_tag = AESGCM(session_key).encrypt(nonce, plaintext, aad)
    ciphertext, tag = ciphertext_and_tag[:-GCM_TAG_BYTES], ciphertext_and_tag[-GCM_TAG_BYTES:]
    encrypted_key = recipient_public_key.encrypt(
        session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    core: dict[str, Any] = {
        "version": VERSION,
        "algorithms": EXPECTED_ALGORITHMS,
        "metadata": metadata,
        "encrypted_session_key": _b64encode(encrypted_key),
        "nonce": _b64encode(nonce),
        "ciphertext": _b64encode(ciphertext),
        "tag": _b64encode(tag),
    }
    signature = sender_private_key.sign(
        canonical_json(core),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return {**core, "signature": _b64encode(signature)}


def encrypt_file(input_path: Path, output_path: Path, sender_private_key, recipient_public_key) -> dict[str, Any]:
    input_path = Path(input_path)
    try:
        plaintext = input_path.read_bytes()
    except OSError as exc:
        raise SecureExchangeError(f"Could not read input file: {input_path}") from exc
    package = create_package(plaintext, input_path.name, recipient_public_key, sender_private_key)
    serialized = (json.dumps(package, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")
    _atomic_write(Path(output_path), serialized, overwrite=False)
    return package


def _strict_json_loads(raw: str) -> Any:
    def reject_duplicate_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise SecureExchangeError(f"Package JSON has a duplicate field: {key}")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=reject_duplicate_pairs)
    except SecureExchangeError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise SecureExchangeError("Package is not valid JSON.") from exc


def load_package(path: Path) -> dict[str, Any]:
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise SecureExchangeError(f"Could not read package: {path}") from exc
    package = _strict_json_loads(raw)
    if not isinstance(package, dict):
        raise SecureExchangeError("Package root must be a JSON object.")
    return package


def verify_and_decrypt(package: dict[str, Any], sender_public_key, recipient_private_key) -> tuple[bytes, dict[str, Any]]:
    """Verify signature, unwrap session key, then GCM-authenticate before returning bytes."""
    if not isinstance(package, dict) or set(package.keys()) != PACKAGE_FIELDS:
        raise SecureExchangeError("Package structure is invalid or contains unexpected fields.")
    if package.get("version") != VERSION:
        raise SecureExchangeError("Unsupported package version.")
    if package.get("algorithms") != EXPECTED_ALGORITHMS:
        raise SecureExchangeError("Unsupported or altered algorithm declaration.")
    metadata = package.get("metadata")
    if not isinstance(metadata, dict) or set(metadata.keys()) != METADATA_FIELDS:
        raise SecureExchangeError("Package metadata structure is invalid.")
    if not isinstance(metadata.get("filename"), str):
        raise SecureExchangeError("Package metadata filename is invalid.")
    if not isinstance(metadata.get("size_bytes"), int) or isinstance(metadata.get("size_bytes"), bool) or metadata["size_bytes"] < 0:
        raise SecureExchangeError("Package metadata file size is invalid.")
    if not isinstance(metadata.get("created_utc"), str):
        raise SecureExchangeError("Package metadata timestamp is invalid.")

    signature = _b64decode(package.get("signature"), "signature")
    core = {key: value for key, value in package.items() if key != "signature"}
    try:
        sender_public_key.verify(
            signature,
            canonical_json(core),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise SecureExchangeError(
            "Signature verification failed: the sender is not authenticated or the package was modified."
        ) from exc
    except (ValueError, TypeError) as exc:
        raise SecureExchangeError("Signature could not be verified; package rejected.") from exc

    # Decode and decrypt only after the sender signature has passed.
    encrypted_key = _b64decode(package["encrypted_session_key"], "encrypted_session_key")
    nonce = _b64decode(package["nonce"], "nonce")
    ciphertext = _b64decode(package["ciphertext"], "ciphertext")
    tag = _b64decode(package["tag"], "tag")
    if len(nonce) != GCM_NONCE_BYTES or len(tag) != GCM_TAG_BYTES:
        raise SecureExchangeError("Invalid AES-GCM nonce or authentication-tag length; package rejected.")

    try:
        session_key = recipient_private_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
    except (ValueError, TypeError) as exc:
        raise SecureExchangeError(
            "Session-key recovery failed: the recipient private key is incorrect or the key field is corrupt."
        ) from exc
    if len(session_key) != AES_KEY_BITS // 8:
        raise SecureExchangeError("Recovered session key has an invalid length; package rejected.")

    try:
        plaintext = AESGCM(session_key).decrypt(nonce, ciphertext + tag, canonical_json(metadata))
    except InvalidTag as exc:
        raise SecureExchangeError(
            "AES-GCM authentication failed: ciphertext, tag, or authenticated metadata is invalid. No plaintext was released."
        ) from exc
    except (ValueError, TypeError) as exc:
        raise SecureExchangeError("AES-GCM decryption failed; package rejected.") from exc

    if len(plaintext) != metadata["size_bytes"]:
        raise SecureExchangeError("Authenticated plaintext size does not match signed metadata; package rejected.")
    _safe_filename(metadata["filename"])
    return plaintext, metadata


def decrypt_to_file(
    package_path: Path, output_path: Path, sender_public_key, recipient_private_key, *, overwrite: bool = False
) -> tuple[Path, dict[str, Any], int]:
    """Write a plaintext file only after signature and AES-GCM checks both pass."""
    package = load_package(Path(package_path))
    plaintext, metadata = verify_and_decrypt(package, sender_public_key, recipient_private_key)
    destination = Path(output_path)
    _atomic_write(destination, plaintext, private=True, overwrite=overwrite)
    return destination, metadata, len(plaintext)


def _prompt_passphrase(label: str, *, confirm: bool = False) -> str:
    first = getpass.getpass(label)
    if confirm:
        second = getpass.getpass("Confirm passphrase: ")
        if first != second:
            raise SecureExchangeError("Passphrases did not match.")
    if not first:
        raise SecureExchangeError("Passphrase cannot be empty.")
    return first


def cmd_setup(args) -> None:
    sender_password = _prompt_passphrase("Create sender private-key passphrase (12+ characters): ", confirm=True)
    recipient_password = _prompt_passphrase("Create recipient private-key passphrase (12+ characters): ", confirm=True)
    setup_workspace(Path(args.workspace), sender_password, recipient_password, force=args.force)


def cmd_encrypt(args) -> None:
    workspace = Path(args.workspace).resolve()
    sender_password = _prompt_passphrase("Sender private-key passphrase: ")
    sender_key = _load_private_key(workspace / "sender/keys/sender_private.pem", sender_password)
    recipient_key = _load_public_key(workspace / "sender/trusted/recipient_public.pem")
    input_path = Path(args.input).resolve()
    output_path = Path(args.output).resolve() if args.output else (
        workspace / "sender/outgoing" / f"{input_path.name}.secure.json"
    )
    package = encrypt_file(input_path, output_path, sender_key, recipient_key)
    print(f"Encrypted and signed package created: {output_path}")
    print(f"Plaintext bytes: {package['metadata']['size_bytes']}; encrypted package bytes: {output_path.stat().st_size}")


def cmd_transfer(args) -> None:
    workspace = Path(args.workspace).resolve()
    source = Path(args.package).resolve()
    if not source.is_file():
        raise SecureExchangeError(f"Package does not exist: {source}")
    destination = Path(args.output).resolve() if args.output else workspace / "recipient/incoming" / source.name
    if source == destination:
        raise SecureExchangeError("Transfer source and destination are the same file.")
    try:
        _atomic_write(destination, source.read_bytes(), overwrite=False)
    except OSError as exc:
        raise SecureExchangeError(f"Could not copy package into recipient/incoming: {destination}") from exc
    print(f"Package copied into recipient's incoming folder: {destination}")
    print("This copy simulates transmission over the untrusted channel; it does not prove the channel is safe.")


def cmd_decrypt(args) -> None:
    workspace = Path(args.workspace).resolve()
    recipient_password = _prompt_passphrase("Recipient private-key passphrase: ")
    recipient_key = _load_private_key(workspace / "recipient/keys/recipient_private.pem", recipient_password)
    sender_key = _load_public_key(workspace / "recipient/trusted/sender_public.pem")
    package_path = Path(args.package).resolve()
    # Verify the package once to obtain signed metadata for the default output path.
    package = load_package(package_path)
    plaintext, metadata = verify_and_decrypt(package, sender_key, recipient_key)
    output_path = Path(args.output).resolve() if args.output else (
        workspace / "recipient/received" / _safe_filename(metadata["filename"])
    )
    _atomic_write(output_path, plaintext, private=True, overwrite=args.overwrite)
    print("All checks passed: sender signature verified and AES-GCM authentication succeeded.")
    print(f"Recovered file saved: {output_path}")
    print(f"Recovered bytes: {len(plaintext)}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Secure examination-paper exchange (RSA-3072 + AES-256-GCM + RSA-PSS)."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    setup = sub.add_parser("setup", help="Generate sender/recipient keys and exchange public keys.")
    setup.add_argument("--workspace", default="exam_workspace", help="Root folder for separate sender and recipient folders.")
    setup.add_argument("--force", action="store_true", help="Replace existing keys (old packages may become undecryptable).")
    setup.set_defaults(func=cmd_setup)

    encrypt = sub.add_parser("encrypt", help="Encrypt a paper and sign the complete package.")
    encrypt.add_argument("--workspace", default="exam_workspace")
    encrypt.add_argument("--input", required=True, help="Path to the examination paper.")
    encrypt.add_argument("--output", help="Output package path; defaults to sender/outgoing/<input>.secure.json.")
    encrypt.set_defaults(func=cmd_encrypt)

    transfer = sub.add_parser("transfer", help="Copy a package to recipient/incoming to simulate network transmission.")
    transfer.add_argument("--workspace", default="exam_workspace")
    transfer.add_argument("--package", required=True, help="Existing package file from sender/outgoing.")
    transfer.add_argument("--output", help="Optional destination path.")
    transfer.set_defaults(func=cmd_transfer)

    decrypt = sub.add_parser("decrypt", help="Verify, decrypt, authenticate, then save the file.")
    decrypt.add_argument("--workspace", default="exam_workspace")
    decrypt.add_argument("--package", required=True, help="Received package path.")
    decrypt.add_argument("--output", help="Optional destination path for the authenticated plaintext.")
    decrypt.add_argument("--overwrite", action="store_true", help="Allow overwriting the output file after all checks pass.")
    decrypt.set_defaults(func=cmd_decrypt)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
        return 0
    except SecureExchangeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

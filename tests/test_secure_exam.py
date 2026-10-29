import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import secure_exam


class SecureExamExchangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Use RSA-3072 in tests to match the workshop's real configuration.
        cls.sender_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.sender_public = cls.sender_private.public_key()
        cls.recipient_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.recipient_public = cls.recipient_private.public_key()
        cls.wrong_sender_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.wrong_sender_public = cls.wrong_sender_private.public_key()
        cls.wrong_recipient_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.plaintext = b"CONFIDENTIAL EXAM SAMPLE\nQuestion 1: Explain AES-GCM.\n"

    def tearDown(self):
        self.temp.cleanup()

    def make_package(self):
        return secure_exam.create_package(
            self.plaintext, "exam_sample.txt", self.recipient_public, self.sender_private
        )

    def save_package(self, package, name="package.json"):
        path = self.root / name
        path.write_text(json.dumps(package, indent=2), encoding="utf-8")
        return path

    def test_authorized_recipient_recovers_original(self):
        package_path = self.save_package(self.make_package())
        output_path = self.root / "received" / "exam_sample.txt"
        saved, metadata, byte_count = secure_exam.decrypt_to_file(
            package_path, output_path, self.sender_public, self.recipient_private
        )
        self.assertEqual(saved, output_path)
        self.assertEqual(output_path.read_bytes(), self.plaintext)
        self.assertEqual(metadata["filename"], "exam_sample.txt")
        self.assertEqual(byte_count, len(self.plaintext))

    def test_attacker_modifications_are_rejected_without_output(self):
        tamper_cases = ("ciphertext", "metadata", "signature")
        for case in tamper_cases:
            with self.subTest(case=case):
                package = self.make_package()
                if case == "ciphertext":
                    raw = bytearray(base64.b64decode(package["ciphertext"]))
                    raw[0] ^= 0x01
                    package["ciphertext"] = base64.b64encode(raw).decode("ascii")
                elif case == "metadata":
                    package["metadata"]["filename"] = "replacement_exam.txt"
                else:
                    raw = bytearray(base64.b64decode(package["signature"]))
                    raw[0] ^= 0x01
                    package["signature"] = base64.b64encode(raw).decode("ascii")

                package_path = self.save_package(package, f"tampered_{case}.json")
                output_path = self.root / f"received_{case}.txt"
                with self.assertRaises(secure_exam.SecureExchangeError):
                    secure_exam.decrypt_to_file(
                        package_path, output_path, self.sender_public, self.recipient_private
                    )
                self.assertFalse(output_path.exists(), "No plaintext file may be created after a failed check")

    def test_wrong_recipient_private_key_is_rejected(self):
        package_path = self.save_package(self.make_package())
        output_path = self.root / "wrong_recipient.txt"
        with self.assertRaisesRegex(secure_exam.SecureExchangeError, "Session-key recovery failed"):
            secure_exam.decrypt_to_file(
                package_path, output_path, self.sender_public, self.wrong_recipient_private
            )
        self.assertFalse(output_path.exists())

    def test_wrong_sender_public_key_is_rejected(self):
        package_path = self.save_package(self.make_package())
        output_path = self.root / "wrong_sender.txt"
        with self.assertRaisesRegex(secure_exam.SecureExchangeError, "Signature verification failed"):
            secure_exam.decrypt_to_file(
                package_path, output_path, self.wrong_sender_public, self.recipient_private
            )
        self.assertFalse(output_path.exists())

    def test_gcm_tag_is_checked_even_if_package_signature_is_valid(self):
        # Fault injection: model a package whose signer signed a corrupted ciphertext.
        # Ordinary network attackers cannot do this without the sender's private key.
        package = self.make_package()
        raw = bytearray(base64.b64decode(package["ciphertext"]))
        raw[0] ^= 0x04
        package["ciphertext"] = base64.b64encode(raw).decode("ascii")
        core = {key: value for key, value in package.items() if key != "signature"}
        signature = self.sender_private.sign(
            secure_exam.canonical_json(core),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        package["signature"] = base64.b64encode(signature).decode("ascii")
        package_path = self.save_package(package, "bad_gcm_tag.json")
        output_path = self.root / "gcm_failure.txt"
        with self.assertRaisesRegex(secure_exam.SecureExchangeError, "AES-GCM authentication failed"):
            secure_exam.decrypt_to_file(
                package_path, output_path, self.sender_public, self.recipient_private
            )
        self.assertFalse(output_path.exists())

    def test_encrypting_same_file_twice_produces_different_packages(self):
        first = self.make_package()
        second = self.make_package()
        self.assertNotEqual(first["nonce"], second["nonce"])
        self.assertNotEqual(first["encrypted_session_key"], second["encrypted_session_key"])
        self.assertNotEqual(first, second)


    def test_separate_sender_recipient_folder_cli_workflow(self):
        workspace = self.root / "exam_workspace"
        sender_password = "sender-workshop-passphrase-01"
        recipient_password = "recipient-workshop-passphrase-02"

        with patch("secure_exam.getpass.getpass", side_effect=[sender_password, sender_password, recipient_password, recipient_password]):
            self.assertEqual(secure_exam.main(["setup", "--workspace", str(workspace)]), 0)

        sender_private_path = workspace / "sender/keys/sender_private.pem"
        recipient_private_path = workspace / "recipient/keys/recipient_private.pem"
        self.assertIn(b"ENCRYPTED PRIVATE KEY", sender_private_path.read_bytes())
        self.assertIn(b"ENCRYPTED PRIVATE KEY", recipient_private_path.read_bytes())
        self.assertEqual(
            (workspace / "recipient/trusted/sender_public.pem").read_bytes(),
            (workspace / "sender/keys/sender_public.pem").read_bytes(),
        )
        self.assertEqual(
            (workspace / "sender/trusted/recipient_public.pem").read_bytes(),
            (workspace / "recipient/keys/recipient_public.pem").read_bytes(),
        )

        input_path = workspace / "sender/input/examination_paper_sample.txt"
        encrypted_path = workspace / "sender/outgoing/exam1.secure.json"
        with patch("secure_exam.getpass.getpass", return_value=sender_password):
            self.assertEqual(secure_exam.main([
                "encrypt", "--workspace", str(workspace), "--input", str(input_path), "--output", str(encrypted_path)
            ]), 0)

        with patch("secure_exam.getpass.getpass", return_value=recipient_password):
            self.assertEqual(secure_exam.main(["transfer", "--workspace", str(workspace), "--package", str(encrypted_path)]), 0)
            received_package = workspace / "recipient/incoming/exam1.secure.json"
            self.assertEqual(secure_exam.main([
                "decrypt", "--workspace", str(workspace), "--package", str(received_package)
            ]), 0)

        recovered = workspace / "recipient/received/examination_paper_sample.txt"
        self.assertTrue(recovered.exists())
        self.assertEqual(recovered.read_bytes(), input_path.read_bytes())

    def test_plaintext_does_not_appear_in_serialized_package(self):
        package_bytes = json.dumps(self.make_package()).encode("utf-8")
        self.assertNotIn(self.plaintext, package_bytes)


if __name__ == "__main__":
    unittest.main(verbosity=2)

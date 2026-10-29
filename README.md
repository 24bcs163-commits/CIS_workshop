# Secure Examination-Paper Exchange (Python)

A runnable workshop implementation of hybrid encryption and signed package verification.

## Security design

- **RSA-3072** key pairs for the sender and recipient.
- **AES-256-GCM** encrypts the examination file with a fresh random 256-bit session key and a fresh 96-bit nonce.
- **RSA-OAEP with SHA-256** encrypts the AES session key using the recipient's trusted public key.
- **RSA-PSS with SHA-256** signs a canonical representation of the entire package except the signature field itself. This covers the wrapped key, nonce, ciphertext, authentication tag, algorithm declarations, and metadata.
- The metadata is also supplied to AES-GCM as **additional authenticated data (AAD)**.
- Private RSA keys are stored as password-encrypted PKCS#8 PEM files. The application never writes an output plaintext file until signature verification, session-key recovery, and AES-GCM authentication all succeed.
- Received filenames are checked to prevent path traversal; existing output files are not overwritten unless `--overwrite` is explicitly supplied.

## 1. Install

Python 3.10 or newer is recommended. From this directory:

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

macOS/Linux:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
```

The application uses the maintained `cryptography` package; there is no need to implement cryptographic primitives manually.

## 2. Create sender and recipient folders

```bash
python secure_exam.py setup --workspace exam_workspace
```

The program asks you to create a passphrase (12 or more characters) for **each** private key, twice to confirm it. Use two different passphrases. They are not stored in the program or written to a file.

This creates the following structure:

```text
exam_workspace/
├── sender/
│   ├── keys/       # sender private/public keys
│   ├── trusted/    # recipient public key, exchanged before sending
│   ├── input/      # paper to send
│   └── outgoing/   # signed encrypted packages
└── recipient/
    ├── keys/       # recipient private/public keys
    ├── trusted/    # sender public key, exchanged before sending
    ├── incoming/   # packages received from the channel
    └── received/   # only successfully authenticated plaintext files
```

For the workshop simulation, `setup` copies each public key into the peer's `trusted/` directory. This models the problem's assumption that public keys were exchanged over a trusted channel. **Do not trust a public key merely because it is inside a received package.** In a real deployment, verify key fingerprints or use a certificate/identity-verification process out of band.

The setup command copies `sample_data/examination_paper_sample.txt` into the sender's `input/` directory if it is not already there. `sample_data/example_encrypted_package.json` is an example encrypted envelope created with disposable in-memory keys; its private keys are intentionally not distributed. For a decryptable end-to-end exchange, create your own matched keys by running `setup`, then run `encrypt`, `transfer`, and `decrypt` below.

## 3. Sender encrypts and signs the paper

```bash
python secure_exam.py encrypt --workspace exam_workspace --input exam_workspace/sender/input/examination_paper_sample.txt --output exam_workspace/sender/outgoing/exam1.secure.json
```

Enter the sender's private-key passphrase. The output JSON package contains the encrypted session key, nonce, ciphertext, GCM tag, signed metadata, algorithm declarations, and digital signature. It does not contain the plaintext or private keys.

## 4. Simulate transfer over the untrusted channel

```bash
python secure_exam.py transfer --workspace exam_workspace --package exam_workspace/sender/outgoing/exam1.secure.json
```

This copies the package into `recipient/incoming/`. It represents the untrusted communication channel; it does not make the channel trusted. To simulate a network attacker, edit a field in the received JSON package before the receiver processes it.

## 5. Recipient verifies and decrypts

```bash
python secure_exam.py decrypt --workspace exam_workspace --package exam_workspace/recipient/incoming/exam1.secure.json
```

Enter the recipient's private-key passphrase. On success, the application writes the recovered paper into `recipient/received/`. On failure, it prints an error and does not create a new plaintext output file.

If you want to retain multiple successful decryptions with the same filename, provide `--output` with a different path. Existing output files are protected by default; use `--overwrite` only when you deliberately intend to replace one.

## 6. Run the required tests

```bash
python -m unittest discover -s tests -v
```

The tests cover:

1. Successful recovery by the authorised recipient.
2. Ciphertext, metadata, and signature tampering.
3. Decryption using the wrong recipient private key.
4. Signature verification with the wrong sender public key.
5. Two encryptions of the same file yielding different packages/nonces/session-key wraps.
6. AES-GCM authentication failure after signature-valid fault injection.
7. A check that the plaintext is not embedded in the JSON package.

The AES-GCM fault-injection case is deliberately artificial: it simulates a malformed package that nevertheless has a valid sender signature. An ordinary network attacker who lacks the sender's private key cannot create such a valid signature.

## How the protections work

- **Confidentiality:** AES-256-GCM encrypts the file; only a party able to use the recipient's private key can recover the random AES session key.
- **Integrity:** RSA-PSS detects changes to signed package fields. AES-GCM independently authenticates ciphertext and metadata AAD during decryption.
- **Sender authentication:** a valid signature under the recipient's pre-trusted sender public key indicates that the corresponding sender private key signed the package. This depends on correctly establishing trust in that public key.
- **Safe failure:** decryption returns plaintext only after the GCM tag is valid, and the receiver saves the file only after all checks succeed.

## Important limitations

This is a local workshop demonstration, not a full production file-transfer service. It reads each file into memory, assumes public keys were exchanged authentically, and does not provide certificate revocation, key rotation, audit logging, or network transport. For real confidential examination papers, follow the institute's key-management and security policies and obtain a security review.

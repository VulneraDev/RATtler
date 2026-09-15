# Encrypted offline recovery

RATtler can export an enabled Recovery Vault as one `.rattlervault` file for a
USB drive or other offline storage. This is an encrypted copy of the local
vault, not an automatic cloud backup. Nothing is uploaded.

## Simple USB workflow

1. Connect a USB drive and open **Ransomware** in RATtler.
2. Choose **Encrypted USB copy**.
3. Select the USB drive under Finder's **Locations** section.
4. Enter the same recovery password twice. Use at least 12 characters and keep
   it somewhere separate from the drive.
5. Wait for **Encrypted USB copy created**, then eject the drive in Finder.
6. Store the disconnected drive somewhere physically safe.

To recover, connect the drive, choose **Restore USB copy**, select the
`.rattlervault` file, and enter its password. RATtler authenticates the complete
bundle before it creates a new `RATtler USB Recovery …` folder on the Desktop.
It never writes over the original documents or an existing recovery folder.

## Encryption design

RATtler does not invent a cryptographic algorithm. Version 1 bundles use:

- AES-256-GCM for streaming authenticated encryption;
- Argon2id with a random 16-byte salt, 64 MiB memory, three iterations, and four
  lanes to derive the 256-bit key from the password;
- a new random 96-bit GCM nonce for every export; and
- the complete cleartext format header as authenticated additional data.

Only the format version, algorithm names, KDF parameters, salt, and nonce are
visible. The vault manifest, original paths, recovery metadata, and file content
are encrypted. The encrypted payload is a bounded tar stream containing only a
canonical manifest and content-addressed objects. No plaintext tar file is
created on disk.

During restore, RATtler reads the encrypted file once to validate its GCM tag
and discards all decrypted bytes. It then reads it again, validates the stream
again and checks every SHA-256 object name before writing eligible recovery
copies. If the second pass changes or fails, RATtler removes the new destination
it created. Inputs are capped at 1 GiB and archive paths are never extracted
directly.

## Password boundary

The macOS app collects the password with native `NSSecureTextField` controls.
It does not place the password in WebKit, command-line arguments, an environment
variable, a file, a report, or a log. The native host sends UTF-8 bytes to the
local engine through an anonymous pipe and clears that input buffer after the
engine exits.

RATtler does not save passwords or provide a reset mechanism. Losing the
password means losing access to that encrypted copy. Memory clearing is
best-effort because macOS and language runtimes may make internal copies.

## What this protects—and what it does not

An encrypted, disconnected USB copy protects recovery data if the drive is lost
and keeps an offline generation away from ransomware running on the Mac. No
single backup is “totally safe”: physical damage, a forgotten password, hostile
firmware, or an already-compromised Mac can still defeat recovery.

The working Recovery Vault under Application Support is not converted by this
feature. It remains private to the current account with mode `0700`/`0600` and
is covered by FileVault when FileVault is enabled. The `.rattlervault` export is
the password-encrypted portable copy. Keep more than one offline generation for
important data and periodically test restore with harmless files.

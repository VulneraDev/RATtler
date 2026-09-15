"""Password-encrypted, streaming Recovery Vault exports.

The container uses streaming AES-256-GCM from PyCA cryptography. A per-bundle
key is derived with Argon2id; RATtler defines only the small container that
carries the KDF parameters and encrypted tar stream, not a new cipher.
"""

import base64
import errno
import hashlib
import io
import json
import os
import shutil
import stat
import struct
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Dict, List, Optional, Tuple, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from .recovery import (
    DEFAULT_MAX_FILE_BYTES,
    MAX_MANIFEST_BYTES,
    _load_manifest,
    _prepare_store,
    _referenced_digests,
    _relative_recovery_path,
    _safe_read,
    _valid_digest,
    _version_for_recovery,
)


MAGIC = b"RATTLER-VAULT\x00\x01\n"
FORMAT_VERSION = 1
MAX_HEADER_BYTES = 4096
MAX_BUNDLE_BYTES = 1024 * 1024 * 1024
MAX_BUNDLE_FILE_BYTES = 64 * 1024 * 1024
MAX_PASSWORD_BYTES = 1024
MIN_PASSWORD_CHARACTERS = 12
ARGON2_MEMORY_KIB = 64 * 1024
ARGON2_ITERATIONS = 3
ARGON2_LANES = 4
SALT_BYTES = 16
NONCE_BYTES = 12
TAG_BYTES = 16
CONTEXT_PREFIX = b"RATtler encrypted recovery bundle v1\x00"
READ_CHUNK = 1024 * 1024


def _password_bytes(password: Union[str, bytes], *, require_strength: bool) -> bytes:
    if isinstance(password, str):
        if require_strength and len(password) < MIN_PASSWORD_CHARACTERS:
            raise ValueError("recovery password must contain at least 12 characters")
        encoded = password.encode("utf-8")
    elif isinstance(password, bytes):
        encoded = password
        if require_strength:
            try:
                if len(password.decode("utf-8")) < MIN_PASSWORD_CHARACTERS:
                    raise ValueError("recovery password must contain at least 12 characters")
            except UnicodeDecodeError as error:
                raise ValueError("recovery password must be valid UTF-8") from error
    else:
        raise TypeError("recovery password must be text")
    if not encoded:
        raise ValueError("recovery password is required")
    if len(encoded) > MAX_PASSWORD_BYTES:
        raise ValueError("recovery password is too long")
    return encoded


def _derive_key(password: bytes, salt: bytes) -> bytes:
    return Argon2id(
        salt=salt,
        length=32,
        iterations=ARGON2_ITERATIONS,
        lanes=ARGON2_LANES,
        memory_cost=ARGON2_MEMORY_KIB,
    ).derive(password)


def _header_bytes(salt: bytes, nonce: bytes) -> bytes:
    document = {
        "cipher": "AES-256-GCM",
        "format": "RATtler Recovery Vault",
        "kdf": {
            "iterations": ARGON2_ITERATIONS,
            "lanes": ARGON2_LANES,
            "memory_kib": ARGON2_MEMORY_KIB,
            "name": "Argon2id",
            "salt": base64.b64encode(salt).decode("ascii"),
        },
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "version": FORMAT_VERSION,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _read_exact(handle: BinaryIO, size: int) -> bytes:
    payload = handle.read(size)
    if len(payload) != size:
        raise ValueError("encrypted recovery bundle is truncated")
    return payload


def _read_header(handle: BinaryIO) -> Tuple[bytes, bytes, bytes, int]:
    if _read_exact(handle, len(MAGIC)) != MAGIC:
        raise ValueError("not a RATtler encrypted recovery bundle")
    header_size = struct.unpack(">I", _read_exact(handle, 4))[0]
    if header_size <= 0 or header_size > MAX_HEADER_BYTES:
        raise ValueError("encrypted recovery header is invalid")
    raw = _read_exact(handle, header_size)
    try:
        document = json.loads(raw.decode("utf-8"))
        kdf = document["kdf"]
        salt = base64.b64decode(kdf["salt"], validate=True)
        nonce = base64.b64decode(document["nonce"], validate=True)
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("encrypted recovery header is invalid") from error
    if (
        document.get("format") != "RATtler Recovery Vault"
        or document.get("version") != FORMAT_VERSION
        or document.get("cipher") != "AES-256-GCM"
        or kdf.get("name") != "Argon2id"
        or kdf.get("memory_kib") != ARGON2_MEMORY_KIB
        or kdf.get("iterations") != ARGON2_ITERATIONS
        or kdf.get("lanes") != ARGON2_LANES
        or len(salt) != SALT_BYTES
        or len(nonce) != NONCE_BYTES
    ):
        raise ValueError("encrypted recovery parameters are unsupported")
    return raw, salt, nonce, len(MAGIC) + 4 + header_size


def _open_regular_bundle(path: Path) -> BinaryIO:
    target = path.expanduser().absolute()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(str(target), flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("encrypted recovery bundle must be a single-link regular file")
        if metadata.st_size > MAX_BUNDLE_BYTES:
            raise ValueError("encrypted recovery bundle exceeds the safety limit")
        return os.fdopen(descriptor, "rb")
    except Exception:
        os.close(descriptor)
        raise


class _EncryptingWriter:
    def __init__(self, output: BinaryIO, encryptor: object):
        self.output = output
        self.encryptor = encryptor
        self.position = 0

    def write(self, payload: bytes) -> int:
        encrypted = self.encryptor.update(payload)
        if encrypted:
            self.output.write(encrypted)
        self.position += len(payload)
        return len(payload)

    def tell(self) -> int:
        return self.position

    def flush(self) -> None:
        self.output.flush()


class _DecryptingReader:
    def __init__(self, source: BinaryIO, decryptor: object, remaining: int):
        self.source = source
        self.decryptor = decryptor
        self.remaining = remaining
        self.buffer = bytearray()
        self.complete = False

    def _advance(self) -> None:
        if self.complete:
            return
        chunk = self.source.read(min(READ_CHUNK, self.remaining)) if self.remaining else b""
        if chunk:
            self.remaining -= len(chunk)
            self.buffer.extend(self.decryptor.update(chunk))
        else:
            self.buffer.extend(self.decryptor.finalize())
            self.complete = True

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            while not self.complete:
                self._advance()
            result = bytes(self.buffer)
            self.buffer.clear()
            return result
        while len(self.buffer) < size and not self.complete:
            self._advance()
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    def finish(self) -> None:
        while not self.complete:
            self._advance()
        self.buffer.clear()


def _tar_info(name: str, size: int) -> tarfile.TarInfo:
    item = tarfile.TarInfo(name)
    item.size = size
    item.mode = 0o600
    item.mtime = 0
    item.uid = 0
    item.gid = 0
    item.uname = ""
    item.gname = ""
    return item


def _write_tar_entry(archive: tarfile.TarFile, name: str, payload: bytes) -> None:
    archive.addfile(_tar_info(name, len(payload)), io.BytesIO(payload))


def _sync_directory(directory: Path) -> None:
    descriptor = -1
    try:
        descriptor = os.open(str(directory), os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def export_bundle(
    store: Path,
    destination: Path,
    password: Optional[Union[str, bytes]] = None,
    *,
    apply: bool = False,
) -> Dict[str, object]:
    """Export a complete vault as one password-encrypted file."""
    _, manifest_path, objects = _prepare_store(store)
    if not manifest_path.exists():
        raise ValueError("recovery vault is not enabled")
    manifest = _load_manifest(manifest_path, [], 0)
    referenced = sorted(_referenced_digests(manifest["files"]))
    max_file_bytes = int(manifest.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES))
    if max_file_bytes <= 0 or max_file_bytes > MAX_BUNDLE_FILE_BYTES:
        raise ValueError("recovery vault file limit is unsupported for encrypted export")
    object_bytes = 0
    for digest in referenced:
        path = objects / digest
        metadata = os.lstat(str(path))
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > max_file_bytes
        ):
            raise ValueError("recovery vault contains an invalid object")
        object_bytes += metadata.st_size
    target = destination.expanduser().absolute()
    result: Dict[str, object] = {
        "success": True,
        "applied": apply,
        "destination": str(target),
        "encrypted": True,
        "cipher": "AES-256-GCM",
        "kdf": "Argon2id",
        "objects": len(referenced),
        "plaintext_bytes": object_bytes,
    }
    if not apply:
        return result
    secret = _password_bytes(password if password is not None else b"", require_strength=True)
    if target.exists() or target.is_symlink():
        raise ValueError("encrypted recovery destination already exists")
    parent = target.parent
    if not parent.exists() or not parent.is_dir() or parent.is_symlink():
        raise ValueError("encrypted recovery destination folder is invalid")

    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    header = _header_bytes(salt, nonce)
    key = _derive_key(secret, salt)
    temporary: Optional[Path] = None
    try:
        descriptor, raw_path = tempfile.mkstemp(
            prefix=".%s." % target.name,
            suffix=".partial",
            dir=str(parent),
        )
        temporary = Path(raw_path)
        os.chmod(raw_path, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(MAGIC)
            output.write(struct.pack(">I", len(header)))
            output.write(header)
            encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
            encryptor.authenticate_additional_data(CONTEXT_PREFIX + header)
            writer = _EncryptingWriter(output, encryptor)
            manifest_payload = json.dumps(
                manifest, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8") + b"\n"
            bundle_payload = json.dumps({
                "created_at": datetime.now(timezone.utc).isoformat(),
                "objects": len(referenced),
                "product": "RATtler",
                "schema": FORMAT_VERSION,
            }, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
            with tarfile.open(fileobj=writer, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
                _write_tar_entry(archive, "bundle.json", bundle_payload)
                _write_tar_entry(archive, "manifest.json", manifest_payload)
                for digest in referenced:
                    payload, _ = _safe_read(objects / digest, max_file_bytes)
                    if hashlib.sha256(payload).hexdigest() != digest:
                        raise ValueError("recovery object failed integrity verification")
                    _write_tar_entry(archive, "objects/%s" % digest, payload)
            final = encryptor.finalize()
            if final:
                output.write(final)
            output.write(encryptor.tag)
            output.flush()
            os.fsync(output.fileno())
        if target.exists() or target.is_symlink():
            raise ValueError("encrypted recovery destination already exists")
        try:
            os.link(str(temporary), str(target))
            temporary.unlink()
        except OSError as error:
            if error.errno not in (errno.EPERM, errno.EOPNOTSUPP, errno.ENOTSUP):
                raise
            if target.exists() or target.is_symlink():
                raise ValueError("encrypted recovery destination already exists")
            os.rename(str(temporary), str(target))
        temporary = None
        try:
            os.chmod(str(target), 0o600)
        except OSError:
            pass
        _sync_directory(parent)
        result["bundle_bytes"] = target.stat().st_size
        return result
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass


def _ciphertext_details(handle: BinaryIO, offset: int) -> Tuple[int, bytes]:
    handle.seek(0, os.SEEK_END)
    remaining = handle.tell() - offset
    if remaining <= TAG_BYTES:
        raise ValueError("encrypted recovery bundle is truncated")
    ciphertext_size = remaining - TAG_BYTES
    handle.seek(offset + ciphertext_size)
    return ciphertext_size, _read_exact(handle, TAG_BYTES)


def _verify_stream(
    handle: BinaryIO, key: bytes, header: bytes, nonce: bytes, offset: int,
) -> Tuple[int, bytes]:
    ciphertext_size, tag = _ciphertext_details(handle, offset)
    handle.seek(offset)
    decryptor = Cipher(
        algorithms.AES(key), modes.GCM(nonce, tag, min_tag_length=TAG_BYTES),
    ).decryptor()
    decryptor.authenticate_additional_data(CONTEXT_PREFIX + header)
    try:
        remaining = ciphertext_size
        while remaining:
            chunk = _read_exact(handle, min(READ_CHUNK, remaining))
            remaining -= len(chunk)
            decryptor.update(chunk)
        decryptor.finalize()
    except InvalidTag as error:
        raise ValueError("recovery password is incorrect or the bundle is damaged") from error
    return ciphertext_size, tag


def _member_bytes(archive: tarfile.TarFile, member: tarfile.TarInfo, limit: int) -> bytes:
    if not member.isfile() or member.size < 0 or member.size > limit:
        raise ValueError("encrypted recovery bundle contains an invalid entry")
    extracted = archive.extractfile(member)
    if extracted is None:
        raise ValueError("encrypted recovery bundle entry is unreadable")
    payload = extracted.read(limit + 1)
    if len(payload) != member.size or len(payload) > limit:
        raise ValueError("encrypted recovery bundle entry is truncated")
    return payload


def _restore_tar(reader: _DecryptingReader, destination: Optional[Path]) -> Dict[str, object]:
    manifest: Optional[Dict[str, object]] = None
    recoverable: Dict[str, List[Tuple[str, Dict[str, object]]]] = {}
    referenced = set()
    object_names = set()
    seen = set()
    restored = 0
    planned = 0
    max_file_bytes = DEFAULT_MAX_FILE_BYTES
    roots: List[str] = []
    targets = set()
    expected_objects: Optional[int] = None
    with tarfile.open(fileobj=reader, mode="r|") as archive:
        for member in archive:
            if member.name in seen:
                raise ValueError("encrypted recovery bundle contains duplicate entries")
            position = len(seen)
            seen.add(member.name)
            if (
                (position == 0 and member.name != "bundle.json")
                or (position == 1 and member.name != "manifest.json")
                or (position >= 2 and not member.name.startswith("objects/"))
            ):
                raise ValueError("encrypted recovery bundle layout is invalid")
            if member.name == "bundle.json":
                metadata = json.loads(_member_bytes(archive, member, 64 * 1024).decode("utf-8"))
                if (
                    not isinstance(metadata, dict)
                    or metadata.get("schema") != FORMAT_VERSION
                    or metadata.get("product") != "RATtler"
                    or not isinstance(metadata.get("objects"), int)
                    or isinstance(metadata.get("objects"), bool)
                    or metadata["objects"] < 0
                ):
                    raise ValueError("encrypted recovery bundle metadata is invalid")
                expected_objects = metadata["objects"]
                continue
            if member.name == "manifest.json":
                if manifest is not None:
                    raise ValueError("encrypted recovery bundle contains duplicate manifests")
                raw_manifest = _member_bytes(archive, member, MAX_MANIFEST_BYTES)
                manifest = json.loads(raw_manifest.decode("utf-8"))
                if (
                    not isinstance(manifest, dict)
                    or manifest.get("schema") != 1
                    or not isinstance(manifest.get("files"), dict)
                    or not isinstance(manifest.get("roots"), list)
                    or not all(isinstance(item, str) for item in manifest.get("roots", []))
                ):
                    raise ValueError("encrypted recovery manifest is invalid")
                manifest_limit = manifest.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)
                if (
                    not isinstance(manifest_limit, int)
                    or isinstance(manifest_limit, bool)
                    or manifest_limit <= 0
                    or manifest_limit > MAX_BUNDLE_FILE_BYTES
                ):
                    raise ValueError("encrypted recovery file limit is invalid")
                max_file_bytes = manifest_limit
                roots = list(manifest["roots"])
                for source, entry in manifest["files"].items():
                    if (
                        not isinstance(source, str)
                        or not os.path.isabs(source)
                        or not isinstance(entry, dict)
                        or not isinstance(entry.get("versions"), list)
                    ):
                        raise ValueError("encrypted recovery manifest is invalid")
                    versions = entry["versions"]
                    for item in versions:
                        digest = item.get("sha256") if isinstance(item, dict) else None
                        size = item.get("size") if isinstance(item, dict) else None
                        if (
                            not _valid_digest(digest)
                            or not isinstance(size, int)
                            or isinstance(size, bool)
                            or size < 0
                            or size > max_file_bytes
                        ):
                            raise ValueError("encrypted recovery manifest is invalid")
                        referenced.add(str(digest))
                    version = _version_for_recovery(versions)
                    if version is not None:
                        digest = str(version["sha256"])
                        recoverable.setdefault(digest, []).append((source, version))
                        planned += 1
                continue
            if not member.name.startswith("objects/") or manifest is None:
                raise ValueError("encrypted recovery bundle layout is invalid")
            digest = member.name[len("objects/"):]
            if not _valid_digest(digest) or "/" in digest or digest not in referenced:
                raise ValueError("encrypted recovery object name is invalid")
            object_names.add(digest)
            payload = _member_bytes(archive, member, max_file_bytes)
            if hashlib.sha256(payload).hexdigest() != digest:
                raise ValueError("encrypted recovery object failed integrity verification")
            if destination is None:
                continue
            for source, version in recoverable.get(digest, []):
                if int(version.get("size", -1)) != len(payload):
                    raise ValueError("encrypted recovery manifest size is invalid")
                target = (destination / _relative_recovery_path(source, roots)).absolute()
                if os.path.commonpath((str(destination), str(target))) != str(destination):
                    raise ValueError("encrypted recovery target escaped destination")
                if str(target) in targets or target.exists() or target.is_symlink():
                    continue
                targets.add(str(target))
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                descriptor = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    with os.fdopen(descriptor, "wb") as output:
                        output.write(payload)
                        output.flush()
                        os.fsync(output.fileno())
                except Exception:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                    raise
                restored += 1
    reader.finish()
    if (
        manifest is None
        or "bundle.json" not in seen
        or expected_objects != len(referenced)
        or object_names != referenced
    ):
        raise ValueError("encrypted recovery bundle is incomplete")
    return {
        "planned_files": planned,
        "restored_files": restored,
        "skipped_files": planned - restored if destination is not None else 0,
    }


def restore_bundle(
    archive: Path,
    destination: Path,
    password: Union[str, bytes],
    *,
    apply: bool = False,
) -> Dict[str, object]:
    """Authenticate an encrypted bundle, then recover copies into a new folder."""
    secret = _password_bytes(password, require_strength=False)
    target = destination.expanduser().absolute()
    if apply and (target.exists() or target.is_symlink()):
        raise ValueError("recovery destination already exists")
    if apply and (
        not target.parent.exists() or not target.parent.is_dir() or target.parent.is_symlink()
    ):
        raise ValueError("recovery destination folder is invalid")
    with _open_regular_bundle(archive) as handle:
        header, salt, nonce, offset = _read_header(handle)
        key = _derive_key(secret, salt)
        ciphertext_size, tag = _verify_stream(handle, key, header, nonce, offset)
        handle.seek(offset)
        decryptor = Cipher(
            algorithms.AES(key), modes.GCM(nonce, tag, min_tag_length=TAG_BYTES),
        ).decryptor()
        decryptor.authenticate_additional_data(CONTEXT_PREFIX + header)
        reader = _DecryptingReader(
            handle, decryptor, ciphertext_size,
        )
        created = False
        try:
            if apply:
                target.mkdir(mode=0o700)
                os.chmod(str(target), 0o700)
                created = True
            counts = _restore_tar(reader, target if apply else None)
        except (InvalidTag, tarfile.TarError, OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            if created:
                shutil.rmtree(str(target), ignore_errors=True)
            if isinstance(error, InvalidTag):
                raise ValueError("recovery password is incorrect or the bundle is damaged") from error
            raise
    return {
        "success": True,
        "applied": apply,
        "source": str(archive.expanduser().absolute()),
        "destination": str(target),
        "encrypted": True,
        "cipher": "AES-256-GCM",
        **counts,
    }

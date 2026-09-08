"""Cold, synthetic-only TLS generation and renewal; never a live CA rollover."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import secrets
import shutil
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


MATERIAL_NAMES = ("ca.crt", "mattermost.crt", "mattermost.key", "hrh-tls.crt", "hrh-tls.key")
RECEIPT_SCHEMA = "restricted-synthetic-clinical-tls-renewal.v1"
RENEWAL_PHASES = frozenset({"renewing_tls", "tls_prepared"})


class TlsError(RuntimeError):
    pass


def _directory(path: Path) -> None:
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise TlsError("TLS material directory is not a normal directory")


def _read(path: Path) -> bytes:
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            raise TlsError("TLS material is not a regular file")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise TlsError("TLS material is not a regular file")
            raw = stream.read(16385)
        if not raw or len(raw) > 16384:
            raise TlsError("TLS material size is invalid")
        return raw
    except OSError as exc:
        raise TlsError("TLS material is unavailable") from exc


def _fsync_directory(path: Path) -> None:
    if os.name == "posix":
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _atomic_write(path: Path, raw: bytes, *, mode: int = 0o600, uid: int | None = None, gid: int | None = None) -> None:
    _directory(path.parent)
    if path.is_symlink() or (path.exists() and not stat.S_ISREG(path.lstat().st_mode)):
        raise TlsError("TLS destination is not a regular file")
    temporary = path.with_name(f".{path.name}.tls-{secrets.token_hex(8)}")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, "wb") as stream:
            if uid is not None and gid is not None:
                os.fchown(stream.fileno(), uid, gid)
            if hasattr(os, "fchmod"):
                os.fchmod(stream.fileno(), mode)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def generate_material(seed: Path, *, now: datetime | None = None) -> None:
    """Same fixed staging names/lifetime; no retained CA signing key."""
    now = now or datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic clinical staging CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(ca_key, hashes.SHA256()))
    material = {"ca.crt": ca.public_bytes(serialization.Encoding.PEM)}
    for host in ("mattermost", "hrh-tls"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        names = [x509.DNSName(host)]
        if host == "mattermost":
            names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
                .issuer_name(ca.subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=30))
                .add_extension(x509.SubjectAlternativeName(names), critical=False)
                .sign(ca_key, hashes.SHA256()))
        material[f"{host}.crt"] = cert.public_bytes(serialization.Encoding.PEM)
        material[f"{host}.key"] = key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    for name, raw in material.items():
        _atomic_write(seed / name, raw)


def _snapshot(seed: Path, *, require_current: bool = True, now: datetime | None = None) -> dict[str, bytes]:
    try:
        _directory(seed)
        material = {name: _read(seed / name) for name in MATERIAL_NAMES}
        ca = x509.load_pem_x509_certificate(material["ca.crt"])
        ca.verify_directly_issued_by(ca)
        if ca.extensions.get_extension_for_class(x509.BasicConstraints).value != x509.BasicConstraints(ca=True, path_length=0):
            raise TlsError("TLS CA constraint is invalid")
        certificates = [ca]
        for host in ("mattermost", "hrh-tls"):
            cert = x509.load_pem_x509_certificate(material[f"{host}.crt"])
            cert.verify_directly_issued_by(ca)
            expected = [x509.DNSName(host)]
            if host == "mattermost":
                expected.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
            if list(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value) != expected:
                raise TlsError("TLS server identity is invalid")
            key = serialization.load_pem_private_key(material[f"{host}.key"], password=None)
            der = lambda public: public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            if der(cert.public_key()) != der(key.public_key()):
                raise TlsError("TLS certificate and private key differ")
            certificates.append(cert)
        instant = now or datetime.now(UTC)
        if require_current and any(not (cert.not_valid_before_utc <= instant < cert.not_valid_after_utc) for cert in certificates):
            raise TlsError("TLS generation is expired or not yet valid")
        return material
    except TlsError:
        raise
    except Exception as exc:
        # Certificate/parser detail and key bytes never cross the CLI boundary.
        raise TlsError("TLS generation is incomplete or invalid") from exc


def _hashes(material: dict[str, bytes]) -> dict[str, str]:
    return {name: hashlib.sha256(raw).hexdigest() for name, raw in material.items()}


def inspect_material(seed: Path, *, require_current: bool = True, now: datetime | None = None) -> dict[str, str]:
    return _hashes(_snapshot(seed, require_current=require_current, now=now))


def publish_host_material(seed: Path, material: dict[str, bytes]) -> None:
    for name in MATERIAL_NAMES:
        _atomic_write(seed / name, material[name])
    if inspect_material(seed) != _hashes(material):
        raise TlsError("TLS host publication did not verify")


def install_generation(seed: Path, expected_manifest: str, mm_tls: Path, hrh_tls: Path, ingress: Path) -> dict:
    """One-shot root helper; caller must fence all TLS readers before invoking."""
    raw_manifest = _read(seed / "generation.json")
    if hashlib.sha256(raw_manifest).hexdigest() != expected_manifest:
        raise TlsError("TLS candidate manifest changed")
    manifest = json.loads(raw_manifest)
    material = _snapshot(seed)
    if manifest.get("material") != _hashes(material):
        raise TlsError("TLS candidate material changed")
    targets = [(mm_tls, "mattermost", 2000, 2000), (hrh_tls, "hrh-tls", 101, 101)]
    writes = []
    for root, host, uid, gid in targets:
        _directory(root)
        writes.extend([(root / "ca.crt", material["ca.crt"], uid, gid, 0o444),
                       (root / "server.crt", material[f"{host}.crt"], uid, gid, 0o444),
                       (root / "server.key", material[f"{host}.key"], uid, gid, 0o440)])
    _directory(ingress)
    writes.append((ingress / "ca.crt", material["ca.crt"], 10007, 20005, 0o444))
    for path, raw, uid, gid, mode in writes:
        if path.is_symlink() or (path.exists() and not stat.S_ISREG(path.lstat().st_mode)):
            raise TlsError("TLS destination is unsafe")
    for path, raw, uid, gid, mode in writes:
        _atomic_write(path, raw, uid=uid, gid=gid, mode=mode)
    for path, raw, uid, gid, mode in writes:
        metadata = path.stat(follow_symlinks=False)
        if _read(path) != raw or (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) != (uid, gid, mode):
            raise TlsError("TLS installed generation did not verify")
    return {"schema": RECEIPT_SCHEMA, "material": _hashes(material)}


def renew(staging, marker: dict, services: tuple[str, ...], *, restoring: bool = False) -> dict:
    """Publish operational state only after the entire cold generation verifies."""
    seed = staging.state_dir / "seed"
    candidate = seed / "tls-next"
    original_phase = marker["lifecycle"]
    if original_phase not in RENEWAL_PHASES:
        inspect_material(seed, require_current=False)  # expiry is repairable, corruption is not
        marker["lifecycle"] = "renewing_tls"
        staging._write_marker(marker)
    if restoring:
        staging._assert_unmounted_backup_volumes(marker["volumes"])
    else:
        stopped = staging.compose("stop", *services, check=False)
        if stopped.returncode:
            raise TlsError("TLS renewal could not stop every workload")
        staging._verify_cold_quiescence({**marker, "lifecycle": "stopped"})
    if marker["lifecycle"] == "renewing_tls":
        if candidate.exists() or candidate.is_symlink():
            _directory(candidate)
            # The bounded generation contains only regular files, never nested trees.
            if any(not stat.S_ISREG(path.lstat().st_mode) for path in candidate.iterdir()):
                raise TlsError("TLS preparation remnant is unsafe")
            shutil.rmtree(candidate)
        candidate.mkdir(mode=0o700)
        _fsync_directory(seed)
        generate_material(candidate)
        manifest = {"schema": RECEIPT_SCHEMA, "project": marker["project"],
                    "state_id": marker["state_id"], "material": inspect_material(candidate)}
        _atomic_write(candidate / "generation.json", (json.dumps(manifest, sort_keys=True) + "\n").encode())
        marker["lifecycle"] = "tls_prepared"
        staging._write_marker(marker)
    manifest_bytes = _read(candidate / "generation.json")
    try:
        manifest = json.loads(manifest_bytes)
    except ValueError as exc:
        raise TlsError("TLS prepared manifest is invalid") from exc
    material = _snapshot(candidate)
    expected = {"schema": RECEIPT_SCHEMA, "project": marker["project"],
                "state_id": marker["state_id"], "material": _hashes(material)}
    if manifest != expected:
        raise TlsError("TLS prepared generation does not bind this staging state")
    try:
        installed = json.loads(staging.control("renew-tls", hashlib.sha256(manifest_bytes).hexdigest()))
    except (ValueError, TypeError) as exc:
        raise TlsError("TLS installation receipt is invalid") from exc
    if installed != {"schema": RECEIPT_SCHEMA, "material": expected["material"]}:
        raise TlsError("TLS installed generation receipt differs")
    staging._assert_no_controller()
    publish_host_material(seed, material)
    marker["lifecycle"] = "recovering" if restoring else "stopped"
    receipt = {**expected, "synthetic_only": True, "lifecycle": marker["lifecycle"],
               "observed_at": datetime.now(UTC).isoformat(),
               "nonclaims": ["not live CA rollover", "not PHI", "not production"]}
    _atomic_write(staging.state_dir / "evidence" / "tls-renewal.json", (json.dumps(receipt, sort_keys=True) + "\n").encode())
    staging._write_marker(marker)  # sole operational publication; no workload has started
    return receipt

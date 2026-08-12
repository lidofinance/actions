"""Execute GnuPG operations and parse its machine-readable output."""

from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .commands import run_command
from .errors import VerificationError


FINGERPRINT = re.compile(r"[0-9A-F]{40}")
EDDSA_ALGORITHM = 22
C_STRING_ESCAPES = {
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "?": "?",
}
BAD_GPG_STATUSES = (
    "BADSIG",
    "ERRSIG",
    "EXPSIG",
    "EXPKEYSIG",
    "REVKEYSIG",
    "NO_PUBKEY",
    "NODATA",
)


@dataclass
class Subkey:
    """A signing-capable or non-signing OpenPGP subkey."""

    fingerprint: str
    algorithm: int | None
    validity: str
    created: int | None
    expires: int | None
    capabilities: str

    @property
    def can_sign(self) -> bool:
        """Report whether GnuPG marks this subkey as signing-capable."""
        return "s" in self.capabilities.lower()

    @property
    def can_encrypt(self) -> bool:
        """Report whether GnuPG marks this subkey as encryption-capable."""
        return "e" in self.capabilities.lower()


@dataclass
class PrimaryKey:
    """An OpenPGP primary key and the subkeys listed beneath it."""

    fingerprint: str
    algorithm: int | None
    validity: str
    created: int | None
    expires: int | None
    capabilities: str
    uids: set[str] = field(default_factory=set)
    subkeys: list[Subkey] = field(default_factory=list)

    @property
    def can_sign(self) -> bool:
        """Report whether GnuPG marks this primary key as signing-capable."""
        return "s" in self.capabilities.lower()

    @property
    def can_encrypt(self) -> bool:
        """Report whether GnuPG marks this primary key as encryption-capable."""
        return "e" in self.capabilities.lower()


def unescape_gpg_colon_field(value: str) -> str:
    """Decode GnuPG's C-style escapes in a colon-listing text field."""
    def replace_escape(match: re.Match[str]) -> str:
        """Decode one hexadecimal or named C-style escape sequence."""
        hexadecimal = match.group(1)
        return chr(int(hexadecimal, 16)) if hexadecimal else C_STRING_ESCAPES[match.group(2)]

    return re.sub(
        r"\\(?:x([0-9A-Fa-f]{2})|([abfnrtv\\'\"?]))",
        replace_escape,
        value,
    )


def parse_gpg_key_listing(source: Path, output: str) -> list[PrimaryKey]:
    """Parse GnuPG's documented --with-colons listing format."""
    keys: list[PrimaryKey] = []
    current: PrimaryKey | None = None
    pending: PrimaryKey | Subkey | None = None

    def finalize_current_primary_key() -> None:
        """Validate and retain the primary key currently being parsed."""
        nonlocal current
        if current is None:
            return
        if not FINGERPRINT.fullmatch(current.fingerprint):
            raise VerificationError(f"{source}: primary key has no valid fingerprint")
        if any(not FINGERPRINT.fullmatch(subkey.fingerprint) for subkey in current.subkeys):
            raise VerificationError(f"{source}: subkey has no valid fingerprint")
        keys.append(current)
        current = None

    for line in output.splitlines():
        fields = (line.split(":") + [""] * 12)[:12]
        record = fields[0]
        if record == "pub":
            finalize_current_primary_key()
            current = PrimaryKey(
                fingerprint="",
                algorithm=int(fields[3] or 0) or None,
                validity=fields[1].lower(),
                created=int(fields[5] or 0) or None,
                expires=int(fields[6] or 0) or None,
                capabilities=fields[11],
            )
            pending = current
        elif record == "sub":
            if current is None:
                raise VerificationError(f"{source}: found a subkey before a primary key")
            subkey = Subkey(
                fingerprint="",
                algorithm=int(fields[3] or 0) or None,
                validity=fields[1].lower(),
                created=int(fields[5] or 0) or None,
                expires=int(fields[6] or 0) or None,
                capabilities=fields[11],
            )
            current.subkeys.append(subkey)
            pending = subkey
        elif record == "fpr" and pending is not None:
            pending.fingerprint = fields[9].upper()
            pending = None
        elif record == "uid" and current is not None:
            current.uids.add(unescape_gpg_colon_field(fields[9]))

    finalize_current_primary_key()
    if not keys:
        raise VerificationError(f"{source}: contains no public OpenPGP primary key")
    return keys


def list_primary_key_fingerprints(gpg_env: dict[str, str]) -> set[str]:
    """List primary-key fingerprints from the supplied isolated GnuPG home."""
    output = run_command(
        "gpg", "--batch", "--no-options", "--with-colons", "--list-keys", env=gpg_env
    ).stdout
    fingerprints: set[str] = set()
    awaiting_fingerprint = False
    for line in output.splitlines():
        fields = line.split(":")
        if fields[0] == "pub":
            awaiting_fingerprint = True
        elif fields[0] == "fpr" and awaiting_fingerprint:
            fingerprints.add(fields[9].upper())
            awaiting_fingerprint = False
    return fingerprints


def import_public_keys(files: list[Path], gpg_home: Path) -> tuple[dict[str, str], set[str]]:
    """Import public key files into an isolated home and return its primary keys."""
    gpg_home.mkdir(mode=0o700)
    gpg_env = os.environ.copy()
    gpg_env["GNUPGHOME"] = str(gpg_home)
    for key_file in files:
        result = run_command(
            "gpg", "--batch", "--no-tty", "--no-options", "--no-autostart",
            "--no-auto-key-retrieve", "--no-auto-key-import", "--import", str(key_file),
            env=gpg_env,
            check=False,
        )
        if result.returncode:
            raise VerificationError(f"cannot import GPG public key {key_file.name}: {result.stderr.strip()}")
    fingerprints = list_primary_key_fingerprints(gpg_env)
    if not fingerprints:
        raise VerificationError("none of the configured public-key files contains a primary GPG key")
    return gpg_env, fingerprints


def find_group_public_key_files(key_root: Path, groups: tuple[str, ...]) -> list[Path]:
    """Find public-key exports for the policy's authorized signer groups."""
    files: list[Path] = []
    for group in groups:
        group_directory = key_root / group
        if not group_directory.is_dir():
            raise VerificationError(f"configured signer group {group!r} has no public-key directory")
        files.extend(source for source in sorted(group_directory.glob("*.asc")) if source.is_file())
    if not files:
        raise VerificationError("the configured signer groups contain no ASCII-armored public keys")
    return files


def find_public_key_files(key_root: Path) -> list[Path]:
    """Find public-key exports stored as <signer-group>/<member>.asc files."""
    files = sorted(
        source
        for group_directory in key_root.iterdir()
        if group_directory.is_dir()
        for source in group_directory.glob("*.asc")
        if source.is_file()
    )
    if not files:
        raise VerificationError(f"{key_root}: contains no ASCII-armored public keys")
    return files


def parse_public_key_files(files: list[Path]) -> dict[Path, list[PrimaryKey]]:
    """Parse public-key exports without using ambient GnuPG state."""
    keys_by_file: dict[Path, list[PrimaryKey]] = {}
    with tempfile.TemporaryDirectory(prefix="gpg-key-policy-") as temporary:
        gpg_home = Path(temporary) / "gnupg"
        gpg_home.mkdir(mode=0o700)
        for source in files:
            contents = source.read_text(encoding="utf-8", errors="replace")
            if "-----BEGIN PGP PRIVATE KEY BLOCK-----" in contents or "-----BEGIN PGP SECRET KEY BLOCK-----" in contents:
                raise VerificationError(f"{source}: must not contain private key material")
            result = run_command(
                "gpg", "--batch", "--no-options", "--no-tty", "--homedir", str(gpg_home),
                "--with-colons", "--show-keys", str(source), check=False,
            )
            if result.returncode:
                raise VerificationError(f"cannot read public key {source}: {result.stderr.strip()}")
            keys_by_file[source] = parse_gpg_key_listing(source, result.stdout)
    return keys_by_file


def extract_valid_signature_primary_fingerprint(status: str) -> str:
    """Extract the primary fingerprint from a successful GnuPG signature status."""
    if any(f"[GNUPG:] {code}" in status for code in BAD_GPG_STATUSES):
        raise VerificationError("invalid, expired, revoked, or unverifiable GPG signature")
    matches = re.findall(r"^\[GNUPG:\] VALIDSIG [0-9A-F]+ .* ([0-9A-F]+)$", status, re.MULTILINE)
    if len(matches) != 1:
        raise VerificationError("GPG did not report exactly one valid signature")
    return matches[0]

"""Execute GnuPG operations and parse its machine-readable output."""

import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .commands import VerificationError, run_command


FINGERPRINT = re.compile(r"[0-9A-F]{40}")
PUBLIC_KEY_BLOCK = re.compile(
    r"-----BEGIN PGP PUBLIC KEY BLOCK-----\r?\n.*?"
    r"\r?\n-----END PGP PUBLIC KEY BLOCK-----",
    re.DOTALL,
)
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
        if record in {"sec", "ssb"}:
            raise VerificationError(f"{source}: must not contain private key material")
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


def find_public_key_files(key_root: Path) -> list[Path]:
    """Find and validate public-key exports stored as <group>/<member>.asc."""
    files = sorted(source for source in key_root.rglob("*.asc") if source.is_file())
    for source in files:
        if len(source.relative_to(key_root).parts) != 2:
            raise VerificationError(f"{source}: public keys must be stored as <signer-group>/<member>.asc")
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
            try:
                contents = source.read_text(encoding="ascii")
            except (OSError, UnicodeDecodeError) as error:
                raise VerificationError(
                    f"{source}: must contain only ASCII-armored public keys"
                ) from error
            if "-----BEGIN PGP PRIVATE KEY BLOCK-----" in contents or "-----BEGIN PGP SECRET KEY BLOCK-----" in contents:
                raise VerificationError(f"{source}: must not contain private key material")
            blocks = PUBLIC_KEY_BLOCK.findall(contents)
            if not blocks or PUBLIC_KEY_BLOCK.sub("", contents).strip():
                raise VerificationError(
                    f"{source}: must contain only ASCII-armored public keys"
                )
            result = run_command(
                "gpg", "--batch", "--no-options", "--no-tty", "--homedir", str(gpg_home),
                "--with-colons", "--show-keys", str(source), check=False,
            )
            if result.returncode:
                raise VerificationError(f"cannot read public key {source}: {result.stderr.strip()}")
            keys_by_file[source] = parse_gpg_key_listing(source, result.stdout)
    return keys_by_file

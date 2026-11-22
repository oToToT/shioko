"""Runs a tlsfuzzer script with its ClientHellos changed to fit shioko.

    python3 tools/tlsfuzzer-profile.py [--keep-groups] NAME SCRIPT [ARGUMENTS...]

tlsfuzzer's TLS 1.3 scripts offer TLS_AES_128_GCM_SHA256 and a secp256r1 key
share, and send no server_name. shioko offers ChaCha20-Poly1305 and X25519
only and needs a server name, so before each ClientHello is built:

- TLS_AES_128_GCM_SHA256 becomes TLS_CHACHA20_POLY1305_SHA256, unless that
  is offered already;
- secp256r1 becomes x25519 in supported_groups and key_share, unless x25519
  is there already, with a new X25519 key share (not with --keep-groups,
  for scripts that take the groups to use as an option);
- rsa_pss_rsae_sha256 becomes ecdsa_secp256r1_sha256 in
  signature_algorithms, unless that is offered already;
- server_name NAME goes first, unless there is one.

A ServerHello or HelloRetryRequest expected to choose TLS_AES_128_GCM_SHA256
is expected to choose TLS_CHACHA20_POLY1305_SHA256 instead, and an
EncryptedExtensions expected to hold certain extensions may also hold the
empty server_name that answers ours.

Everything else, malformed or not, is left as the script made it.
"""

import runpy
import sys

from tlsfuzzer import expect, messages
from tlsfuzzer.helpers import key_share_gen
from tlslite.constants import CipherSuite, ExtensionType, GroupName, \
    SignatureScheme
from tlslite.extensions import ClientKeyShareExtension, SNIExtension, \
    SignatureAlgorithmsExtension, SupportedGroupsExtension

KEEP_GROUPS = sys.argv[1] == "--keep-groups"
if KEEP_GROUPS:
    del sys.argv[1]
NAME = sys.argv[1]
SCRIPT = sys.argv[2]
sys.argv = [SCRIPT] + sys.argv[3:]

AES = CipherSuite.TLS_AES_128_GCM_SHA256
CHACHA = CipherSuite.TLS_CHACHA20_POLY1305_SHA256
P256 = GroupName.secp256r1
X25519 = GroupName.x25519
PSS = SignatureScheme.rsa_pss_rsae_sha256
ECDSA = SignatureScheme.ecdsa_secp256r1_sha256


def adapt_groups(extension):
    if type(extension) is SupportedGroupsExtension and extension.groups \
            and X25519 not in extension.groups:
        groups = [X25519 if g == P256 else g for g in extension.groups]
        return SupportedGroupsExtension().create(groups)
    return extension


def adapt_shares(extension):
    if type(extension) is ClientKeyShareExtension \
            and extension.client_shares is not None \
            and all(s.group != X25519 for s in extension.client_shares):
        shares = [key_share_gen(X25519) if s.group == P256 else s
                  for s in extension.client_shares]
        return ClientKeyShareExtension().create(shares)
    return extension


def adapt_schemes(extension):
    if type(extension) is SignatureAlgorithmsExtension and extension.sigalgs \
            and ECDSA not in extension.sigalgs:
        schemes = [ECDSA if s == PSS else s for s in extension.sigalgs]
        return SignatureAlgorithmsExtension().create(schemes)
    return extension


def adapt(adapter, extension):
    """Adapts an extension, or what a generator of one makes."""
    if callable(extension) and not hasattr(extension, "extType"):
        return lambda state: adapter(extension(state))
    return adapter(extension)


original = messages.ClientHelloGenerator.__init__


def adapted(self, ciphers=None, extensions=None, *args, **kwargs):
    if ciphers and CHACHA not in ciphers:
        ciphers = [CHACHA if c == AES else c for c in ciphers]
    if isinstance(extensions, dict):
        changed = {}
        if ExtensionType.server_name not in extensions:
            changed[ExtensionType.server_name] = \
                SNIExtension().create(bytearray(NAME, "ascii"))
        for kind, extension in extensions.items():
            if kind == ExtensionType.supported_groups and not KEEP_GROUPS:
                extension = adapt(adapt_groups, extension)
            elif kind == ExtensionType.key_share and not KEEP_GROUPS:
                extension = adapt(adapt_shares, extension)
            elif kind == ExtensionType.signature_algorithms:
                extension = adapt(adapt_schemes, extension)
            changed[kind] = extension
        extensions = changed
    original(self, ciphers, extensions, *args, **kwargs)


messages.ClientHelloGenerator.__init__ = adapted


def expecting(cls):
    before = cls.__init__

    def init(self, *args, **kwargs):
        if kwargs.get("cipher") == AES:
            kwargs["cipher"] = CHACHA
        before(self, *args, **kwargs)
    cls.__init__ = init


expecting(expect.ExpectServerHello)
expecting(expect.ExpectHelloRetryRequest)

encrypted_extensions = expect.ExpectEncryptedExtensions.__init__


def expecting_name(self, extensions=None):
    if isinstance(extensions, dict) \
            and ExtensionType.server_name not in extensions:
        extensions = dict(extensions)
        extensions[ExtensionType.server_name] = None
    encrypted_extensions(self, extensions)


expect.ExpectEncryptedExtensions.__init__ = expecting_name
runpy.run_path(SCRIPT, run_name="__main__")

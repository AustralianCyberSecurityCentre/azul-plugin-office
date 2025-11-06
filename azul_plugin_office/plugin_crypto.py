"""Microsoft Office Decryptor.

This plugin providers features about encryption used on office documents
and can attempt to decrypt documents based on configured or supplied
passwords lists.

The plugin is a wrapper around the awesome `msoffcrypto-tool` by nolze.
"""

import traceback
from binascii import hexlify
from enum import Enum
from io import BytesIO
from struct import unpack

import msoffcrypto
from azul_runner import (
    BinaryPlugin,
    Feature,
    FeatureType,
    FeatureValue,
    Job,
    State,
    add_settings,
    cmdline_run,
)

# lib does not support returning crypt info for some formats so need to use their internals
from msoffcrypto.format.doc97 import _parse_header_RC4, _parse_header_RC4CryptoAPI
from msoffcrypto.format.ppt97 import (
    _parseCryptSession10Container,
    _parseCurrentUser,
    _parseUserEditAtom,
    construct_persistobjectdirectory,
)
from msoffcrypto.format.xls97 import _BIFFStream, recordNameNum

KNOWN_TYPES = {
    # Office 2007+ docx, xlsx, etc.
    "agile": "ECMA-376 Agile",
    "standard": "ECMA-376 Standard",
    # Office 2003 added external crypto provider for larger key sizes
    "rc4_cryptoapi": "Office Binary RC4 - CryptoAPI",
    # Office 97 doc, xls - 40bit RC4
    "rc4": "Office Binary RC4",
    # Office 95 and lower - Unsupported
    "xor": "XOR Obfuscation",
}


class Algorithms(Enum):
    """Algorithm Definitions from wincrypt.h."""

    CALG_NO_SIGN = 0x00002000
    CALG_DSS_SIGN = 0x00002200
    CALG_ECDSA = 0x00002203
    CALG_RSA_SIGN = 0x00002400
    CALG_SSL3_MASTER = 0x00004C01
    CALG_SCHANNEL_MASTER_HASH = 0x00004C02
    CALG_SCHANNEL_MAC_KEY = 0x00004C03
    CALG_PCT1_MASTER = 0x00004C04
    CALG_SSL2_MASTER = 0x00004C05
    CALG_TLS1_MASTER = 0x00004C06
    CALG_SCHANNEL_ENC_KEY = 0x00004C07
    CALG_DES = 0x00006601
    CALG_RC2 = 0x00006602
    CALG_3DES = 0x00006603
    CALG_3DES_112 = 0x00006609
    CALG_DESX = 0x00006604
    CALG_AES_128 = 0x0000660E
    CALG_AES_192 = 0x0000660F
    CALG_AES_256 = 0x00006610
    CALG_AES = 0x00006611
    CALG_RC4 = 0x00006801
    CALG_SEAL = 0x00006802
    CALG_RC5 = 0x0000660D
    CALG_SKIPJACK = 0x0000660A
    CALG_TEK = 0x0000660B
    CALG_CYLINK_MEK = 0x0000660C
    CALG_MD2 = 0x00008001
    CALG_MD4 = 0x00008002
    CALG_MD5 = 0x00008003
    CALG_SHA1 = 0x00008004
    CALG_MAC = 0x00008005
    CALG_SSL3_SHAMD5 = 0x00008008
    CALG_HMAC = 0x00008009
    CALG_TLS1PRF = 0x0000800A
    CALG_HASH_REPLACE_OWF = 0x0000800B
    CALG_SHA_256 = 0x0000800C
    CALG_SHA_384 = 0x0000800D
    CALG_SHA_512 = 0x0000800E
    CALG_ECMQV = 0x0000A001
    CALG_HUGHES_MD5 = 0x0000A003
    CALG_RSA_KEYX = 0x0000A400
    CALG_DH_SF = 0x0000AA01
    CALG_DH_EPHEM = 0x0000AA02
    CALG_AGREEDKEY_ANY = 0x0000AA03
    CALG_KEA_KEYX = 0x0000AA04
    CALG_ECDH = 0x0000AA05
    CALG_ECDH_EPHEM = 0x0000AE06

    def simple_name(self):
        """Return the algorithm name in a format that matches strings in ECMA-376 Agile.

        For example CALG_AES_256 => AES-256.
        """
        return self.name[5:].replace("_", "-")


class AzulPluginOfficeDecryptor(BinaryPlugin):
    """Feature and decrypt password-protected office documents."""

    VERSION = "2025.03.19"
    # inherit directly from Plugin so we can process multiple streams together
    MULTI_STREAM_AWARE = True
    SETTINGS = add_settings(
        filter_data_types={
            "content": [
                "document/office/passwordprotected",
                "document/office/word",
                "document/office/excel",
                "document/office/powerpoint",
            ]
        },
        default_passwords=(
            list[str],
            [
                "VelvetSweatshop",  # Hardcoded Excel prompt bypass
                "infected",
                "password",
            ],
        ),
    )
    FEATURES = {
        Feature("office_encrypted_format", desc="Office document type that was encrypted", type=FeatureType.String),
        Feature(
            "office_encryption_provider", desc="Cryptographic provider used for encryption", type=FeatureType.String
        ),
        Feature("office_encryption_method", desc="Office encryption method used", type=FeatureType.String),
        Feature("office_encryption_algorithm", desc="Encryption algorithm used on document", type=FeatureType.String),
        Feature(
            "office_encryption_key_size",
            desc="Size in bits of key used to encrypt the document",
            type=FeatureType.Integer,
        ),
        Feature(
            "office_encryption_hash_algorithm", desc="Hash algorithm used for verification", type=FeatureType.String
        ),
        Feature("office_encryption_salt", desc="Salt value used during encryption", type=FeatureType.String),
        Feature("office_encryption_spin_count", desc="Number of hash iterations to perform", type=FeatureType.Integer),
        Feature("office_encryption_verifier", desc="Encrypted verifier input value", type=FeatureType.String),
        Feature("office_encryption_verifier_hash", desc="Encrypted verifier hash", type=FeatureType.String),
        Feature("office_password", desc="Password used to decrypt the document", type=FeatureType.String),
        Feature("office_secret_key", desc="Intermediate secret key used for decryption", type=FeatureType.String),
        Feature("password", desc="Password used to decrypt the document", type=FeatureType.String),
        Feature("filename", desc="Document filename", type=FeatureType.Filepath),
        Feature("tag", desc="Any informational label about the sample", type=FeatureType.String),
        Feature("corrupted", desc="A corrupted file that could not be analyzed.", type=FeatureType.String),
    }

    def execute(self, job: Job):
        """Process encrypted document."""
        if not job.get_all_data():
            return State(State.Label.OPT_OUT, "OfficeDecryptor requires streams")

        dictionary = []
        data = None
        for s in job.get_all_data():
            if s.file_info.label == "content":
                data = s
            elif s.file_info.label == "password_dictionary":
                dictionary = s.read().decode("utf-8").splitlines()

        if data is None:
            return State(State.Label.ERROR_EXCEPTION, "OfficeDecryptor requires content data")
        try:
            f = msoffcrypto.OfficeFile(data)
        except msoffcrypto.exceptions.FileFormatError:
            self.add_feature_values("corrupted", "Not a valid office file.")
            return State(
                State.Label.COMPLETED_WITH_ERRORS,
                message=f"Corrupted file either it's malicious or there's a bug {traceback.format_exc()}",
            )

        if not f.is_encrypted():
            return State(State.Label.OPT_OUT)

        method = getattr(f, "type", None)
        handler = {
            ("ooxml", "agile"): self.ecma_agile_features,
            ("ooxml", "standard"): self.ecma_standard_features,
            ("doc97", None): self.doc_features,
            ("ppt97", None): self.ppt_features,
            ("xls97", None): self.xls_features,
        }[f.format, method]

        features = handler(f)
        features["office_encrypted_format"] = f.format
        features["tag"] = "encrypted"

        passwords = list(self.cfg.default_passwords)
        passwords.extend(dictionary)
        for p in passwords:
            try:
                o = BytesIO()
                f.load_key(password=p)
                f.decrypt(o)
            # just raises generic Exception when decrypt/validation fails
            except Exception:  # noqa: S112 # nosec B112
                continue

            # successful decrypt
            features["office_password"] = p
            features["password"] = p
            if hasattr(f, "secret_key"):
                features["office_secret_key"] = hexlify(f.secret_key).decode()
            decrypted = o.getvalue()
            child_features = {"tag": "decrypted_doc"}
            feature_filenames = [x for x in job.event.entity.features if x.name == "filename"]
            for fv in feature_filenames:
                f = fv.value
                # if has valid looking file ext, propagate filename to child
                if "." in f and len(f.rsplit(".")[-1]) in (3, 4, 5):
                    child_features["filename"] = f
                    break
            c = self.add_child_with_data(
                {
                    "action": "decrypted",
                    "algorithm": features["office_encryption_algorithm"],
                    "password": p,
                },
                decrypted,
            )
            c.add_many_feature_values(child_features)
            break

        # We still want to report features when failure to guess password so return OK
        self.add_many_feature_values(features)

    def get_algorithm(self, algid):
        """Return the algorithm name by id constant."""
        if algid is None:
            return None
        try:
            return Algorithms(algid).simple_name()
        except ValueError:
            # return the unknown id as a string
            return str(algid)

    def ecma_standard_features(self, office_file):
        """Extract features from ECMA-376 Standard Encrypted OOXML files."""
        header = office_file.info["header"]
        verifier = office_file.info["verifier"]
        return {
            "office_encryption_method": KNOWN_TYPES.get(office_file.type, "Unknown"),
            "office_encryption_provider": header["cspName"].strip("\0"),
            "office_encryption_key_size": header["keySize"],
            "office_encryption_algorithm": self.get_algorithm(header["algId"]),
            "office_encryption_hash_algorithm": self.get_algorithm(header["algIdHash"]),
            "office_encryption_salt": FeatureValue(hexlify(verifier["salt"]).decode(), label="verifier"),
            "office_encryption_verifier_hash": hexlify(verifier["encryptedVerifierHash"]).decode(),
            "office_encryption_verifier": hexlify(verifier["encryptedVerifier"]).decode(),
        }

    def ecma_agile_features(self, office_file):
        """Extract features from ECMA-376 Agile Encrypted OOXML files."""
        info = office_file.info
        # msoffcrypto hardcoded to only support AES CBC Mode it doesn't seem to extract the relevant fields
        return {
            "office_encryption_method": KNOWN_TYPES.get(office_file.type, "Unknown"),
            "office_encryption_algorithm": "AES-%i" % info["passwordKeyBits"],
            "office_encryption_key_size": info["passwordKeyBits"],
            "office_encryption_hash_algorithm": info["passwordHashAlgorithm"],
            "office_encryption_spin_count": info["spinValue"],
            "office_encryption_salt": [
                FeatureValue(hexlify(info["passwordSalt"]).decode(), label="password"),
                FeatureValue(hexlify(info["keyDataSalt"]).decode(), label="keydata"),
            ],
            "office_encryption_verifier": hexlify(info["encryptedVerifierHashInput"]).decode(),
            "office_encryption_verifier_hash": hexlify(info["encryptedVerifierHashValue"]).decode(),
        }

    def doc_features(self, office_file):
        """Extract DOC 97 format RC4 features."""
        # msoffcrypto only sets relevant info when password verifies, so extract ourselves
        fib = office_file.info.fib
        if fib.base.fObfuscation:
            return {
                "office_encryption_method": KNOWN_TYPES["xor"],
                "office_encryption_algorithm": "XOR",
                "office_encryption_verifier": hex(fib.base.IKey),
            }

        hashing = "MD5"
        with office_file.ole.openstream(office_file.info.tablename) as table:
            encryptionHeader = table
            encryptionVersionInfo = table.read(4)
            vMajor, vMinor = unpack("<HH", encryptionVersionInfo)
            if vMajor == 0x0001 and vMinor == 0x0001:
                office_file.type = "rc4"
                info = _parse_header_RC4(encryptionHeader)
            elif vMajor in [0x0002, 0x0003, 0x0004] and vMinor == 0x0002:
                office_file.type = "rc4_cryptoapi"
                info = _parse_header_RC4CryptoAPI(encryptionHeader)
                hashing = "SHA1"
            else:
                raise Exception("Unexpected document encryption version %x, %x" % (vMajor, vMinor))

        return {
            "office_encryption_algorithm": "RC4",
            "office_encryption_method": KNOWN_TYPES[office_file.type],
            "office_encryption_hash_algorithm": hashing,
            "office_encryption_salt": [
                FeatureValue(hexlify(info["salt"]).decode(), label="password"),
            ],
            "office_encryption_key_size": info.get("keySize", 40),
            "office_encryption_verifier": hexlify(info["encryptedVerifier"]).decode(),
            "office_encryption_verifier_hash": hexlify(info["encryptedVerifierHash"]).decode(),
        }

    def xls_features(self, office_file):
        """Extract XLS 97 format RC4 features."""
        office_file.data.workbook.seek(0)
        workbook = _BIFFStream(office_file.data.workbook)
        (num,) = unpack("<H", workbook.data.read(2))
        if num != 2057:
            raise Exception("BOF not found")
        (size,) = unpack("<H", workbook.data.read(2))
        workbook.data.read(size)  # Skip BOF

        num, size = workbook.skip_to(recordNameNum["FilePass"])
        (wEncryptionType,) = unpack("<H", workbook.data.read(2))
        if wEncryptionType == 0x0000:  # XOR obfuscation
            return {
                "office_encryption_method": KNOWN_TYPES["xor"],
                "office_encryption_algorithm": "XOR",
            }
        elif wEncryptionType != 0x0001:  # RC4
            raise Exception("Unknown xls encryption type 0x%0x" % wEncryptionType)

        encryptionInfo = BytesIO(workbook.data.read(size - 2))
        encryptionVersionInfo = encryptionInfo.read(4)

        hashing = "MD5"
        vMajor, vMinor = unpack("<HH", encryptionVersionInfo)
        if vMajor == 0x0001 and vMinor == 0x0001:  # RC4
            office_file.type = "rc4"
            info = _parse_header_RC4(encryptionInfo)
        elif vMajor in [0x0002, 0x0003, 0x0004] and vMinor == 0x0002:  # RC4 CryptoAPI
            office_file.type = "rc4_cryptoapi"
            info = _parse_header_RC4CryptoAPI(encryptionInfo)
            hashing = "SHA1"
        else:
            raise Exception("Unexpected document encryption version %x, %x" % (vMajor, vMinor))

        return {
            "office_encryption_algorithm": "RC4",
            "office_encryption_method": KNOWN_TYPES[office_file.type],
            "office_encryption_hash_algorithm": hashing,
            "office_encryption_salt": [
                FeatureValue(hexlify(info["salt"]).decode(), label="password"),
            ],
            "office_encryption_key_size": info.get("keySize", 40),
            "office_encryption_verifier": hexlify(info["encryptedVerifier"]).decode(),
            "office_encryption_verifier_hash": hexlify(info["encryptedVerifierHash"]).decode(),
        }

    def ppt_features(self, office_file):
        """Extract PPT 97 format RC4 features (PowerPoint only supported RC4 CryptoAPI)."""
        persistobjectdirectory = construct_persistobjectdirectory(office_file.data)
        office_file.data.currentuser.seek(0)
        currentuser = _parseCurrentUser(office_file.data.currentuser)

        office_file.data.powerpointdocument.seek(currentuser.currentuseratom.offsetToCurrentEdit)
        usereditatom = _parseUserEditAtom(office_file.data.powerpointdocument)

        cryptsession10container_offset = persistobjectdirectory[usereditatom.encryptSessionPersistIdRef]
        office_file.data.powerpointdocument.seek(cryptsession10container_offset)
        cryptsession10container = _parseCryptSession10Container(office_file.data.powerpointdocument)

        encryptionInfo = BytesIO(cryptsession10container.data)

        encryptionVersionInfo = encryptionInfo.read(4)
        vMajor, vMinor = unpack("<HH", encryptionVersionInfo)
        if vMajor not in [0x0002, 0x0003, 0x0004] or vMinor != 0x0002:  # RC4 CryptoAPI
            raise Exception("Unexpected document encryption version %x, %x" % (vMajor, vMinor))

        info = _parse_header_RC4CryptoAPI(encryptionInfo)
        office_file.type = "rc4_cryptoapi"
        return {
            "office_encryption_algorithm": "RC4",
            "office_encryption_method": KNOWN_TYPES[office_file.type],
            "office_encryption_hash_algorithm": "SHA1",
            "office_encryption_salt": [
                FeatureValue(hexlify(info["salt"]).decode(), label="password"),
            ],
            "office_encryption_key_size": info.get("keySize", 40),
            "office_encryption_verifier": hexlify(info["encryptedVerifier"]).decode(),
            "office_encryption_verifier_hash": hexlify(info["encryptedVerifierHash"]).decode(),
        }


def main():
    """Run the plugin via command-line."""
    cmdline_run(plugin=AzulPluginOfficeDecryptor)


if __name__ == "__main__":
    main()

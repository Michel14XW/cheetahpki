from .checkCertValidity import checkCertValidity #TODO Renommer les autres fonction en nom_propre ainsi que les fichiers
from .createSelfSignedRootCert import is_valid_email, createSelfSignedRootCert
from .createSignedCert import is_valid_email, createSignedCert
from .getCertInfo import get_serial_number #TODO faire ressortir la hierarchie
from .getCertInfo import get_owner
from .getCertInfo import get_validity_end
from .getCertInfo import get_validity_start
from .exceptions import (
    CertificateError,
    CertificateFileNotFoundError,
    CertificateFileEmptyError,
    CertificateLoadError,
    CertificateSaveError,
    CertificateSigningError,
    InvalidCertificateError,
    CertificateDateError,
    PrivateKeyFileNotFoundError,
    PublicKeyFileNotFoundError,
    PrivateKeyLoadError,
    PublicKeyLoadError,
    InvalidKeySizeError,
    KeyPairGenerationError,
    KeySaveError,
    DirectoryCreationError,
)
from .generateKeyPair import generateKeyPair
from .fingerprint import get_certificate_fingerprint
from .fingerprint import get_public_key_fingerprint
from .createSignedInterCert import createSignedInterCert
from .generateCsr import generateCsr
from .parseCsr import parseCsr

__version__ = "0.0.9"
VERSION = __version__.split(".")

__all__ = (
    'checkCertValidity',
    'is_valid_email',
    'createSelfSignedRootCert',
    'createSignedCert',
    'CertificateError',
    'CertificateFileNotFoundError',
    'CertificateFileEmptyError',
    'CertificateLoadError',
    'CertificateSaveError',
    'CertificateSigningError',
    'InvalidCertificateError',
    'CertificateDateError',
    'PrivateKeyFileNotFoundError',
    'PublicKeyFileNotFoundError',
    'PrivateKeyLoadError',
    'PublicKeyLoadError',
    'InvalidKeySizeError',
    'KeyPairGenerationError',
    'KeySaveError',
    'DirectoryCreationError',
    'generateKeyPair',
    'get_owner',
    'get_serial_number',
    'get_validity_start',
    'get_validity_end',
    'get_certificate_fingerprint',
    'get_public_key_fingerprint',
    'createSignedInterCert',
    'generateCsr',
    'parseCsr',
)

# update version 0.0.9
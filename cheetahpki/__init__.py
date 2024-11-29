from .checkCertValidity import checkCertValidity
from .createSelfSignedRootCert import is_valid_email, createSelfSignedRootCert
from .createSignedCert import is_valid_email, createSignedCert
from .getCertInfo import get_serial_number
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

__version__ = "0.0.5"
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
)

# update version 0.0.4
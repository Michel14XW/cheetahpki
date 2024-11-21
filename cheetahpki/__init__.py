from .checkCertValidity import checkCertValidity
from .createSelfSignedRootCert import is_valid_email, createSelfSignedRootCert
from .createSignedCert import is_valid_email, createSignedCert
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

__version__ = "0.0.2"
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
)

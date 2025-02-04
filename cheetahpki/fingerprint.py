from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key

def getPublicKeyFingerprint(public_key_pem_path:str):
    """
    Calcule l'empreinte SHA-256 d'une clé publique au format PEM.
    
    Args:
        public_key_pem_path (str): Chemin de la Clé publique au format keys/root/root_CA_public_key.pem.
    
    Returns:
        str: Empreinte SHA-256 de la clé publique.
    """
    # Charger la clé publique
    public_key = load_pem_public_key(public_key_pem_path)
    
    # Obtenir la version DER de la clé publique
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Calculer le hachage SHA-256
    digest = hashes.Hash(hashes.SHA256())
    digest.update(public_key_der)
    fingerprint = digest.finalize()
    
    # Retourner l'empreinte en format lisible
    return ":".join(f"{byte:02X}" for byte in fingerprint)

"""
keys/root/root_CA_private_key.pem

# Exemple d'utilisation
with open("keys/root/root_CA_public_key.pem", "rb") as file:
    public_key_pem_path = file.read()

fingerprint = get_public_key_fingerprint(public_key_pem_path)
print(f"Empreinte SHA-256 de la clé publique : {fingerprint}")
"""



def getCertificateFingerprint(certificate_pem_path:str):
    """
    Calcule l'empreinte SHA-256 d'un certificat au format PEM.
    
    Args:
        certificate_pem_path (str): Chemin du Certificat au format certificate/root_ca_certificate.pem.
    
    Returns:
        str: Empreinte SHA-256 du certificat.
    """
    # Charger le certificat
    certificate = x509.load_pem_x509_certificate(certificate_pem_path)
    
    # Calculer l'empreinte SHA-256
    fingerprint = certificate.fingerprint(hashes.SHA256())
    
    # Retourner l'empreinte en format lisible
    return ":".join(f"{byte:02X}" for byte in fingerprint)


"""
keys/root/root_CA_public_key.pem

# Exemple d'utilisation
with open("certificate/root_ca_certificate.pem", "rb") as file:
    certificate_pem_path = file.read()

fingerprint = get_certificate_fingerprint(certificate_pem_path)
print(f"Empreinte SHA-256 du certificat : {fingerprint}")
"""


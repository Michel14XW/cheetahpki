import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import datetime

def createSelfSignedRootCert(pseudo, company, city, region, country_code, email, 
                               valid_days, private_key_path, key_password=None):
    """
    Crée un certificat auto-signé pour une CA root sans champ département.

    Args:
        pseudo (str): Nom commun ou pseudo de la CA root.
        company (str): Compagnie à laquelle appartient la CA root.
        city (str): Ville de résidence de la CA root.
        region (str): Région de la CA root.
        country_code (str): Code pays ISO à deux lettres.
        email (str): Adresse email de contact pour la CA root.
        valid_days (int): Durée de validité du certificat en jours.
        private_key_path (str): Chemin vers la clé privée de la CA root.
        key_password (str, optional): Mot de passe pour déchiffrer la clé privée de la CA root (si nécessaire).
    
    Returns:
        str: Chemin du fichier où le certificat auto-signé est enregistré.
    """

    # Résoudre le chemin complet du fichier de la clé privée
    private_key_path = os.path.abspath(private_key_path)
    
    # Charger la clé privée de la CA root
    with open(private_key_path, "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=key_password.encode() if key_password else None,
            backend=default_backend()
        )

    # Créer les informations du sujet (la CA root elle-même)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_code),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, region),
        x509.NameAttribute(NameOID.LOCALITY_NAME, city),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, company),  # La compagnie sans département
        x509.NameAttribute(NameOID.COMMON_NAME, pseudo),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])

    # Définir la période de validité du certificat
    valid_from = datetime.datetime.utcnow()
    valid_to = valid_from + datetime.timedelta(days=valid_days)

    # Générer un numéro de série unique pour le certificat
    serial_number = x509.random_serial_number()

    # Créer le certificat auto-signé
    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer  # Émetteur identique au sujet (auto-signature)
    ).public_key(
        private_key.public_key()
    ).serial_number(
        serial_number
    ).not_valid_before(
        valid_from
    ).not_valid_after(
        valid_to
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),  # Indique que c'est un certificat CA
        critical=True
    ).sign(
        private_key=private_key,  # Utilise la clé privée de la CA root pour signer le certificat
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    # Enregistrer le certificat dans un fichier dans le dossier "certificate"
    os.makedirs('certificate', exist_ok=True)  # Crée le dossier s'il n'existe pas
    cert_filename = os.path.join('certificate', "root_ca_certificate.pem")
    with open(cert_filename, "wb") as cert_file:
        cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))

    return cert_filename


"""
# Exemple d'utilisation
if __name__ == "__main__":
    pseudo = input("Entrez le nom ou pseudo de la CA root : ")
    company = input("Entrez la compagnie de la CA root : ")
    city = input("Entrez la ville de résidence de la CA root : ")
    region = input("Entrez la région de résidence de la CA root : ")
    country_code = input("Entrez le code pays (2 lettres) : ")
    email = input("Entrez l'email de la CA root : ")
    valid_days = int(input("Entrez la durée de validité du certificat (en jours) : "))

    # Informations pour la CA root
    private_key_path = input("Entrez le chemin vers la clé privée de la CA root : ")
    key_password = input("Entrez le mot de passe de la clé privée de la CA root (laisser vide si aucun) : ") or None

    cert_file = create_self_signed_root_cert(pseudo, company, city, region, country_code, email, valid_days, private_key_path, key_password)
    print(f"Certificat CA root auto-signé enregistré sous: {cert_file}")
"""
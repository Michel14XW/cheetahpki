from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import datetime
import os

def createSignedCert(public_key_path, uid, pseudo, company, department, city, region, country_code, email,
                              valid_days, ca_private_key_path, ca_cert_path, ca_key_password=None):
    """
    Crée un certificat utilisateur et le signe avec la clé privée de la CA intermédiaire.

    Args:
        public_key_path (str): Chemin vers la clé publique de l'utilisateur.
        uid (str): UID unique de l'utilisateur.
        pseudo (str): Pseudo ou nom de l'utilisateur.
        company (str): Compagnie de l'utilisateur.
        department (str): Département de l'utilisateur (lié à la CA intermédiaire).
        city (str): Ville de résidence de l'utilisateur.
        region (str): Région de résidence de l'utilisateur.
        country_code (str): Code pays ISO à deux lettres.
        email (str): Adresse email de l'utilisateur.
        valid_days (int): Durée de validité du certificat en jours.
        ca_private_key_path (str): Chemin vers la clé privée de la CA intermédiaire.
        ca_cert_path (str): Chemin vers le certificat de la CA intermédiaire.
        ca_key_password (str, optional): Mot de passe pour déchiffrer la clé privée de la CA (si nécessaire).
    
    Returns:
        str: Chemin du fichier où le certificat est enregistré.
    """

    # Charger la clé publique de l'utilisateur
    with open(public_key_path, "rb") as public_key_file:
        public_key = serialization.load_pem_public_key(
            public_key_file.read(),
            backend=default_backend()
        )

    # Charger le certificat de la CA intermédiaire
    with open(ca_cert_path, "rb") as ca_cert_file:
        ca_cert = x509.load_pem_x509_certificate(
            ca_cert_file.read(),
            backend=default_backend()
        )

    # Charger la clé privée de la CA intermédiaire
    with open(ca_private_key_path, "rb") as ca_private_key_file:
        ca_private_key = serialization.load_pem_private_key(
            ca_private_key_file.read(),
            password=ca_key_password.encode() if ca_key_password else None,
            backend=default_backend()
        )

    # Créer les informations du sujet (utilisateur)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_code),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, region),
        x509.NameAttribute(NameOID.LOCALITY_NAME, city),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, company),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, department),
        x509.NameAttribute(NameOID.COMMON_NAME, pseudo),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])

    # Définir la période de validité du certificat
    valid_from = datetime.datetime.utcnow()
    valid_to = valid_from + datetime.timedelta(days=valid_days)

    # Générer un numéro de série unique pour le certificat
    serial_number = x509.random_serial_number()

    # Créer le certificat utilisateur
    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject  # Utiliser le sujet de la CA intermédiaire comme émetteur
    ).public_key(
        public_key
    ).serial_number(
        serial_number
    ).not_valid_before(
        valid_from
    ).not_valid_after(
        valid_to
    ).add_extension(
        x509.SubjectAlternativeName([x509.RFC822Name(email)]),
        critical=False
    ).sign(
        private_key=ca_private_key,  # Utiliser la clé privée de la CA pour signer
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    # Enregistrer le certificat dans un fichier dans le dossier "certificate"
    os.makedirs('certificate', exist_ok=True)  # Crée le dossier s'il n'existe pas
    cert_filename = f"certificate/{uid}_certificate.pem"
    with open(cert_filename, "wb") as cert_file:
        cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))
    
    return cert_filename


"""
# Exemple d'utilisation
if __name__ == "__main__":
    public_key_path = input("Entrez le chemin vers la clé publique de l'utilisateur : ")
    uid = input("Entrez l'UID de l'utilisateur : ")
    pseudo = input("Entrez le nom ou pseudo de l'utilisateur : ")
    company = input("Entrez la compagnie de l'utilisateur : ")
    department = input("Entrez le département de l'utilisateur : ")
    city = input("Entrez la ville de résidence de l'utilisateur : ")
    region = input("Entrez la région de résidence de l'utilisateur : ")
    country_code = input("Entrez le code pays (2 lettres) : ")
    email = input("Entrez l'email de l'utilisateur : ")
    valid_days = int(input("Entrez la durée de validité du certificat (en jours) : "))
    
    # Informations pour la CA intermédiaire
    ca_private_key_path = input("Entrez le chemin vers la clé privée de la CA intermédiaire : ")
    ca_cert_path = input("Entrez le chemin vers le certificat de la CA intermédiaire : ")
    ca_key_password = input("Entrez le mot de passe de la clé privée de la CA intermédiaire (laisser vide si aucun) : ") or None
    
    cert_file = create_signed_certificate(public_key_path, uid, pseudo, company, department, city, region, country_code,
                                          email, valid_days, ca_private_key_path, ca_cert_path, ca_key_password)
    print(f"Certificat utilisateur signé enregistré sous: {cert_file}")
"""
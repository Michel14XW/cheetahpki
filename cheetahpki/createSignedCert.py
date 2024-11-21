import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import datetime
import re

from .exceptions import (
    PublicKeyFileNotFoundError,
    PublicKeyLoadError,
    PrivateKeyFileNotFoundError,
    PrivateKeyLoadError,
    CertificateLoadError,
    CertificateSaveError
)

def is_valid_email(email):
    """ Vérifie si l'email a un format valide. """
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def createSignedCert(public_key_path, pseudo, company, department, city, region, country_code, email,
                     valid_days, ca_private_key_path, ca_cert_path, ca_key_password=None,
                     output_folder="certificate", output_filename=None):
    """
    Crée un certificat utilisateur et le signe avec la clé privée de la CA intermédiaire.

    Args:
        public_key_path (str): Chemin vers la clé publique de l'utilisateur.
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
        output_folder (str, optional): Dossier de destination du certificat. ( "\""" le back slash est utilisé comme séparateur) Par défaut "certificate".
        output_filename (str, optional): Nom du fichier de sortie sans extension. Par défaut "<pseudo>_certificate".

    Returns:
        str: Chemin du fichier où le certificat est enregistré.

    Raises:
        PublicKeyFileNotFoundError: Si le fichier de clé publique de l'utilisateur est introuvable.
        PublicKeyLoadError: Si le chargement de la clé publique échoue.
        CertificateLoadError: Si le chargement du certificat de la CA échoue.
        PrivateKeyFileNotFoundError: Si le fichier de clé privée de la CA intermédiaire est introuvable.
        PrivateKeyLoadError: Si le chargement de la clé privée de la CA échoue.
        CertificateSaveError: Si l'enregistrement du certificat échoue.
    """

    # Valider les paramètres d'entrée
    if not pseudo or not company:
        raise ValueError("Les champs 'pseudo' et 'company' sont obligatoires.")
    
    if not is_valid_email(email):
        raise ValueError("Adresse email invalide.")
    
    if valid_days <= 0:
        raise ValueError("La durée de validité doit être positive.")
    
    # Charger la clé publique de l'utilisateur
    try:
        with open(public_key_path, "rb") as public_key_file:
            public_key = serialization.load_pem_public_key(
                public_key_file.read(),
                backend=default_backend()
            )
    except FileNotFoundError:
        raise PublicKeyFileNotFoundError("Le fichier de clé publique de l'utilisateur est introuvable.")
    except Exception as e:
        raise PublicKeyLoadError(f"Erreur lors du chargement de la clé publique: {e}")

    # Charger le certificat de la CA intermédiaire
    try:
        with open(ca_cert_path, "rb") as ca_cert_file:
            ca_cert = x509.load_pem_x509_certificate(
                ca_cert_file.read(),
                backend=default_backend()
            )
    except FileNotFoundError:
        raise CertificateLoadError("Le fichier de certificat de la CA intermédiaire est introuvable.")
    except Exception as e:
        raise CertificateLoadError(f"Erreur lors du chargement du certificat de la CA: {e}")

    # Charger la clé privée de la CA intermédiaire
    try:
        with open(ca_private_key_path, "rb") as ca_private_key_file:
            ca_private_key = serialization.load_pem_private_key(
                ca_private_key_file.read(),
                password=ca_key_password.encode() if ca_key_password else None,
                backend=default_backend()
            )
    except FileNotFoundError:
        raise PrivateKeyFileNotFoundError("Le fichier de clé privée de la CA intermédiaire est introuvable.")
    except Exception as e:
        raise PrivateKeyLoadError(f"Erreur lors du chargement de la clé privée de la CA: {e}")

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
    valid_from = datetime.datetime.now(datetime.UTC)
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

    # Définir le nom et l'emplacement de sauvegarde du certificat
    output_filename = output_filename or f"{pseudo}_certificate.pem"
    output_path = os.path.join(output_folder, output_filename)
    
    # Enregistrer le certificat dans le fichier spécifié
    try:
        os.makedirs(output_folder, exist_ok=True)  # Crée le dossier s'il n'existe pas
        with open(output_path, "wb") as cert_file:
            cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))
    except Exception as e:
        raise CertificateSaveError(f"Erreur lors de l'enregistrement du certificat: {e}")
    
    return output_path



"""
# Exemple d'utilisation
if __name__ == "__main__":
    public_key_path = input("Chemin de la clé publique : ")
    pseudo = input("Nom ou pseudo de l'utilisateur : ")
    company = input("Nom de la compagnie : ")
    department = input("Département : ")
    city = input("Ville : ")
    region = input("Région : ")
    country_code = input("Code pays (2 lettres) : ")
    email = input("Adresse email : ")
    valid_days = int(input("Durée de validité (jours) : "))
    ca_private_key_path = input("Chemin de la clé privée de la CA intermédiaire : ")
    ca_cert_path = input("Chemin du certificat de la CA intermédiaire : ")
    ca_key_password = input("Mot de passe pour la clé privée de la CA (laisser vide si aucun) : ") or None

    cert_file = createSignedCert(
        public_key_path, pseudo, company, department, city, region, country_code, email,
        valid_days, ca_private_key_path, ca_cert_path, ca_key_password
    )
    print(f"Certificat généré et enregistré à : {cert_file}")
"""
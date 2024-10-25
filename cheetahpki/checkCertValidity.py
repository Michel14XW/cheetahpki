from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
import datetime

def checkCertValidity(cert_file):
    """
    Vérifie la validité d'un certificat en fonction de sa date d'expiration.

    Cette fonction charge un certificat au format PEM, puis vérifie s'il est encore valide
    en comparant sa date d'expiration avec la date et l'heure actuelles.

    Args:
        cert_file (str): Le chemin du fichier PEM contenant le certificat.

    Returns:
        int ou None: Renvoie le nombre de jours restants avant l'expiration du certificat si celui-ci est valide.
                     Renvoie None si le certificat est expiré.
    """
    
    # Charger le certificat à partir du fichier PEM
    with open(cert_file, 'rb') as f:
        cert_data = f.read()
    cert = load_pem_x509_certificate(cert_data, default_backend())
    
    # Obtenir la date actuelle et la date d'expiration du certificat
    now = datetime.datetime.utcnow()
    not_after = cert.not_valid_after
    
    # Calculer le temps restant avant l'expiration
    time_remaining = not_after - now
    
    # Retourner le nombre de jours restants ou None si expiré
    return time_remaining.days if time_remaining.total_seconds() > 0 else None


"""
# Exemple d'utilisation
time_left = check_certificate_validity("certificate/test1_certificate.pem")
print(time_left)

"""
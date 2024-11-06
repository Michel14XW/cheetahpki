from cryptography import x509
from cryptography.hazmat.backends import default_backend

def getValidityStart(cert_pem_path):
    """
    Prend en entrée un chemin vers un fichier .pem de certificat et retourne la date de début de validité du certificat.
    
    :param cert_pem_path: Chemin vers le fichier .pem du certificat
    :return: Date de début de validité du certificat (format datetime)
    """
    # Charger le certificat depuis le fichier PEM
    with open(cert_pem_path, 'rb') as cert_file:
        cert_data = cert_file.read()
    
    # Charger le certificat en utilisant la bibliothèque cryptography
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    
    # Extraire la date de début de validité du certificat
    validity_start = cert.not_valid_before_utc
    
    return validity_start



"""
# Exemple d'utilisation
cert_path = "certificate/test1_certificate.pem"
validity_start = getValidityStart(cert_path)
print(f"Le certificat est valide à partir de : {validity_start}")
"""

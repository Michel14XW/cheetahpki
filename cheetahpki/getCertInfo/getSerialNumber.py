from cryptography import x509
from cryptography.hazmat.backends import default_backend

def getSerialNumber(cert_pem_path):
    """
    Prend en entrée un chemin vers un fichier .pem de certificat et retourne le numéro de série du certificat.
    
    :param cert_pem_path: Chemin vers le fichier .pem du certificat
    :return: Le numéro de série du certificat
    """
    # Charger le certificat depuis le fichier PEM
    with open(cert_pem_path, 'rb') as cert_file:
        cert_data = cert_file.read()
    
    # Charger le certificat en utilisant la bibliothèque cryptography
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    
    # Extraire le numéro de série du certificat
    serial_number = cert.serial_number
    
    return serial_number



"""
# Exemple d'utilisation
cert_path = "certificate/test1_certificate.pem"
serial_number = get_certificate_serial_number(cert_path)
print(f"Le numéro de série du certificat est : {serial_number}")
"""
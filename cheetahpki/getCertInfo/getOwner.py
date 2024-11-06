from cryptography import x509
from cryptography.hazmat.backends import default_backend

def getOwner(cert_pem_path):
    """
    Prend en entrée un chemin vers un fichier .pem de certificat et retourne le propriétaire du certificat (CN - Common Name).
    
    :param cert_pem_path: Chemin vers le fichier .pem du certificat
    :return: Le nom du propriétaire du certificat (Common Name)
    """
    # Charger le certificat depuis le fichier PEM
    with open(cert_pem_path, 'rb') as cert_file:
        cert_data = cert_file.read()
    
    # Charger le certificat en utilisant la bibliothèque cryptography
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    
    # Extraire les informations du sujet (le propriétaire)
    subject = cert.subject
    
    # Rechercher le champ "Common Name" (CN) dans le sujet
    owner_name = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    
    return owner_name



"""
# Exemple d'utilisation
cert_path = "certificate/test1_certificate.pem"
owner = getOwner(cert_path)
print(f"Le propriétaire du certificat est : {owner}")
"""
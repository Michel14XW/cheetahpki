import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generateKeyPair(uid, key_size=2048, key_directory="keys", private_key_password=None):
    """
    Génère une paire de clés RSA et les enregistre dans un sous-dossier avec l'UID du propriétaire.
    
    Args:
        uid (str): Identifiant unique pour le propriétaire des clés.
        key_size (int): Taille des clés RSA à générer (par défaut 2048 bits).
        key_directory (str): Nom du sous-dossier où les clés seront enregistrées (par défaut 'keys').
        private_key_password (str, optional): Mot de passe pour chiffrer la clé privée. Si None, pas de chiffrement.
    
    Returns:
        tuple: Chemins des fichiers pour la clé privée et la clé publique.
    """
    
    # Créer le répertoire si nécessaire
    if not os.path.exists(key_directory):
        os.makedirs(key_directory)
        print(f"Répertoire {key_directory} créé avec succès.")

    # Générer la clé privée
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    # Choisir l'algorithme de chiffrement pour la clé privée
    encryption_algorithm = (
        serialization.BestAvailableEncryption(private_key_password.encode()) 
        if private_key_password else serialization.NoEncryption()
    )

    # Sérialiser et enregistrer la clé privée dans le dossier 'keys'
    private_key_filename = os.path.join(key_directory, f"{uid}_private_key.pem")
    with open(private_key_filename, "wb") as private_key_file:
        private_key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption_algorithm
            )
        )

    # Générer la clé publique associée
    public_key = private_key.public_key()

    # Sérialiser et enregistrer la clé publique dans le dossier 'keys'
    public_key_filename = os.path.join(key_directory, f"{uid}_public_key.pem")
    with open(public_key_filename, "wb") as public_key_file:
        public_key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    return private_key_filename, public_key_filename


"""
# Exemple d'utilisation :
if __name__ == "__main__":

    uid = input("Entrez l'UID du propriétaire des clés: ")
    use_password = input("Voulez-vous chiffrer la clé privée avec un mot de passe ? (oui/non): ").strip().lower()

    if use_password == 'oui':
        private_key_password = input("Entrez le mot de passe pour la clé privée: ")
    else:
        private_key_password = None

    private_key_file, public_key_file = generate_key_pair(uid, private_key_password=private_key_password)

    print(f"Clé privée enregistrée sous: {private_key_file}")
    print(f"Clé publique enregistrée sous: {public_key_file}")
"""
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from .exceptions import (KeySaveError, 
                        InvalidKeySizeError, KeyPairGenerationError, 
                        DirectoryCreationError)

def generateKeyPair(uid:str, key_size:int=2048, key_directory:str="tmp/keys", private_key_password:str=None):
    """
    Génère une paire de clés RSA et les enregistre dans un sous-dossier avec l'UID du propriétaire.
    
    Args:
        uid (str): Identifiant unique pour le propriétaire des clés : prenom ou pseudo.
        key_size (int): Taille des clés RSA à générer (par défaut 2048 bits).
        key_directory (str): Chemin où les clés seront enregistrées (par défaut dans le dossier 'tmp/keys').
        private_key_password (str, optional): Mot de passe pour chiffrer la clé privée. Si None, pas de chiffrement.
    
    Returns:
        tuple: Chemins des fichiers pour la clé privée et la clé publique.
    
    Raises:
        DirectoryCreationError: Si le répertoire de destination ne peut pas être créé.
        InvalidKeySizeError: Si la taille de la clé est invalide.
        KeySaveError: Si une erreur survient lors de l'écriture des fichiers.
        KeyPairGenerationError: Si la génération de la paire de clés échoue.
    """
    
    try:
        # Créer le répertoire si nécessaire
        if not os.path.exists(key_directory):
            os.makedirs(key_directory)
            print(f"Répertoire {key_directory} créé avec succès.")
    except OSError as e:
        raise DirectoryCreationError(f"Erreur lors de la création du répertoire {key_directory}: {e}")

    try:
        # Générer la clé privée
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
    except ValueError as e:
        raise InvalidKeySizeError(f"Taille de clé invalide : {key_size}. Erreur : {e}")
    except Exception as e:
        raise KeyPairGenerationError(f"Erreur lors de la génération de la paire de clés: {e}")

    # Vérifier que le mot de passe est valide si fourni
    if private_key_password and not isinstance(private_key_password, str):
        raise ValueError("Le mot de passe doit être une chaîne de caractères valide.")

    # Choisir l'algorithme de chiffrement pour la clé privée
    encryption_algorithm = (
        serialization.BestAvailableEncryption(private_key_password.encode()) 
        if private_key_password else serialization.NoEncryption()
    )

    private_key_filename = os.path.join(key_directory, f"{uid}_private_key.pem")
    try:
        # Sérialiser et enregistrer la clé privée dans le dossier 'keys'
        with open(private_key_filename, "wb") as private_key_file:
            private_key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=encryption_algorithm
                )
            )
    except IOError as e:
        raise KeySaveError(f"Erreur lors de l'enregistrement de la clé privée dans {private_key_filename}: {e}")

    # Générer la clé publique associée
    public_key = private_key.public_key()
    public_key_filename = os.path.join(key_directory, f"{uid}_public_key.pem")

    try:
        # Sérialiser et enregistrer la clé publique dans le dossier 'keys'
        with open(public_key_filename, "wb") as public_key_file:
            public_key_file.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
    except IOError as e:
        raise KeySaveError(f"Erreur lors de l'enregistrement de la clé publique dans {public_key_filename}: {e}")

    return private_key_filename, public_key_filename


"""
# Exemple d'utilisation :
if __name__ == "__main__":

    uid = input("Entrez l'UID du propriétaire des clés: ")
    key_directory = input("Entrez le dossier de destination : ")
    use_password = input("Voulez-vous chiffrer la clé privée avec un mot de passe ? (oui/non): ").strip().lower()

    if use_password == 'oui':
        private_key_password = input("Entrez le mot de passe pour la clé privée: ")
    else:
        private_key_password = None

    private_key_file, public_key_file = generateKeyPair(uid, key_directory=key_directory, private_key_password=private_key_password)

    print(f"Clé privée enregistrée sous: {private_key_file}")
    print(f"Clé publique enregistrée sous: {public_key_file}")
"""
# CheetahPKI

**Version**: 0.0.1  
**Description**: Package pour la génération de paires de clés et de certificats numériques.  

CheetahPKI est un package Python permettant de générer des paires de clés RSA, de créer des certificats auto-signés, des certificats signés par une autorité de certification (CA), et de récupérer des informations sur les certificats.

## Fonctionnalités

- **Génération de paires de clés RSA** : Crée et enregistre des paires de clés avec un identifiant unique.
- **Création de certificats auto-signés** : Génère des certificats pour des autorités racine.
- **Création de certificats signés** : Permet de signer un certificat utilisateur via une clé privée CA.
- **Vérification de validité** : Vérifie la date d'expiration d'un certificat pour confirmer sa validité.
- **Extraction d'informations sur les certificats** : Obtenez des informations telles que le nom du propriétaire, le numéro de série, et les dates de validité.

## Installation

Installez le package via pip (non disponible actuellement sur PyPI) :

```bash
pip install cheetahpki
```

## Utilisation 

**1. Génération d'une paire de clés**
Fichier : generateKeyPair.py
Fonction : generateKeyPair
```bash
from cheetahpki.generateKeyPair import generateKeyPair

# Exemple
private_key_path, public_key_path = generateKeyPair(uid='user123')
```

**2. Création d'un certificat auto-signé**
Fichier : createSelfSignedRootCert.py
Fonction : createSelfSignedRootCert
```bash
from cheetahpki.createSelfSignedRootCert import createSelfSignedRootCert

# Exemple
cert_path = createSelfSignedRootCert(
    pseudo='RootCA',
    company='MyCompany',
    city='Lome',
    country_code='TG',
    valid_days=365,
    private_key_path='path/to/private_key.pem'
)
```

**3. Création d'un certificat signé par la CA**
Fichier : createSignedCert.py
Fonction : createSignedCert
```bash
from cheetahpki.createSignedCert import createSignedCert

# Exemple
cert_path = createSignedCert(
    public_key_path='path/to/public_key.pem',
    uid='user123',
    pseudo='User123',
    company='MyCompany',
    department='IT',
    city='Lome',
    region='Maritime',
    country_code='TG',
    email='user@mycompany.tg',
    valid_days=365,
    ca_private_key_path='path/to/ca_private_key.pem',
    ca_cert_path='path/to/ca_cert.pem'
)

```

**4. Vérification de la validité d'un certificat**
Fichier : checkCertValidity.py
Fonction : checkCertValidity
```bash
from cheetahpki.checkCertValidity import checkCertValidity

# Exemple
days_remaining = checkCertValidity(cert_file='path/to/cert.pem')
```

**5. Extraction d'informations sur le certificat**
Dossier : getCertInfo
**- Obtenir le propriétaire**
Fichier : getOwner.py
```bash
from cheetahpki.getCertInfo.getOwner import getOwner

owner = getOwner(cert_pem_path='path/to/cert.pem')
```

**- Obtenir le numéro de série**
Fichier : getSerialNumber.py
```bash
from cheetahpki.getCertInfo.getSerialNumber import getSerialNumber

serial_number = getSerialNumber(cert_pem_path='path/to/cert.pem')
```

**- Obtenir la date de début de validité**
Fichier : getValidityStart.py
```bash
from cheetahpki.getCertInfo.getValidityStart import getValidityStart

start_date = getValidityStart(cert_pem_path='path/to/cert.pem')
```

**- Obtenir la date de fin de validité**
Fichier : getValidityEnd.py
```bash
from cheetahpki.getCertInfo.getValidityEnd import getValidityEnd

end_date = getValidityEnd(cert_pem_path='path/to/cert.pem')
```

## Arborescence du projet
```bash
cheetahpki/
├── generateKeyPair.py
├── createSelfSignedRootCert.py
├── createSignedCert.py
├── checkCertValidity.py
└── getCertInfo/
    ├── getOwner.py
    ├── getSerialNumber.py
    ├── getValidityEnd.py
    └── getValidityStart.py
```

## Licence
Ce projet est sous licence MIT.

Développé pour simplifier la gestion des certificats et de la cryptographie en Python



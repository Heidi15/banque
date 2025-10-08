# Banque en Ligne [VoltBank]- API Backend

## Description

*VoltBank* : Une application web de gestion bancaire permettant aux utilisateurs de gérer leurs comptes, effectuer des transactions et suivre leur historique financier. Ce projet propose une API REST complète pour une banque en ligne moderne.

## Fonctionnalités principales

### Gestion des utilisateurs
- Inscription et authentification sécurisée
- Connexion avec génération de tokens JWT
- Gestion de profil utilisateur

### Gestion des comptes bancaires
- Création automatique d'un compte principal à l'inscription (100€ offerts)
- Ouverture de comptes secondaires (jusqu'à 5 comptes maximum)
- Consultation du solde et des informations de compte
- Clôture de comptes avec transfert automatique vers le compte principal

### Transactions financières
- Dépôt d'argent (limite de 2000€ par dépôt)
- Virements entre comptes (plafond de 10 000€ par jour et par compte)
- Annulation de transaction (dans les 5 secondes)
- Historique complet des transactions

### Gestion des bénéficiaires
- Ajout de bénéficiaires pour faciliter les virements
- Consultation de la liste des bénéficiaires
- Détails complets (nom, IBAN, date d'ajout)

## Stack technique

- **Framework** : FastAPI
- **Base de données** : SQLite avec SqlModel (ORM)
- **Authentification** : PyJWT (JSON Web Tokens)
- **Validation** : Pydantic
- **Sécurité** : Passlib (hashage bcrypt)

## Installation

1. Cloner le repository
```bash
git clone <https://github.com/Heidi15/banque.git>
cd banque-en-ligne
```

2. Installer les dépendances
```bash
pip install -r requirements.txt
```

3. Lancer l'application
```bash
uvicorn main:app --reload
```

L'API sera accessible sur `http://localhost:8000`

## Documentation

La documentation interactive de l'API est disponible sur :
- Swagger UI : `http://localhost:8000/docs`
- ReDoc : `http://localhost:8000/redoc`

## Authentification

L'API utilise JWT pour l'authentification. Après connexion, vous recevrez un token à inclure dans l'en-tête `Authorization` de vos requêtes :

```
Authorization: Bearer <votre_token>
```

## Règles métier

- Maximum 5 comptes par utilisateur (1 principal + 4 secondaires)
- 100€ offerts à l'ouverture du compte principal
- Limite de dépôt : 1999€ par transaction
- Plafond de virement : 10 000€ par jour et par compte
- Annulation possible dans les 5 secondes suivant une transaction
- Le compte principal ne peut pas être clôturé

## Licence

Projet éducatif - Startup fictive de banque en ligne

## Equipe

Heidi IROUDAYARADJOU / Lea CHEN / Sellia NADE / Félicien BOURY

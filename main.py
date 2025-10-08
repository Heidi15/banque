from fastapi import FastAPI, HTTPException
from sqlmodel import SQLModel, Field, create_engine, Session, select, desc, Relationship
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional, List
import bcrypt

# Modèles de données
class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    hashed_password: str
    email: str
    accounts: List["Account"] = Relationship(back_populates="user")
    beneficiaries: List["Beneficiary"] = Relationship(back_populates="user")

class Account(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    account_number: str = Field(unique=True)
    balance: float = Field(default=0.0)
    is_main: bool = Field(default=False)
    is_closed: bool = Field(default=False)
    user_id: int = Field(foreign_key="user.id")
    created_at: datetime = Field(default_factory=datetime.now)
    user: Optional[User] = Relationship(back_populates="accounts")
    sent_transactions: List["Transaction"] = Relationship(
        back_populates="source_account",
        sa_relationship_kwargs={"foreign_keys": "Transaction.source_account_id"}
    )
    received_transactions: List["Transaction"] = Relationship(
        back_populates="destination_account",
        sa_relationship_kwargs={"foreign_keys": "Transaction.destination_account_id"}
    )

class Transaction(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    amount: float
    transaction_type: str  # "deposit", "transfer", "bonus"
    source_account_id: int | None = Field(default=None, foreign_key="account.id")
    destination_account_id: int | None = Field(default=None, foreign_key="account.id")
    created_at: datetime = Field(default_factory=datetime.now)
    is_cancelled: bool = Field(default=False)
    is_confirmed: bool = Field(default=False)
    description: str = Field(default="")
    source_account: Optional[Account] = Relationship(
        back_populates="sent_transactions",
        sa_relationship_kwargs={"foreign_keys": "[Transaction.source_account_id]"}
    )
    destination_account: Optional[Account] = Relationship(
        back_populates="received_transactions",
        sa_relationship_kwargs={"foreign_keys": "[Transaction.destination_account_id]"}
    )

class Beneficiary(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str
    account_number: str
    user_id: int = Field(foreign_key="user.id")
    added_at: datetime = Field(default_factory=datetime.now)
    user: Optional[User] = Relationship(back_populates="beneficiaries")

# Configuration de la base
DATABASE_URL = "sqlite:///database.db"
engine = create_engine(DATABASE_URL)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Création des tables
def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

# Application FastAPI
app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Bienvenue sur mon API FastAPI!"}

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# Routes API
@app.post("/users/")
def create_user(emailvar: str, passwordvar: str):
    user = User(id=0, email=emailvar, hashed_password=passwordvar)
    with Session(engine) as session:
        existing_user = session.exec(select(User).where(User.email == user.email)).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Email déjà utilisé")
        existing_user2 = session.exec(select(User).order_by(desc(User.id))).first()
        user = User(
            id=existing_user2.id + 1 if existing_user2 else 1,
            email=user.email,
            hashed_password=hacher_mot_de_passe(user.hashed_password).decode('utf-8')
        )

        session.add(user)
        session.commit()
        session.refresh(user)
        return user

@app.get("/users/")
def get_users():
    with Session(engine) as session:
        statement = select(User)
        users = session.exec(statement).all()
        return users

# Hacher un mot de passe
def hacher_mot_de_passe(mot_de_passe: str) -> bytes:
    # Générer un sel et hacher le mot de passe
    sel = bcrypt.gensalt()
    mot_de_passe_hache = bcrypt.hashpw(mot_de_passe.encode('utf-8'), sel)
    return mot_de_passe_hache

# Vérifier un mot de passe
def verifier_mot_de_passe(mot_de_passe: str, mot_de_passe_hache: bytes) -> bool:
    return bcrypt.checkpw(mot_de_passe.encode('utf-8'), mot_de_passe_hache)

# Story 4 - Ouvrir un compte
@app.post("/accounts/")
def create_account(user_id: int):
    """Créer un nouveau compte bancaire pour un utilisateur"""
    with Session(engine) as session:
        # Vérifier que l'utilisateur existe
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
        
        # Vérifier la limite de 5 comptes
        user_accounts = session.exec(
            select(Account).where(Account.user_id == user_id)
        ).all()
        
        if len(user_accounts) >= 5:
            raise HTTPException(status_code=400, detail="Limite de 5 comptes atteinte")
        
        # Générer un numéro de compte unique
        import random
        account_number = f"FR{random.randint(10000000, 99999999)}"
        
        # Créer le compte avec un solde de 0
        new_account = Account(
            account_number=account_number,
            balance=0.0,
            is_main=len(user_accounts) == 0,  # Premier compte = compte principal
            user_id=user_id
        )
        session.add(new_account)
        session.commit()
        session.refresh(new_account)
        return new_account

# Story 6 - Déposer de l'argent
@app.post("/accounts/{account_id}/deposit/")
def deposit_money(account_id: int, amount: float):
    """Déposer de l'argent sur un compte"""
    # Vérifier que le montant est positif
    if amount <= 0:
        raise HTTPException(status_code=400, detail="Le montant doit être positif")
    
    # Vérifier la limite de dépôt (1999€ max)
    if amount >= 2000:
        raise HTTPException(status_code=400, detail="Dépôt limité à 1999€ maximum")
    
    with Session(engine) as session:
        # Récupérer le compte
        account = session.get(Account, account_id)
        if not account:
            raise HTTPException(status_code=404, detail="Compte non trouvé")
        
        # Mettre à jour le solde
        account.balance += amount
        
        # Créer une transaction pour tracer l'opération
        transaction = Transaction(
            amount=amount,
            transaction_type="deposit",
            destination_account_id=account_id,
            description=f"Dépôt de {amount}€"
        )
        session.add(transaction)
        session.commit()
        session.refresh(account)
        
        return {
            "message": "Dépôt effectué avec succès",
            "account": account,
            "transaction": transaction
        }

# Story 7 - Envoyer de l'argent
@app.post("/accounts/{source_account_id}/transfer/")
def transfer_money(
    source_account_id: int,
    destination_account_number: str,
    amount: float
):
    """Transférer de l'argent vers un autre compte"""
    # Vérifier que le montant est positif
    if amount <= 0:
        raise HTTPException(status_code=400, detail="Le montant doit être positif")
    
    with Session(engine) as session:
        # Récupérer le compte source
        source_account = session.get(Account, source_account_id)
        if not source_account:
            raise HTTPException(status_code=404, detail="Compte source non trouvé")
        
        # Récupérer le compte destinataire
        destination_account = session.exec(
            select(Account).where(Account.account_number == destination_account_number)
        ).first()
        if not destination_account:
            raise HTTPException(status_code=404, detail="Compte destinataire non trouvé")
        
        # Vérifier que les comptes sont différents
        if destination_account.id == source_account_id:
            raise HTTPException(status_code=400, detail="Le compte destinataire doit être différent du compte source")
        
        # Vérifier que le compte source a assez d'argent
        if source_account.balance < amount:
            raise HTTPException(status_code=400, detail="Solde insuffisant")
        
        # Vérifier le plafond journalier de 10000€
        today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        today_transfers = session.exec(
            select(Transaction).where(
                Transaction.source_account_id == source_account_id,
                Transaction.transaction_type == "transfer",
                Transaction.created_at >= today_start
            )
        ).all()
        total_today = sum(t.amount for t in today_transfers)
        
        if total_today + amount > 10000:
            raise HTTPException(
                status_code=400,
                detail=f"Plafond journalier de 10000€ dépassé. Déjà utilisé aujourd'hui: {total_today}€"
            )
        
        # Effectuer le transfert
        source_account.balance -= amount
        destination_account.balance += amount
        
        # Créer une transaction pour tracer l'opération
        transaction = Transaction(
            amount=amount,
            transaction_type="transfer",
            source_account_id=source_account_id,
            destination_account_id=destination_account.id,
            description=f"Virement vers {destination_account_number}"
        )
        session.add(transaction)
        session.commit()
        session.refresh(source_account)
        session.refresh(destination_account)
        
        return {
            "message": "Virement effectué avec succès",
            "source_account": source_account,
            "destination_account": destination_account,
            "transaction": transaction
        }

# Story 9 - Voir les comptes
@app.get("/users/{user_id}/accounts/")
def get_user_accounts(user_id: int):
    """Récupérer tous les comptes d'un utilisateur"""
    with Session(engine) as session:
        # Vérifier que l'utilisateur existe
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
        
        # Récupérer les comptes triés par date de création décroissante
        accounts = session.exec(
            select(Account).where(Account.user_id == user_id)
            .order_by(desc(Account.created_at))
        ).all()
        
        # Formater la réponse avec solde et numéro de compte
        result = []
        for account in accounts:
            result.append({
                "id": account.id,
                "account_number": account.account_number,
                "balance": account.balance,
                "is_main": account.is_main,
                "created_at": account.created_at
            })
        
        return result
    
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)    
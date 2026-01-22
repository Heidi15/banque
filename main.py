from fastapi import FastAPI, HTTPException, Depends, Header, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import SQLModel, Field, create_engine, Session, select, desc, Relationship
from passlib.context import CryptContext
from contextlib import asynccontextmanager
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from typing import Optional, List
import bcrypt
import jwt
import os
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

# Configuration JWT
SECRET_KEY = "cle_secret_securisee"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 300

# Constantes
SECONDARY_ACCOUNT_MAX_BALANCE = 50000.0

# Modèles de données
class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    hashed_password: str
    email: str
    first_name: str
    last_name: str
    accounts: List["Account"] = Relationship(back_populates="user")
    beneficiaries: List["Beneficiary"] = Relationship(back_populates="user")
    isclosed: bool

class Account(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    account_number: str = Field(unique=True)
    balance: float = Field(default=0.0)
    is_main: bool = Field(default=False)
    is_closed: bool = Field(default=False)
    user_id: int = Field(foreign_key="user.id")
    # Changer created_at par opened_at
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
    transaction_type: str  # "deposit", "transfer", "auto_transfer"
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
    added_at: datetime | None = Field(default_factory=datetime.now)
    #source_user: User
    user: User = Relationship(back_populates="beneficiaries")
    '''
    name = user_beneficiary.email,
    account_number= destination_account_number,
    user_id= user_beneficiary.id,
    user = user_sourceb
    '''
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class AccountCreate(BaseModel):
    account_name: str = ""
    account_type: str = "Compte courant"  

class CloseAccountRequest(BaseModel):
    password: str      

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str

class EmailChangeRequest(BaseModel):
    new_email: EmailStr    

class TransferRequest(BaseModel):
    destination_account_number: str
    amount: float
    description: str = ""  # Libellé du virement (facultatif)

class BeneficiaryCreate(BaseModel):
    name: str
    account_number: str    

# Configuration de la base
DATABASE_URL = os.environ["DATABASE_URL"]
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Création des tables
def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

# Fonction Cron Job - Transfert automatique des surplus
def transfer_excess_from_secondary_accounts():
    """
    Tâche planifiée qui s'exécute tous les jours pour transférer
    le surplus des comptes secondaires vers les comptes principaux
    """
    print(f"[CRON JOB] Démarrage du transfert automatique des excédents - {datetime.now()}")
    
    with Session(engine) as session:
        # Récupérer tous les comptes secondaires (non principaux et non clôturés)
        secondary_accounts = session.exec(
            select(Account).where(
                Account.is_main == False,
                Account.is_closed == False,
                Account.balance > SECONDARY_ACCOUNT_MAX_BALANCE
            )
        ).all()
        
        transfers_count = 0
        
        for account in secondary_accounts:
            excess_amount = account.balance - SECONDARY_ACCOUNT_MAX_BALANCE
            
            if excess_amount > 0:
                # Trouver le compte principal de l'utilisateur
                main_account = session.exec(
                    select(Account).where(
                        Account.user_id == account.user_id,
                        Account.is_main == True,
                        Account.is_closed == False
                    )
                ).first()
                
                if main_account:
                    # Effectuer le transfert
                    account.balance = SECONDARY_ACCOUNT_MAX_BALANCE
                    main_account.balance += excess_amount
                    
                    # Créer une transaction
                    auto_transaction = Transaction(
                        amount=excess_amount,
                        transaction_type="auto_transfer",
                        source_account_id=account.id,
                        destination_account_id=main_account.id,
                        is_confirmed=True,
                        description=f"Transfert automatique de l'excédent vers le compte principal (plafond 50 000€)"
                    )
                    session.add(auto_transaction)
                    transfers_count += 1
                    
                    print(f"[CRON JOB] Transfert de {excess_amount}€ du compte {account.account_number} vers {main_account.account_number}")
        
        session.commit()
        print(f"[CRON JOB] Terminé - {transfers_count} transfert(s) effectué(s)")

# Config du scheduler
scheduler = BackgroundScheduler()

# Application FastAPI
@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    
    # Démarrer le scheduler
    scheduler.add_job(
        transfer_excess_from_secondary_accounts,
        CronTrigger(hour=23, minute=59),  # Tous les jours à 23h59
        id="transfer_excess_job",
        name="Transfert automatique des excédents vers compte principal",
        replace_existing=True
    )
    scheduler.start()
    print("[SCHEDULER] Tâche planifiée activée - Transfert automatique quotidien à 23h59")
    
    yield
    
    # Arrêter le scheduler
    scheduler.shutdown()
    print("[SCHEDULER] Arrêt du scheduler")
    
app = FastAPI(
    title="FINVO API",
    description="API de la banque en ligne FINVO",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://bank-react-js.vercel.app",
        "https://bank-react-fseeosswb-sellias-projects.vercel.app",
        "http://localhost:3000",  # dev local (React)
        "http://localhost:5173",  # dev local (Vite)
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "Bienvenue sur l'API FINVO!"}

security = HTTPBearer()

# Fonctions utilitaires
def hacher_mot_de_passe(mot_de_passe: str) -> bytes:
    sel = bcrypt.gensalt()
    mot_de_passe_hache = bcrypt.hashpw(mot_de_passe.encode('utf-8'), sel)
    return mot_de_passe_hache

def verifier_mot_de_passe(mot_de_passe: str, mot_de_passe_hache: bytes) -> bool:
    return bcrypt.checkpw(mot_de_passe.encode('utf-8'), mot_de_passe_hache)

# Fonctions JWT
def create_access_token(data: dict):
    to_encode = data.copy()
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Token invalide")

# Fonction pour récupérer l'utilisateur connecté
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = verify_token(token)
    return payload.get("user_id")

# Story 1 - Inscription
@app.post("/users/")
def create_user(user_data: UserCreate):
    with Session(engine) as session:
        existing_user = session.exec(select(User).where(User.email == user_data.email)).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Email déjà utilisé")
        
        existing_user2 = session.exec(select(User).order_by(desc(User.id))).first()
        user = User(
            id=existing_user2.id + 1 if existing_user2 else 1,
            email=user_data.email,
            hashed_password=hacher_mot_de_passe(user_data.password).decode('utf-8'),
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            isclosed=False
        )

        session.add(user)
        session.commit()
        session.refresh(user)

        # Story 11 - Création du compte principal
        import random
        account_number = f"FR{random.randint(10000000, 99999999)}"
        main_account = Account(
            account_number=account_number,
            balance=100.0,
            is_main=True,
            user_id=user.id
        )
        session.add(main_account)
        session.commit()
        session.refresh(main_account)
        
        # Transaction bonus de 100€
        bonus_transaction = Transaction(
            amount=100.0,
            transaction_type="bonus",
            destination_account_id=main_account.id,
            is_confirmed=True,
            description="Bonus d'ouverture de compte principal"
        )
        session.add(bonus_transaction)
        session.commit()
        
        return {
            "user": {
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "isclosed": user.isclosed
            },
            "main_account": {
                "id": main_account.id,
                "account_number": main_account.account_number,
                "balance": main_account.balance,
                "is_main": main_account.is_main
            },
            "message": "100€ offerts !"
        }

# Story 12 - Supprimer un utilisateur
@app.post("/delete_user/")
def delete_user(user_id: int = Depends(get_current_user)):
    with Session(engine) as session:
        user = session.exec(select(User).where(User.id == user_id)).first()
        user.isclosed = True
        session.commit()
        session.refresh(user)
    return "L'utilisateur a été supprimé."

# Clôturer un compte
@app.post("/accounts/{account_id}/close/")
def close_account(account_id: int, data: CloseAccountRequest, user_id: int = Depends(get_current_user)):
    """Clôturer un compte bancaire avec confirmation par mot de passe"""
    with Session(engine) as session:
        # Vérifier le mot de passe de l'utilisateur
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
        
        if not verifier_mot_de_passe(data.password, user.hashed_password.encode('utf-8')):
            raise HTTPException(status_code=401, detail="Mot de passe incorrect")
        
        account = session.get(Account, account_id)
        if not account:
            raise HTTPException(status_code=404, detail="Compte non trouvé")
        
        if account.user_id != user_id:
            raise HTTPException(status_code=403, detail="Accès interdit")
        
        if account.is_main:
            raise HTTPException(status_code=400, detail="Le compte principal ne peut pas être clôturé")
        
        if account.is_closed:
            raise HTTPException(status_code=400, detail="Ce compte est déjà clôturé")
        
        # Transférer le solde vers le compte principal
        main_account = session.exec(
            select(Account).where(
                Account.user_id == user_id,
                Account.is_main == True,
                Account.is_closed == False
            )
        ).first()
        
        if not main_account:
            raise HTTPException(status_code=404, detail="Compte principal non trouvé")
        
        if account.balance > 0:
            main_account.balance += account.balance
            
            # Créer une transaction de transfert
            transfer_transaction = Transaction(
                amount=account.balance,
                transaction_type="transfer",
                source_account_id=account.id,
                destination_account_id=main_account.id,
                is_confirmed=True,
                description=f"Transfert lors de la clôture du compte"
            )
            session.add(transfer_transaction)
            account.balance = 0
        
        account.is_closed = True
        session.commit()
        session.refresh(account)
        
        return {
            "message": "Compte clôturé avec succès",
            "account": account,
            "transferred_to_main": main_account.balance
        }
     
# Story 2 - Connexion
@app.post("/login/")
def login(login_data: LoginRequest):
    with Session(engine) as session:
        user = session.exec(select(User).where(User.email == login_data.email)).first()
        if not user:
            raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")
        
        if not verifier_mot_de_passe(login_data.password, user.hashed_password.encode('utf-8')):
            raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")
        
        if user.isclosed:
            raise HTTPException(status_code=403, detail="Ce compte a été supprimé")
        
        token = create_access_token({"user_id": user.id, "email": user.email})
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name
            }
        }

# Story 3 - Récupération de l'utilisateur connecté
@app.get("/users/me/")
def get_current_user_info(user_id: int = Depends(get_current_user)):
    """Récupérer les informations de l'utilisateur connecté (sans le mdp)"""
    with Session(engine) as session:
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
        
        # Retourner id, email, prénom et nom (pas le mot de passe)
        return {
            "id": user.id,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name
        }

# Story 4 - Ouvrir un compte
@app.post("/accounts/")
def create_account(account_data: AccountCreate, user_id: int = Depends(get_current_user)):
    """Créer un nouveau compte bancaire pour un utilisateur"""
    with Session(engine) as session:
        # Vérifier que l'utilisateur existe
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
        
        # Vérifier la limite de 5 comptes
        user_accounts = session.exec(
            select(Account).where(
                Account.user_id == user_id,
                Account.is_closed == False
            )
        ).all()
        
        if len(user_accounts) >= 5:
            raise HTTPException(status_code=400, detail="Limite de 5 comptes atteinte")

        # Générer un numéro de compte unique        
        import random
        while True:
            account_number = f"FR{random.randint(10000000, 99999999)}"
            existing = session.exec(
                select(Account).where(Account.account_number == account_number)
            ).first()
            if not existing:
                break
        
        # Créer le compte avec un solde de 0
        new_account = Account(
            account_number=account_number,
            balance=0.0,
            is_main=False,  # Les nouveaux comptes ne sont jamais principaux
            user_id=user_id
        )
        
        session.add(new_account)
        session.commit()
        session.refresh(new_account)
        return new_account

# Story 5 - Voir les infos d'un compte
@app.get("/accounts/{account_id}/")
def get_account_info(account_id: int, user_id: int = Depends(get_current_user)):
    """Récupérer les informations d'un compte (si appartient à l'utilisateur)"""
    with Session(engine) as session:
        account = session.get(Account, account_id)
        if not account:
            raise HTTPException(status_code=404, detail="Compte non trouvé")
        
        # Vérifier que le compte appartient à l'utilisateur connecté
        if account.user_id != user_id:
            raise HTTPException(status_code=404, detail="Compte non trouvé")
        
        return {
            "id": account.id,
            "account_number": account.account_number,
            "balance": account.balance,
            "is_main": account.is_main,
            "is_closed": account.is_closed,
            "created_at": account.created_at
        }

# Story 6 - Déposer de l'argent
@app.post("/accounts/{account_id}/deposit/")
def deposit_money(account_id: int, amount: float, user_id: int = Depends(get_current_user)):
    """Déposer de l'argent sur un de ses comptes"""
    if amount <= 0:
        raise HTTPException(status_code=400, detail="Le montant doit être positif")
    
    # Vérifier la limite de dépôt (1999€ max)
    if amount >= 2000:
        raise HTTPException(status_code=400, detail="Dépôt limité à 1999€ maximum")
    
    with Session(engine) as session:
        account = session.get(Account, account_id)
        if not account:
            raise HTTPException(status_code=404, detail="Compte non trouvé")
        
        # Vérifier que le compte appartient à l'utilisateur connecté
        if account.user_id != user_id:
            raise HTTPException(status_code=403, detail="Accès interdit : vous ne pouvez déposer que sur vos propres comptes")
        
        account.balance += amount
        
        # Créer une transaction
        transaction = Transaction(
            amount=amount,
            transaction_type="deposit",
            destination_account_id=account_id,
            description=f"Dépôt de {amount}€"
        )
        session.add(transaction)
        session.commit()
        session.refresh(account)
        
        warning_message = None
        if not account.is_main and account.balance > SECONDARY_ACCOUNT_MAX_BALANCE:
            excess = account.balance - SECONDARY_ACCOUNT_MAX_BALANCE
            warning_message = f"Attention : Le solde de votre compte secondaire dépasse 50 000€. L'excédent de {excess:.2f}€ sera automatiquement transféré vers votre compte principal à la fin de la journée."
        
        response = {
            "message": "Dépôt effectué avec succès",
            "account": account,
            "transaction": transaction
        }
        
        if warning_message:
            response["warning"] = warning_message
        
        return response

# Story 7 - Envoyer de l'argent
@app.post("/accounts/{source_account_id}/transfer/")
def transfer_money(
    source_account_id: int,
    data: TransferRequest,
    user_id: int = Depends(get_current_user)
):
    destination_account_number = data.destination_account_number
    amount = data.amount
    description = data.description  # ✅ Nouvelle ligne

    if amount <= 0:
        raise HTTPException(status_code=400, detail="Le montant doit être positif")
    
    with Session(engine) as session:
        source_account = session.get(Account, source_account_id)
        if not source_account:
            raise HTTPException(status_code=404, detail="Compte source non trouvé")
        
        if source_account.user_id != user_id:
            raise HTTPException(status_code=403, detail="Accès interdit : vous ne pouvez effectuer des virements que depuis vos propres comptes")
        
        destination_account = session.exec(
            select(Account).where(Account.account_number == destination_account_number)
        ).first()
        if not destination_account:
            raise HTTPException(status_code=404, detail="Compte destinataire non trouvé")
        
        if destination_account.id == source_account_id:
            raise HTTPException(status_code=400, detail="Le compte destinataire doit être différent du compte source")
        
        if source_account.balance < amount:
            raise HTTPException(status_code=400, detail="Solde insuffisant")
        
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
        
        source_account.balance -= amount
        destination_account.balance += amount
        
        transaction = Transaction(
            amount=amount,
            transaction_type="transfer",
            source_account_id=source_account_id,
            destination_account_id=destination_account.id,
            description=description if description else f"Virement vers {destination_account_number}"
        )

        # Ajout automatique du bénéficiaire
        existing_beneficiary = session.exec(
            select(Beneficiary).where(
                Beneficiary.user_id == user_id,
                Beneficiary.account_number == destination_account_number
            )
        ).first()
        
        if not existing_beneficiary and destination_account.user_id != user_id:
            destination_user = session.get(User, destination_account.user_id)
            
            new_beneficiary = Beneficiary(
                name=f"{destination_user.first_name} {destination_user.last_name}",
                account_number=destination_account_number,
                user_id=user_id
            )
            session.add(new_beneficiary)
        
        session.add(transaction)
        session.commit()
        session.refresh(source_account)
        session.refresh(destination_account)
        session.refresh(transaction)
        
        return {
            "message": "Virement effectué avec succès",
            "source_account": {
                "id": source_account.id,
                "account_number": source_account.account_number,
                "balance": source_account.balance,
                "user": {
                    "id": source_account.user.id,
                    "first_name": source_account.user.first_name,
                    "last_name": source_account.user.last_name
                }
            },
            "destination_account": {
                "id": destination_account.id,
                "account_number": destination_account.account_number,
                "user": {
                    "id": destination_account.user.id,
                    "first_name": destination_account.user.first_name,
                    "last_name": destination_account.user.last_name
                }
            },
            "transaction": {
                "id": transaction.id,
                "amount": transaction.amount,
                "transaction_type": transaction.transaction_type,
                "source_account_id": transaction.source_account_id,
                "destination_account_id": transaction.destination_account_id,
                "created_at": transaction.created_at.isoformat(),
                "is_cancelled": transaction.is_cancelled,
                "is_confirmed": transaction.is_confirmed,
                "description": transaction.description
            }
        }
    
# Story 8 - Voir les transactions d'un compte
@app.get("/show_all_user_transactions/")
def get_user_transactions(user_id: int = Depends(get_current_user)):
    with Session(engine) as session:
        # Récupérer tous les IDs des comptes de l'utilisateur
        user_account_ids = session.exec(
            select(Account.id).where(Account.user_id == user_id)
        ).all()
        
        if not user_account_ids:
            return []  # L'utilisateur n'a pas de compte
        
        # Récupérer les transactions impliquant ces comptes
        statement = select(Transaction).where(
            (Transaction.destination_account_id.in_(user_account_ids)) | 
            (Transaction.source_account_id.in_(user_account_ids))
        ).order_by(desc(Transaction.created_at))
        transactions = session.exec(statement).all()
        return transactions

# Story 9 - Voir les comptes
@app.get("/users/{user_id}/accounts/")
def get_user_accounts(user_id: int, current_user_id: int = Depends(get_current_user)):
    if user_id != current_user_id:
        raise HTTPException(status_code=403, detail="Accès interdit : vous ne pouvez voir que vos propres comptes")
    
    with Session(engine) as session:
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
        
        accounts = session.exec(
            select(Account).where(Account.user_id == user_id)
            .order_by(desc(Account.created_at))
        ).all()
        
        result = []
        for account in accounts:
            result.append({
                "id": account.id,
                "account_number": account.account_number,
                "balance": account.balance,
                "is_main": account.is_main,
                "is_closed": account.is_closed,    # ✔ AJOUT ESSENTIEL
                "created_at": account.created_at
            })
        
        return result

# Story 10 - Annuler une transaction
@app.post("/transactions/{transaction_id}/cancel/")
def cancel_transaction(transaction_id: int, user_id: int = Depends(get_current_user)):
    print(f"[DEBUG] Tentative d'annulation de la transaction {transaction_id} par l'utilisateur {user_id}")
    
    with Session(engine) as session:
        transaction = session.get(Transaction, transaction_id)

        if not transaction:
            print(f"[DEBUG] Transaction {transaction_id} non trouvée")
            raise HTTPException(status_code=404, detail="Transaction non trouvée")

        print(f"[DEBUG] Transaction trouvée: is_confirmed={transaction.is_confirmed}, is_cancelled={transaction.is_cancelled}")
        
        # Récupérer les IDs des comptes de l'utilisateur
        user_account_ids = session.exec(
            select(Account.id).where(Account.user_id == user_id)
        ).all()
        
        # Vérifier que l'utilisateur est impliqué dans la transaction
        if transaction.source_account_id not in user_account_ids and transaction.destination_account_id not in user_account_ids:
            print(f"[DEBUG] L'utilisateur {user_id} n'est pas autorisé à annuler cette transaction")
            raise HTTPException(status_code=403, detail="Vous n'êtes pas autorisé à annuler cette transaction")

        if transaction.is_confirmed:
            print(f"[DEBUG] Transaction déjà confirmée, impossible d'annuler")
            raise HTTPException(status_code=400, detail="Une transaction confirmée ne peut pas être annulée.")

        if transaction.is_cancelled:
            print(f"[DEBUG] Transaction déjà annulée")
            return {"message": "La transaction a déjà été annulée."}
        
        time_limit = timedelta(seconds=5)
        time_elapsed = datetime.now() - transaction.created_at
        print(f"[DEBUG] Temps écoulé: {time_elapsed.total_seconds()}s / 5s")
        
        if time_elapsed > time_limit:
            print(f"[DEBUG] Délai dépassé")
            raise HTTPException(status_code=400, detail="Le délai de 5 secondes pour annuler cette transaction est dépassé.")
            
        source_account = session.get(Account, transaction.source_account_id)
        destination_account = session.get(Account, transaction.destination_account_id)

        if not source_account or not destination_account:
            print(f"[DEBUG] Comptes non trouvés")
            raise HTTPException(status_code=404, detail="Comptes non trouvés")

        if transaction.transaction_type == "deposit" or transaction.transaction_type == "bonus":
            print(f"[DEBUG] Type de transaction non annulable: {transaction.transaction_type}")
            raise HTTPException(status_code=403, detail="Seules les transactions de virement (transfer) peuvent être annulées par l'utilisateur.")
        
        # IMPORTANT : Sauvegarder les soldes AVANT annulation
        before_transaction_source = source_account.balance
        before_transaction_destination = destination_account.balance
        
        print(f"[DEBUG] AVANT annulation - Source: {before_transaction_source}€, Destination: {before_transaction_destination}€")
        
        # Annuler la transaction : remettre les soldes comme avant
        source_account.balance += transaction.amount
        destination_account.balance -= transaction.amount
        transaction.is_cancelled = True
        
        print(f"[DEBUG] APRÈS annulation - Source: {source_account.balance}€, Destination: {destination_account.balance}€")
        
        # IMPORTANT : Commit les changements
        session.add(source_account)
        session.add(destination_account)
        session.add(transaction)
        session.commit()
        
        # Rafraîchir pour obtenir les valeurs à jour
        session.refresh(source_account)
        session.refresh(destination_account)
        session.refresh(transaction)
        
        print(f"[DEBUG] Transaction annulée avec succès - Nouvelle balance source: {source_account.balance}€")
        
        return {
            "before_transaction_source": before_transaction_source,
            "before_transaction_destination": before_transaction_destination,
            "message": "Transaction annulée avec succès. Les comptes ont été mis à jour.",
            "transaction_id": transaction.id,
            "new_source_balance": source_account.balance,
            "new_destination_balance": destination_account.balance
        }
    
# Story 13 - Voir le détail d'une transaction
@app.get("/show_transaction_details/")
def show_transaction_details(transaction_id: int, user_id: int = Depends(get_current_user)):
    with Session(engine) as session:
        # Récupérer la transaction
        transaction = session.get(Transaction, transaction_id)
        if not transaction:
            raise HTTPException(status_code=404, detail="Transaction non trouvée")
        
        # Récupérer tous les IDs des comptes de l'utilisateur
        user_account_ids = session.exec(
            select(Account.id).where(Account.user_id == user_id)
        ).all()
        
        # Vérifier que l'utilisateur est dans la transaction
        is_authorized = (
            transaction.source_account_id in user_account_ids or 
            transaction.destination_account_id in user_account_ids
        )
        
        if not is_authorized:
            raise HTTPException(
                status_code=403, 
                detail="Vous n'êtes pas autorisé à voir cette transaction"
            )
    
        return transaction

# Story 14 - Ajouter un bénéficiaire
@app.post("/beneficiaries/")
def add_beneficiary(data: BeneficiaryCreate, user_id: int = Depends(get_current_user)):
    name = data.name
    account_number = data.account_number

    if not name.strip():
        raise HTTPException(status_code=400, detail="Le nom du bénéficiaire doit être renseigné")

    with Session(engine) as session:
        destination_account = session.exec(
            select(Account).where(Account.account_number == account_number)
        ).first()
        
        if not destination_account:
            raise HTTPException(status_code=404, detail="Le numéro de compte spécifié pour le bénéficiaire n'existe pas")

        if destination_account.user_id == user_id:
            raise HTTPException(status_code=400, detail="Vous ne pouvez pas vous ajouter vous-même comme bénéficiaire")

        existing_beneficiary = session.exec(
            select(Beneficiary).where(
                Beneficiary.user_id == user_id,
                Beneficiary.account_number == account_number
            )
        ).first()

        if existing_beneficiary:
            raise HTTPException(status_code=400, detail="Ce bénéficiaire est déjà ajouté")

        new_beneficiary = Beneficiary(
            name=name.strip(),
            account_number=account_number,
            user_id=user_id
        )

        session.add(new_beneficiary)
        session.commit()
        session.refresh(new_beneficiary)
        
        return {
            "message": "Bénéficiaire ajouté avec succès",
            "beneficiary": {
                "id": new_beneficiary.id,
                "name": new_beneficiary.name,
                "account_number": new_beneficiary.account_number,
                "added_at": new_beneficiary.added_at
            }
        }

# Story 15 - Voir les bénéficiaires
@app.get("/user_beneficiaries/")
def get_user_beneficiaries(user_id: int = Depends(get_current_user)):
    with Session(engine) as session:
        statement = select(Beneficiary).where(Beneficiary.user_id == user_id)
        beneficiary = session.exec(statement).all()
        return beneficiary
    
# (React JS BONUS) Modifier le mot de passe
@app.put("/users/me/password/")
def change_password(
    password_data: PasswordChangeRequest,
    user_id: int = Depends(get_current_user)
):
    """Modifier le mot de passe de l'utilisateur connecté"""
    with Session(engine) as session:
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
        
        # Vérifier l'ancien mot de passe
        if not verifier_mot_de_passe(password_data.current_password, user.hashed_password.encode('utf-8')):
            raise HTTPException(status_code=401, detail="Mot de passe actuel incorrect")
        
        # Mettre à jour avec le nouveau mot de passe
        user.hashed_password = hacher_mot_de_passe(password_data.new_password).decode('utf-8')
        session.add(user)
        session.commit()
        
        return {
            "message": "Mot de passe modifié avec succès"
        }

# Modifier un bénéficiaire
@app.put("/beneficiaries/{beneficiary_id}/")
def update_beneficiary(
    beneficiary_id: int,
    data: BeneficiaryCreate,
    user_id: int = Depends(get_current_user)
):
    """Modifier un bénéficiaire existant"""
    with Session(engine) as session:
        beneficiary = session.get(Beneficiary, beneficiary_id)
        if not beneficiary:
            raise HTTPException(status_code=404, detail="Bénéficiaire non trouvé")
        
        # Vérifier que le bénéficiaire appartient à l'utilisateur
        if beneficiary.user_id != user_id:
            raise HTTPException(status_code=403, detail="Accès interdit")
        
        # Vérifier que le nouveau numéro de compte existe
        if data.account_number != beneficiary.account_number:
            destination_account = session.exec(
                select(Account).where(Account.account_number == data.account_number)
            ).first()
            
            if not destination_account:
                raise HTTPException(status_code=404, detail="Le numéro de compte spécifié n'existe pas")
            
            if destination_account.user_id == user_id:
                raise HTTPException(status_code=400, detail="Vous ne pouvez pas vous ajouter vous-même comme bénéficiaire")
        
        # Vérifier si un autre bénéficiaire avec le même compte existe déjà
        existing_beneficiary = session.exec(
            select(Beneficiary).where(
                Beneficiary.user_id == user_id,
                Beneficiary.account_number == data.account_number,
                Beneficiary.id != beneficiary_id
            )
        ).first()
        
        if existing_beneficiary:
            raise HTTPException(status_code=400, detail="Ce bénéficiaire est déjà ajouté")
        
        # Mettre à jour le bénéficiaire
        beneficiary.name = data.name.strip()
        beneficiary.account_number = data.account_number
        
        session.add(beneficiary)
        session.commit()
        session.refresh(beneficiary)
        
        return {
            "message": "Bénéficiaire modifié avec succès",
            "beneficiary": {
                "id": beneficiary.id,
                "name": beneficiary.name,
                "account_number": beneficiary.account_number,
                "added_at": beneficiary.added_at
            }
        }

# Supprimer un bénéficiaire
@app.delete("/beneficiaries/{beneficiary_id}/")
def delete_beneficiary(
    beneficiary_id: int,
    user_id: int = Depends(get_current_user)
):
    """Supprimer un bénéficiaire"""
    with Session(engine) as session:
        beneficiary = session.get(Beneficiary, beneficiary_id)
        if not beneficiary:
            raise HTTPException(status_code=404, detail="Bénéficiaire non trouvé")
        
        # Vérifier que le bénéficiaire appartient à l'utilisateur
        if beneficiary.user_id != user_id:
            raise HTTPException(status_code=403, detail="Accès interdit")
        
        session.delete(beneficiary)
        session.commit()
        
        return {
            "message": "Bénéficiaire supprimé avec succès"
        }        

# (React JS BONUS) Modifier l'email
@app.put("/users/me/email/")
def change_email(
    email_data: EmailChangeRequest,
    user_id: int = Depends(get_current_user)
):
    """Modifier l'email de l'utilisateur connecté"""
    with Session(engine) as session:
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
        
        # Vérifier que l'email n'est pas déjà utilisé
        existing_user = session.exec(
            select(User).where(User.email == email_data.new_email, User.id != user_id)
        ).first()
        
        if existing_user:
            raise HTTPException(status_code=400, detail="Cet email est déjà utilisé")
        
        # Mettre à jour l'email
        user.email = email_data.new_email
        session.add(user)
        session.commit()
        
        return {
            "message": "Email modifié avec succès",
            "new_email": user.email
        }

# (React JS BONUS) Dashboard - Statistiques
@app.get("/dashboard/stats/")
def get_dashboard_stats(user_id: int = Depends(get_current_user)):
    """
    Récupérer les statistiques du dashboard pour l'utilisateur connecté
    """
    with Session(engine) as session:
        # Récupérer tous les comptes de l'utilisateur (non clôturés uniquement)
        user_accounts = session.exec(
            select(Account).where(
                Account.user_id == user_id,
                Account.is_closed == False
            )
        ).all()
        
        if not user_accounts:
            return {
                "total_balance": 0,
                "accounts": [],
                "transactions": []
            }
        
        account_ids = [acc.id for acc in user_accounts]
        
        # Calculer le solde total
        total_balance = sum(acc.balance for acc in user_accounts)
        
        # Récupérer toutes les transactions des 12 derniers mois
        twelve_months_ago = datetime.now() - timedelta(days=365)
        
        transactions = session.exec(
            select(Transaction).where(
                (Transaction.destination_account_id.in_(account_ids)) | 
                (Transaction.source_account_id.in_(account_ids)),
                Transaction.created_at >= twelve_months_ago
            ).order_by(desc(Transaction.created_at))  # ✅ Tri par date décroissante
        ).all()
        
        # Formater les transactions pour le front
        formatted_transactions = []
        for t in transactions:
            # Déterminer si c'est une entrée ou une sortie pour l'utilisateur
            is_income = t.destination_account_id in account_ids and t.source_account_id not in account_ids
            is_expense = t.source_account_id in account_ids and t.destination_account_id not in account_ids
            
            # Si c'est un transfert interne, on ne compte pas comme recette/dépense
            is_internal = (
                t.source_account_id in account_ids and 
                t.destination_account_id in account_ids
            )
            
            # ✅ Gestion spéciale pour les dépôts et bonus (toujours des revenus)
            if t.transaction_type in ["deposit", "bonus"]:
                is_income = True
                is_expense = False
                is_internal = False
            
            formatted_transactions.append({
                "id": t.id,
                "amount": t.amount,
                "transaction_type": t.transaction_type,
                "source_account_id": t.source_account_id,
                "destination_account_id": t.destination_account_id,
                "created_at": t.created_at.isoformat(),
                "is_cancelled": t.is_cancelled,
                "is_confirmed": t.is_confirmed,
                "description": t.description,
                "is_income": is_income,
                "is_expense": is_expense,
                "is_internal": is_internal
            })
        
        return {
            "total_balance": total_balance,
            "accounts": [
                {
                    "id": acc.id,
                    "account_number": acc.account_number,
                    "balance": acc.balance,
                    "is_main": acc.is_main
                }
                for acc in user_accounts
            ],
            "transactions": formatted_transactions
        }

# Story BONUS - Gestion du plafond des comptes secondaires
@app.post("/trigger-auto-transfer/")
def trigger_auto_transfer(user_id: int = Depends(get_current_user)):
    """
    Endpoint pour déclencher manuellement le transfert auto des surplus
    (Pour ne pas attendre le Cron Job quotidien)
    """
    transfer_excess_from_secondary_accounts()
    return {
        "message": "Transfert automatique des excédents exécuté avec succès",
        "executed_by_user": user_id,
        "executed_at": datetime.now()
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
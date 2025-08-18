import os
from typing import Optional
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from auth import create_access_token, get_password_hash, verify_password
from sqlmodel import SQLModel, Session, select
from DbManager import engine, get_user_by_id
from models import User, PasswordEntry, Category
from dtos.UserCreate import UserCreate
from passlib.context import CryptContext
import secrets
from contextlib import asynccontextmanager
from encryption import derive_key, encrypt_data, decrypt_data


pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def create_db_and_tables():
    print("Criando tabelas...")
    SQLModel.metadata.create_all(engine)
    print("Tabelas criadas com sucesso!")


def drop_db_and_tables():
    print("Droppando tabelas...")
    SQLModel.metadata.drop_all(engine)
    print("Tabelas droppadas com sucesso!")


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield
    drop_db_and_tables()


app = FastAPI(lifespan=lifespan)


@app.post("/users/")
def create_user(user: UserCreate):
    with Session(engine) as session:
        existing_user = session.exec(select(User).where(User.username == user.username)).first()

        if existing_user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Username already registered")

        encryption_salt = secrets.token_hex(16)

        master_key_hash = get_password_hash(user.master_password)

        new_user = User(
            username=user.username,
            master_key_hash=master_key_hash,
            encryption_salt=encryption_salt
        )

        session.add(new_user)
        session.commit()
        session.refresh(new_user)
        return {"id": new_user.id, "username": new_user.username}


class UserLogin(BaseModel):
    username: str
    master_password: str


@app.post("/login", response_model=dict)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    with Session(engine) as session:
        user: User | None = session.exec(select(User).where(User.username == form_data.username)).first()
        if not user or not verify_password(form_data.password,
                                           user.master_key_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        access_token = create_access_token(data={"sub": str(user.id)})
        return {"access_token": access_token, "token_type": "bearer"}


class PasswordEntryCreate(BaseModel):
    service_name: str
    username: str
    encrypted_password: str
    notes: Optional[str] = None
    user_id: UUID
    category_id: Optional[UUID] = None


@app.post("/password-entries/")
def create_password_entry(password_entry: PasswordEntryCreate):
    with Session(engine) as session:

        user = get_user_by_id(password_entry.user_id)
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        key = derive_key(user.master_key_hash, user.encryption_salt)

        password_entry.encrypted_password = encrypt_data(password_entry.encrypted_password,
                                                         key)

        print("Senha criptografada: ", password_entry.encrypted_password)

        db_password_entry = PasswordEntry(**password_entry.model_dump())

        session.add(db_password_entry)
        session.commit()
        session.refresh(db_password_entry)
        return db_password_entry


@app.get("/password-entries/")
def get_password_entries(user_id: UUID):
    with Session(engine) as session:
        user = get_user_by_id(user_id)
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="User not found")

        password_entries = session.exec(select(PasswordEntry).where(
            PasswordEntry.user_id == user.id)).all()
        return password_entries

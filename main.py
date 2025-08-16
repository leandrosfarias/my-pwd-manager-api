import os
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from auth import create_access_token, get_password_hash, verify_password
from sqlmodel import Field, SQLModel, create_engine, Session, select
from models.User import User
from dtos.UserCreate import UserCreate
from passlib.context import CryptContext
import secrets
from contextlib import asynccontextmanager


pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


class Hero(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    secret_name: str
    age: Optional[int] = None


database_url = os.getenv("DATABASE_URL")
if not database_url:
    raise ValueError("DATABASE_URL environment variable is not set")

engine = create_engine(database_url)


def create_db_and_tables():
    print("Criando tabelas...")
    SQLModel.metadata.create_all(engine)
    print("Tabelas criadas com sucesso!")


def drop_db_and_tables():
    print("Droppando tabelas...")
    SQLModel.metadata.drop_all(engine)
    print("Tabelas droppadas com sucesso!")


def get_all_users():
    with Session(engine) as session:
        statement = select(User)
        results = session.exec(statement)
        users = results.all()
        return users


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

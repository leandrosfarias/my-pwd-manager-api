from sqlmodel import Field, SQLModel, Relationship
from uuid import UUID, uuid4
from typing import List, Optional


class User(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)

    username: str = Field(max_length=255, unique=True, index=True)
    master_key_hash: str
    encryption_salt: str

    password_entries: List["PasswordEntry"] = Relationship(back_populates="user")


class PasswordEntry(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    service_name: str = Field(max_length=255)
    username: str = Field(max_length=255)
    encrypted_password: str
    notes: Optional[str] = Field(default=None, max_length=1000)

    user_id: UUID = Field(foreign_key="user.id")
    category_id: Optional[UUID] = Field(foreign_key="category.id")

    user: "User" = Relationship(back_populates="password_entries")
    category: Optional["Category"] = Relationship(back_populates="password_entries")


class Category(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    name: str = Field(max_length=255)

    password_entries: List["PasswordEntry"] = Relationship(back_populates="category")

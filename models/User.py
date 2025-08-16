from sqlmodel import Field, SQLModel
from uuid import UUID, uuid4


class User(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)

    username: str = Field(max_length=255, unique=True, index=True)
    master_key_hash: str
    encryption_salt: str

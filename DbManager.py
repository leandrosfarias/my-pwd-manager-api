from sqlmodel import select, Session, create_engine
import os
from models import User
from uuid import UUID


database_url = os.getenv("DATABASE_URL")
if not database_url:
    raise ValueError("DATABASE_URL environment variable is not set")

engine = create_engine(database_url)


def get_user_by_id(user_id: UUID) -> User | None:
    with Session(engine) as session:
        return session.exec(select(User).where(User.id == user_id)).first()

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import Session
from sqlalchemy.orm import declarative_base
import os
from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = "postgresql+psycopg2://postgres:yash1009@localhost:5432/Final"


# DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:yash1009@localhost:5432/Password-Manager")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

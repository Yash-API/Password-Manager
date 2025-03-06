from sqlalchemy import Column, Integer, String
from database import Base
from pydantic import BaseModel

class PasswordEntry(Base):
    __tablename__ = "password_entries"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    website = Column(String, index=True)
    hashed_password = Column(String)
    # password = Column(String)
    role = Column(String)

class Token(BaseModel):
    access_token: str
    token_type: str


class UserCreate(BaseModel):
    username: str
    password: str
    website: str
    role: str  # 'admin' or 'user'

class UserLogin(BaseModel):
    username: str
    password: str

class TokenData(BaseModel):
    username: str
    role: str

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String)

from sqlalchemy import Column, Integer, String, ForeignKey, Boolean
from sqlalchemy.orm import relationship, declarative_base
from pydantic import BaseModel, EmailStr, field_validator, validator
from typing import Optional

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    website = Column(String, index=True)
    role = Column(String, default="user")  # "user" or "master"

    # Relationship with PasswordEntry
    password_entries = relationship("PasswordEntry", back_populates="user")

class PasswordEntry(Base):
    __tablename__ = "password_entries"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True)
    website = Column(String, index=True)
    hashed_password = Column(String)

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))  # ForeignKey to User
    user = relationship("User", back_populates="password_entries")  # Relationship

class Website(Base):
    __tablename__ = "websites"

    id = Column(Integer, primary_key=True, index=True)
    website = Column(String, unique=True, index=True)


# Pydantic Schemas for API validation
class Token(BaseModel):
    access_token: str
    token_type: str

# Allowed Email Domains
ALLOWED_EMAIL_DOMAINS = ["gmail.com", "yahoo.com"]

# Pydantic schemas
class UserUpdatePassword(BaseModel):
    old_password: str
    new_password: str

ALLOWED_EMAIL_DOMAINS = {"gmail.com", "yahoo.com", "example.com"} 

class UserCreate(BaseModel):
    email: EmailStr  # Ensures it is a valid email format
    password: str
    website: str
    role: Optional[str] = "user"

    @field_validator("email")
    @classmethod
    def validate_email_domain(cls, value):
        domain = value.split("@")[-1]
        if domain not in ALLOWED_EMAIL_DOMAINS:
            raise ValueError(f"Only emails from {', '.join(ALLOWED_EMAIL_DOMAINS)} are allowed")
        return value

class PasswordImport(BaseModel):
    website: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

    @field_validator("email")
    @classmethod
    def validate_email_domain(cls, value):
        domain = value.split("@")[-1]
        if domain not in ALLOWED_EMAIL_DOMAINS:
            raise ValueError("Only emails from @gmail.com and @yahoo.com are allowed")
        return value

class TokenData(BaseModel):
    email: EmailStr
    role: str

class PasswordEntryCreate(BaseModel):
    website: str
    password: str


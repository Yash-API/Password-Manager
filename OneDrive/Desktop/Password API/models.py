from sqlalchemy import Column, Integer, String
from database import Base

class PasswordEntry(Base):
    __tablename__ = "password_entries"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    website = Column(String, index=True)
    hashed_password = Column(String)

from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from database import Base

class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)

    # Relationship
    password_entries = relationship("PasswordEntry", back_populates="owner")

class PasswordEntry(Base):
    __tablename__ = "password_entries"

    id = Column(Integer, primary_key=True, index=True)
    site_name = Column(String, index=True)
    site_url = Column(String)
    encrypted_password = Column(String)
    user_id = Column(Integer, ForeignKey("users.id"))

    # Relationship
    owner = relationship("User", back_populates="password_entries")

# import asyncio
# from database import engine, Base

# async def recreate_tables():
#     async with engine.begin() as conn:
#         await conn.run_sync(Base.metadata.drop_all)  # Drops existing tables
#         await conn.run_sync(Base.metadata.create_all)  # Recreates tables

# asyncio.run(recreate_tables())

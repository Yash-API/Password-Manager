from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from models import User, PasswordEntry
import jwt
from database import get_db
import hashlib
from datetime import datetime, timedelta
from sqlalchemy.orm import joinedload
from sqlalchemy.orm import selectinload
from database import engine
from models import Base

SECRET_KEY = "5dcad3ae1bf44eab3bdb0fbc7ff23510d5b330e78f8785af38af2376ac3750a3"

app = FastAPI()

async def create_tables():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def create_token(username: str):
    expiration = datetime.utcnow() + timedelta(hours=1)
    payload = {"sub": username, "exp": expiration}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

@app.post("/register/")
async def register(username: str, password: str, db: AsyncSession = Depends(get_db)):
    hashed_pw = hash_password(password)
    user = User(username=username, password=hashed_pw)
    db.add(user)
    await db.commit()
    return {"msg": "User registered successfully"}

@app.post("/login/")
async def login(username: str, password: str, db: AsyncSession = Depends(get_db)):
    stmt = select(User).where(User.username == username)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or user.hashed_password != hash_password(password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token(username)
    return {"token": token}

@app.post("/passwords/")
async def create_password(site_name: str, site_url: str, password: str, user_id: int, db: AsyncSession = Depends(get_db)):
    hashed_pw = hash_password(password)
    new_entry = PasswordEntry(site_name=site_name, site_url=site_url, encrypted_password=hashed_pw, user_id=user_id)
    db.add(new_entry)
    await db.commit()
    return {"msg": "Password saved successfully"}

# @app.get("/passwords/")
# async def get_passwords(user_id: int, db: AsyncSession = Depends(get_db)):
#     stmt = select(PasswordEntry).where(PasswordEntry.user_id == user_id)
#     result = await db.execute(stmt)
#     entries = result.scalars().all()
#     return entries,user_id

@app.get("/passwords/")
async def get_passwords(user_id: int, db: AsyncSession = Depends(get_db)):
    # Fetch user and related password entries
    stmt = (
        select(User)
        .options(selectinload(User.password_entries))  # Correct relationship loading
        .where(User.id == user_id)
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    passwords_data = [
        {
            "site_name": entry.site_name,
            "site_url": entry.site_url,
            "password": entry.encrypted_password,  # Encrypted password
        }
        for entry in user.password_entries
    ]

    return {
        "username": user.username,
        "passwords": passwords_data
    }

@app.patch("/passwords/{password_id}")
async def update_password(password_id: int, new_password: str, db: AsyncSession = Depends(get_db)):
    stmt = select(PasswordEntry).where(PasswordEntry.id == password_id)
    result = await db.execute(stmt)
    entry = result.scalars().first()

    if not entry:
        raise HTTPException(status_code=404, detail="Password entry not found")

    entry.encrypted_password = hash_password(new_password)
    await db.commit()
    return {"msg": "Password updated successfully"}

@app.delete("/passwords/{password_id}")
async def delete_password(password_id: int, db: AsyncSession = Depends(get_db)):
    stmt = select(PasswordEntry).where(PasswordEntry.id == password_id)
    result = await db.execute(stmt)
    entry = result.scalars().first()

    if not entry:
        raise HTTPException(status_code=404, detail="Password entry not found")

    await db.delete(entry)
    await db.commit()
    return {"msg": "Password deleted successfully"}

@app.on_event("startup")
async def on_startup():
    await create_tables()

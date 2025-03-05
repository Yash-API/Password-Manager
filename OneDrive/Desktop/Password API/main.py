from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from models import Base, PasswordEntry
from database import engine, get_db
import hashlib
import jwt
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "c6f00c4c5a7eb6d0613cb1a65444257ac99753f6e5685afec5c15011b2a96f03")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

Base.metadata.create_all(bind=engine)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def hash_password(password: str):
    return hashlib.sha256(password.encode()).hexdigest()

def get_current_user(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Create a new password entry 
@app.post("/passwords/")
def create_password(email: str, website: str, password: str, db: Session = Depends(get_db)):
    hashed_pwd = hash_password(password)
    entry = PasswordEntry(email=email, website=website, hashed_password=hashed_pwd)
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return {"message": "Password saved successfully"}

@app.get("/passwords/")
def get_passwords(db: Session = Depends(get_db)):
    return db.query(PasswordEntry).all()

@app.patch("/passwords/{email}")
def update_password(email: str, new_password: str, db: Session = Depends(get_db)):
    entry = db.query(PasswordEntry).filter(PasswordEntry.email == email).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    entry.hashed_password = hash_password(new_password)
    db.commit()
    return {"message": "Password updated successfully"}

@app.delete("/passwords/{email}")
def delete_password(email: str, db: Session = Depends(get_db)):
    entry = db.query(PasswordEntry).filter(PasswordEntry.email == email).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    db.delete(entry)
    db.commit()
    return {"message": "Entry deleted successfully"}

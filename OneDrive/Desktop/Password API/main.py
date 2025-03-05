from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from models import Base, PasswordEntry, UserLogin, Token
from database import engine, get_db
from typing import Annotated
import hashlib
import jwt
import os
from jwt.exceptions import InvalidTokenError
from dotenv import load_dotenv
from datetime import datetime, timedelta
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm


load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "c6f00c4c5a7eb6d0613cb1a65444257ac99753f6e5685afec5c15011b2a96f03")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

def verify_password(plain_Password,hased_password):
    return pwd_context.verify(plain_Password,hased_password)

def get_password_hash(password):
    return pwd_context.hash(password)

Base.metadata.create_all(bind=engine)

def create_access_token(data: dict,expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def hash_password(password: str):
    return hashlib.sha256(password.encode()).hexdigest()

def get_user(db: Session, email: str):
    return db.query(PasswordEntry).filter(PasswordEntry.email == email).first()

def authenticate_user(db: Session, email: str, password: str):
    user = get_user(db, email)
    if not user:
        return False
    if not hash_password(password) == user.hashed_password:
        return False
    return user

def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception

    user = get_user(db, email)
    if user is None:
        raise credentials_exception
    return user


def get_current_active_user(
    current_user: Annotated[PasswordEntry, Depends(get_current_user)]
):
    return current_user


# Create a new password entry 
@app.post("/register/")
def register(email: str, website: str, password: str, role: str, db: Session = Depends(get_db)):
    existing_user = db.query(PasswordEntry).filter(PasswordEntry.email == email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    hashed_pwd = hash_password(password)
    entry = PasswordEntry(email=email, website=website, hashed_password=hashed_pwd , role=role)
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return {"message": "Password saved successfully"}

@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db),
) -> Token:
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email, "role": user.role}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


# @app.post("/login/")
# def login(email: str, password: str, db: Session = Depends(get_db)):
    
#     if PasswordEntry.role == "user":
#         raise HTTPException(status_code=401, detail="Invalid credentials")
#     else:
#         user = db.query(PasswordEntry).filter(PasswordEntry.email == email).first()
#         if not user or not hash_password(password) == user.hashed_password:
#             raise HTTPException(status_code=401, detail="Invalid credentials")
#     return {"message": "Login successful"}

# @app.get("/passwords/")
# def get_passwords(db: Session = Depends(get_db)):
#     return db.query(PasswordEntry).all()

@app.get("/users/me/")
def read_users_me(current_user: Annotated[PasswordEntry, Depends(get_current_active_user)]):
    return {
        "email": current_user.email,
        "role": current_user.role,
        "website": current_user.website,
    }


@app.get("/users/me/passwords/")
def get_user_passwords(current_user: Annotated[PasswordEntry, Depends(get_current_active_user)], db: Session = Depends(get_db)):
    passwords = db.query(PasswordEntry).filter(PasswordEntry.email == current_user.email).all()
    return passwords


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

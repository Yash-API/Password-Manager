from fastapi import FastAPI, Depends, HTTPException, status, Query, Body
from sqlalchemy.orm import Session
from models import Base, PasswordEntry, UserLogin, Token, User, UserCreate, Website, BaseModel, PasswordImport, UserUpdatePassword
from database import engine, get_db, SessionLocal
from typing import Annotated, List
import hashlib
import jwt
import os
from jwt.exceptions import InvalidTokenError
from dotenv import load_dotenv
from datetime import datetime, timedelta
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import EmailStr
from cryptography.fernet import Fernet
import base64

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    # Generate a proper Fernet key
    SECRET_KEY = base64.urlsafe_b64encode(os.urandom(32)).decode()
    print("Warning: No SECRET_KEY found in .env. Generated a new one. Store it securely!")
    print(f"Generated SECRET_KEY: {SECRET_KEY}")

# Initialize Fernet with the proper key
try:
    fernet = Fernet(SECRET_KEY.encode())
except ValueError:
    # If the existing key is invalid, generate a new one
    SECRET_KEY = base64.urlsafe_b64encode(os.urandom(32)).decode()
    print("Warning: Invalid SECRET_KEY detected. Generated a new one. Store it securely!")
    print(f"Generated SECRET_KEY: {SECRET_KEY}")
    fernet = Fernet(SECRET_KEY.encode())

ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Create all tables in the database
Base.metadata.create_all(bind=engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

MASTER_email = "admin@master.com"
MASTER_PASSWORD = "SuperSecureMasterPassword"
MASTER_ROLE = "master"

# Add this dictionary to store email-password mappings
# WARNING: This is extremely insecure and for demonstration only
PASSWORD_STORE = {}

# Encrypt Password Function
def encrypt_password(hashed_password: str) -> str:
    return fernet.encrypt(hashed_password.encode()).decode()

# Decrypt Password Function
def decrypt_password(encrypted_password: str) -> str:
    return fernet.decrypt(encrypted_password.encode()).decode()

# Completely rewrite the decrypt_password function to look up original passwords
def get_original_password(email: str, hashed_password: str = None) -> str:
    """
    Retrieves the original password for a given email.
    WARNING: This is extremely insecure and for demonstration only.
    """
    if email in PASSWORD_STORE:
        return PASSWORD_STORE[email]
    return f"Password not found (hash: {hashed_password[:8]}...)"

def create_master_user():
    db = SessionLocal()
    master_user = db.query(User).filter(User.email == MASTER_email).first()
    
    if not master_user:
        hashed_pwd = encrypt_password(MASTER_PASSWORD)
        new_master = User(
            email=MASTER_email, 
            password=MASTER_PASSWORD,
            hashed_password=hashed_pwd, 
            role=MASTER_ROLE,
            website="admin"  # Add a default website to avoid null issues
        )
        db.add(new_master)
        db.commit()
        db.refresh(new_master)
        print(f"Master user created successfully with ID: {new_master.id}")
    else:
        print(f"Master user already exists with ID: {master_user.id}")

    db.close()

create_master_user()

def verify_password(plain_Password,hased_password):
    return pwd_context.verify(plain_Password,hased_password)

def get_password_hash(hashed_password):
    return pwd_context.hash(hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")

def get_user(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def authenticate_user(db: Session, email: str, password: str):
    user = get_user(db, email)
    if not user:
        return False
    
    # Simply compare with the stored plain password for demonstration
    # In production, you should use a secure password hashing algorithm
    if user.password != password:
        return False
    return user

def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception

    user = get_user(db, email)
    if user is None:
        raise credentials_exception
    return user

def get_current_admin(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.role != "master":
        raise HTTPException(status_code=403, detail="Access denied! Admin only.")
    return current_user

def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    return current_user

@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db)
):
    # Debug print to see what credentials are being used
    print(f"Login attempt: {form_data.username}")
    
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Print success message for debugging
    print(f"Login successful for: {user.email} with role: {user.role}")
    
    # Generate token with role information
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


# # Create a new password entry 
@app.post("/register/")
def register(email: str, password: str, website: str, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already exists")
    
    # Use the password for encryption, not a parameter named hashed_password
    hashed_pwd = encrypt_password(password)
    entry = User(
        email=email, 
        website=website, 
        password=password,  # Store the actual password 
        hashed_password=hashed_pwd,  # Store the encrypted password
        role="user"  # Default role
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    
    return {"message": "Registration successful"}

@app.put("/update-password/")
def update_password(
    email: str,
    new_password: str, 
    current_admin: User = Depends(get_current_admin), 
    db: Session = Depends(get_db)
):
    # import pdb; pdb.set_trace()
    # Fetch user details from the database
    user = db.query(User).filter(User.email == email).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Hash the new password
    hashed_password = encrypt_password(new_password)

    # Update the password in the database
    user.hashed_password = hashed_password
    db.commit()
    db.refresh(user)

    return {"message": "Password updated successfully"}
    
@app.post("/admin/create-master/")
def create_master_user_api(email: str, password: str, db: Session = Depends(get_db), admin: PasswordEntry = Depends(get_current_admin)):
    # Check if user already exists
    existing_user = db.query(PasswordEntry).filter(PasswordEntry.email == email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Admin user already exists")

    # Hash the password
    hashed_password = encrypt_password(password)

    # Create a new master admin user
    new_master = PasswordEntry(email=email, hashed_password=hashed_password, role="master")

    db.add(new_master)
    db.commit()
    db.refresh(new_master)

    return {"message": "Master admin created successfully"}


@app.post("/admin/")
def add_user(
    email: str, 
    website: str, 
    hashed_password: str, 
    role: str, 
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    existing_user = db.query(PasswordEntry).filter(PasswordEntry.email == email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    hashed_pwd = encrypt_password(hashed_password)
    new_user = PasswordEntry(email=email, website=website, password=hashed_password, role=role)
    db.add(new_user)
    db.commit()
    return {"message": "User added successfully"}

@app.delete("/admin/delete-user/{email}")
def delete_user(
    email: str, 
    db: Session = Depends(get_db), 
    admin: User = Depends(get_current_admin)
):
    user = db.query(PasswordEntry).filter(PasswordEntry.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    db.delete(user)
    db.commit()
    return {"message": "User deleted successfully"}

@app.post("/add-websites-passwords/")
def add_website_password(
    website: str = Query(..., description="Website name"),
    hashed_password: str = Query(..., description="Password for the website"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Allows a logged-in user to add a single website with a password.
    """

    if not website or not hashed_password:
        raise HTTPException(status_code=400, detail="Website and password are required.")

    # Check if the website already exists for this user
    existing_entry = db.query(PasswordEntry).filter(
        PasswordEntry.user_id == current_user.id,
        PasswordEntry.website == website
    ).first()

    if existing_entry:
        raise HTTPException(status_code=400, detail="Website already exists for your account.")

    # Store the original password in our insecure dictionary
    PASSWORD_STORE[current_user.email] = hashed_password
    
    # Hash the password
    hashed_pwd = encrypt_password(hashed_password)

    # Create new entry linked to the current user
    new_entry = PasswordEntry(
        email=current_user.email, 
        website=website, 
        password=hashed_password,  # Store the actual password
        hashed_password=hashed_pwd,
        user_id=current_user.id
    )
    
    db.add(new_entry)
    db.commit()
    db.refresh(new_entry)

    return {
        "message": "Website password added successfully!", 
        "website": website,
        "success": True
    }

@app.get("/fetch-all-data/")
def fetch_all_data(
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    """
    Fetch all users and all website-password entries.
    Accessible only by admins.
    """
    users = db.query(User).all()
    users_data = [
        {
            "email": user.email,
            "role": user.role,
            "website": user.website,
            "password": decrypt_password(user.hashed_password)  # Decrypt password
        } 
        for user in users
    ]

    website_passwords = db.query(PasswordEntry).all()
    website_password_data = [
        {
            "email": entry.email, 
            "website": entry.website, 
            "password": decrypt_password(entry.hashed_password)  # Decrypt password
        }
        for entry in website_passwords
    ]

    return {
        "users": users_data,
        "website_password_entries": website_password_data
    }

@app.get("/get-password/{website}")
async def get_password(website: str, db: Session = Depends(get_db)):
    entry = db.query(PasswordEntry).filter(PasswordEntry.website == website).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Password not found")
    original_password = decrypt_password(entry.hashed_password)
    return {"website": website, "password": original_password}
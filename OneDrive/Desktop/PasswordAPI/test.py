from fastapi import FastAPI, Depends, HTTPException, status, Query, Body
from sqlalchemy.orm import Session
from models import Base, PasswordEntry, UserLogin, Token, User, UserCreate, Website, BaseModel, PasswordImport
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
import base64

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "c6f00c4c5a7eb6d0613cb1a65444257ac99753f6e5685afec5c15011b2a96f03")
ALGORITHM = "HS256"
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

def hash_password(password: str):
    return hashlib.sha256(password.encode()).hexdigest()

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
        hashed_pwd = hash_password(MASTER_PASSWORD)
        new_master = User(email=MASTER_email, hashed_password=hashed_pwd, role=MASTER_ROLE)
        db.add(new_master)
        db.commit()
        db.refresh(new_master)
        print("Master user created successfully!")

    db.close()

create_master_user()

def verify_password(plain_Password,hased_password):
    return pwd_context.verify(plain_Password,hased_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

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

# Create a new password entry 
@app.post("/register/")
def register(
    email: EmailStr = Query(..., description="email"), 
    password: str = Query(..., description="password"),
    website: str = Query(..., description="website"),
    db: Session = Depends(get_db)
):
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already exists")
    
    # Store the original password in our insecure dictionary
    PASSWORD_STORE[email] = password
    
    hashed_pwd = hash_password(password)
    entry = User(email=email, hashed_password=hashed_pwd, role="user", website=website)
    
    db.add(entry)
    db.commit()
    db.refresh(entry)
    
    return {"message": "Registration successful"}

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
    
    # Generate token with role information
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email, "role": user.role}, expires_delta=access_token_expires
    )
    
    return Token(access_token=access_token, token_type="bearer")

@app.put("/update-password/")
def update_password(
    email: str,
    new_password: str, 
    current_admin: PasswordEntry = Depends(get_current_admin), 
    db: Session = Depends(get_db)
):
    import pdb; pdb.set_trace()
    # Fetch user details from the database
    user = db.query(PasswordEntry).filter(PasswordEntry.email == email).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Hash the new password
    hashed_password = hash_password(new_password)

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
    hashed_password = hash_password(password)

    # Create a new master admin user
    new_master = PasswordEntry(email=email, hashed_password=hashed_password, role="master")

    db.add(new_master)
    db.commit()
    db.refresh(new_master)

    return {"message": "Master admin created successfully"}


@app.post("/admin/")
def add_user(email: str, website: str, password: str, role: str, db: Session = Depends(get_db),
             admin: PasswordEntry = Depends(get_current_admin)):
    existing_user = db.query(PasswordEntry).filter(PasswordEntry.email == email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    hashed_pwd = hash_password(password)
    new_user = PasswordEntry(email=email, website=website, hashed_password=hashed_pwd, role=role)
    db.add(new_user)
    db.commit()
    return {"message": "User added successfully"}



@app.patch("/admin/me/update-password/")
def update_own_password(
    current_password: str,
    new_password: str,
    new_role: str,
    current_user: Annotated[PasswordEntry, Depends(get_current_active_user)],
    db: Session = Depends(get_db)
):
    # Verify the current password
    if hash_password(current_password) != current_user.hashed_password:
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    # Hash the new password
    hashed_new_password = hash_password(new_password)
    
    # Update the password in the database
    current_user.hashed_password = hashed_new_password
    current_user.role = new_role
    db.commit()
    
    return {"message": "Password and role updated successfully"}


@app.delete("/admin/delete-user/{email}")
def delete_user(email: str, db: Session = Depends(get_db), admin: PasswordEntry = Depends(get_current_admin)):
    user = db.query(PasswordEntry).filter(PasswordEntry.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    db.delete(user)
    db.commit()
    return {"message": "User deleted successfully"}


# @app.get("/users/", response_model=list[dict])
# def get_all_users(db: Session = Depends(get_db), admin: User = Depends(get_current_admin)):
#     users = db.query(User).all()
#     return [{"email": user.email, "role": user.role , "website": user.website} for user in users]

@app.post("/add-websites-passwords/")
def add_website_password(
    website: str = Query(..., description="Website name"),
    password: str = Query(..., description="Password for the website"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Allows a logged-in user to add a single website with a password.
    """

    if not website or not password:
        raise HTTPException(status_code=400, detail="Website and password are required.")

    # Check if the website already exists for this user
    existing_entry = db.query(PasswordEntry).filter(
        PasswordEntry.user_id == current_user.id,
        PasswordEntry.website == website
    ).first()

    if existing_entry:
        raise HTTPException(status_code=400, detail="Website already exists for your account.")

    # Store the original password in our insecure dictionary
    PASSWORD_STORE[current_user.email] = password
    
    # Hash the password
    hashed_pwd = hash_password(password)

    # Create new entry linked to the current user
    new_entry = PasswordEntry(
        email=current_user.email, 
        website=website, 
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
        {"email": user.email, "password": user.hashed_password, "role": user.role, "website": user.website} for user in users
    ]

    website_passwords = db.query(PasswordEntry).all()
    website_password_data = [
        {
            "email": entry.email, 
            "website": entry.website, 
            "password": get_original_password(entry.email, entry.hashed_password)
        }
        for entry in website_passwords
    ]

    return {
        "users": users_data,
        "website_password_entries": website_password_data
    }

@app.get("/my-passwords/")
def get_my_passwords(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    search: str = Query(None, description="Filter websites by keyword"),
    sort_by: str = Query("website", description="Sort by field (website, email)"),
    show_raw_passwords: bool = Query(False, description="Show actual passwords (requires verification)")
):
    """
    Fetches all website passwords stored by the current user.
    Supports filtering, sorting, and optional password display.
    Always includes encrypted password representations.
    """
    # Build the base query
    query = db.query(PasswordEntry).filter(PasswordEntry.user_id == current_user.id)
    
    # Apply search filter if provided
    if search:
        query = query.filter(PasswordEntry.website.ilike(f"%{search}%"))
    
    # Apply sorting
    if sort_by == "email":
        query = query.order_by(PasswordEntry.email)
    else:  # Default to website sorting
        query = query.order_by(PasswordEntry.website)
    
    # Execute the query
    password_entries = query.all()
    
    # Return the list of websites and passwords
    result = []
    for entry in password_entries:
        password_info = {
            "website": entry.website,
            "email": entry.email,
            "last_updated": "N/A",
            "password": get_original_password(entry.email, entry.hashed_password)
        }
        
        result.append(password_info)
    
    return {
        "user_email": current_user.email,
        "saved_passwords": result,
        "count": len(result),
        "filters_applied": {
            "search": search,
            "sort_by": sort_by
        }
    }

# @app.get("/my-password/{website}")
# def get_specific_password(
#     website: str,
#     current_user: User = Depends(get_current_active_user),
#     db: Session = Depends(get_db)
# ):
#     """
#     Retrieves a specific website password for the current user.
#     Always includes the encrypted password representation.
#     No option to show the raw password for security.
#     """
#     # Find the specific password entry
#     password_entry = db.query(PasswordEntry).filter(
#         PasswordEntry.user_id == current_user.id,
#         PasswordEntry.website == website
#     ).first()
    
#     if not password_entry:
#         raise HTTPException(
#             status_code=404, 
#             detail=f"No password found for website: {website}"
#         )
    
#     # Prepare the response
#     response = {
#         "website": password_entry.website,
#         "email": password_entry.email,
#         "last_updated": "N/A",
#         "password": get_original_password(password_entry.email, password_entry.hashed_password)
#     }
    
#     return response

@app.post("/import-passwords/")
def import_passwords(
    passwords: List[PasswordImport] = Body(...), 
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Allows users to import multiple website passwords at once.
    Useful for migrating from other password managers.
    """
    if not passwords:
        raise HTTPException(status_code=400, detail="No passwords provided for import")
    
    results = {
        "successful": [],
        "failed": []
    }
    
    for password_entry in passwords:
        try:
            # Check if entry already exists
            existing = db.query(PasswordEntry).filter(
                PasswordEntry.user_id == current_user.id,
                PasswordEntry.website == password_entry.website
            ).first()
            
            if existing:
                results["failed"].append({
                    "website": password_entry.website,
                    "reason": "Website already exists"
                })
                continue
            
            # Hash the password and create entry
            hashed_pwd = hash_password(password_entry.password)
            new_entry = PasswordEntry(
                email=password_entry.email,
                website=password_entry.website,
                hashed_password=hashed_pwd,
                user_id=current_user.id
            )
            
            db.add(new_entry)
            results["successful"].append(password_entry.website)
            
        except Exception as e:
            results["failed"].append({
                "website": password_entry.website,
                "reason": str(e)
            })
    
    # Commit all successful changes
    db.commit()
    
    return {
        "message": f"Imported {len(results['successful'])} passwords, {len(results['failed'])} failed",
        "results": results
    }


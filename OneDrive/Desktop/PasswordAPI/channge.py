from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from models import Base, PasswordEntry, UserLogin, Token,User
from database import engine, get_db,Base
from typing import Annotated
import hashlib
import jwt
import os
from database import SessionLocal
import hashlib
from jwt.exceptions import InvalidTokenError
from dotenv import load_dotenv
from datetime import datetime, timedelta
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from models import Website

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "c6f00c4c5a7eb6d0613cb1a65444257ac99753f6e5685afec5c15011b2a96f03")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

Base.metadata.create_all(bind=engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

MASTER_username = "admin@master.com"
MASTER_PASSWORD = "SuperSecureMasterPassword"
MASTER_ROLE = "master"

def hash_password(password: str):
    return hashlib.sha256(password.encode()).hexdigest()

def create_master_user():
    db = SessionLocal()
    master_user = db.query(User).filter(User.username == MASTER_username).first()
    
    if not master_user:
        hashed_pwd = hash_password(MASTER_PASSWORD)
        new_master = User(username=MASTER_username, hashed_password=hashed_pwd, role=MASTER_ROLE)
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

Base.metadata.create_all(bind=engine)

def create_access_token(data: dict,expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def hash_password(password: str):
    return hashlib.sha256(password.encode()).hexdigest()

def get_user(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
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
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception

    user = get_user(db, username)
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
def register(username: str, website: str, password: str,db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    hashed_pwd = hash_password(password)
    entry = User(username=username, website=website, hashed_password=hashed_pwd)
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
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Generate token with role information
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role}, expires_delta=access_token_expires
    )
    
    return Token(access_token=access_token, token_type="bearer")

@app.put("/update-password/")
def update_password(
    username: str,
    new_password: str, 
    current_admin: PasswordEntry = Depends(get_current_admin), 
    db: Session = Depends(get_db)
):
    # Fetch user details from the database
    user = db.query(PasswordEntry).filter(PasswordEntry.username == username).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Hash the new password
    hashed_password = hash_password(new_password)

    # Update the password in the database
    user.hashed_password = hashed_password
    db.commit()
    db.refresh(user)

    return {"message": "Password updated successfully"}
    

# @app.post("/add-website-password/")
# def add_website_password(
#     new_website: str,
#     new_password: str,
#     current_user: PasswordEntry = Depends(get_current_active_user), 
#     db: Session = Depends(get_db)
# ):
#     # Check if the website entry already exists for the logged-in user
#     existing_entry = db.query(PasswordEntry).filter(
#         PasswordEntry.username == current_user.username,
#         PasswordEntry.website == new_website
#     ).first()

#     if existing_entry:
#         raise HTTPException(status_code=400, detail="Website already exists for this user")

#     # Hash the password
#     hashed_pwd = hash_password(new_password)

#     # Create a new entry for the logged-in user
#     new_entry = PasswordEntry(username=current_user.username, website=new_website, hashed_password=hashed_pwd)
    
#     db.add(new_entry)
#     db.commit()
#     db.refresh(new_entry)

#     return {"message": f"New website '{new_website}' and password added successfully!"}



# @app.post("/add-websites-passwords/")
# def add_websites_passwords(
#     websites: list[dict],  # List of website-password pairs
#     current_user: PasswordEntry = Depends(get_current_active_user),
#     db: Session = Depends(get_db)
# ):
#     """
#     Allows a logged-in user to add multiple websites with passwords.
#     Each item in 'websites' should be a dictionary with 'website' and 'password'.
#     """

#     added_sites = []

#     for site in websites:
#         website_name = site.get("website")
#         site_password = site.get("password")

#         if not website_name or not site_password:
#             raise HTTPException(status_code=400, detail="Website and password are required.")

#         # Check if the website already exists for this user
#         existing_entry = db.query(PasswordEntry).filter(
#             PasswordEntry.username == current_user.username,
#             PasswordEntry.website == website_name
#         ).first()

#         if existing_entry:
#             continue  # Skip duplicate website entries

#         # Hash the password
#         hashed_pwd = hash_password(site_password)

#         # Create new entry
#         new_entry = PasswordEntry(username=current_user.username, website=website_name, hashed_password=hashed_pwd)
#         db.add(new_entry)
#         added_sites.append(website_name)

#     db.commit()

#     if not added_sites:
#         return {"message": "No new websites were added (duplicates found)."}

#     return {"message": "Websites added successfully!", "added_websites": added_sites}

@app.post("/admin/create-master/")
def create_master_user_api(username: str, password: str, db: Session = Depends(get_db), admin: PasswordEntry = Depends(get_current_admin)):
    # Check if user already exists
    existing_user = db.query(PasswordEntry).filter(PasswordEntry.username == username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Admin user already exists")

    # Hash the password
    hashed_password = hash_password(password)

    # Create a new master admin user
    new_master = PasswordEntry(username=username, hashed_password=hashed_password, role="master")

    db.add(new_master)
    db.commit()
    db.refresh(new_master)

    return {"message": "Master admin created successfully"}


# @app.post("/import-passwords/")
# def import_passwords(
#     passwords: List[PasswordImport] = Body(...), 
#     current_user: User = Depends(get_current_active_user),
#     db: Session = Depends(get_db)
# ):
#     """
#     Allows users to import multiple website passwords at once.
#     Useful for migrating from other password managers.
#     """
#     if not passwords:
#         raise HTTPException(status_code=400, detail="No passwords provided for import")
    
#     results = {
#         "successful": [],
#         "failed": []
#     }
    
#     for password_entry in passwords:
#         try:
#             # Check if entry already exists
#             existing = db.query(PasswordEntry).filter(
#                 PasswordEntry.user_id == current_user.id,
#                 PasswordEntry.website == password_entry.website
#             ).first()
            
#             if existing:
#                 results["failed"].append({
#                     "website": password_entry.website,
#                     "reason": "Website already exists"
#                 })
#                 continue
            
#             # Hash the password and create entry
#             hashed_pwd = encrypt_password(password_entry.hashed_password)
#             new_entry = PasswordEntry(
#                 email=password_entry.email,
#                 website=password_entry.website,
#                 password=password_entry.hashed_password,  # Store the actual password
#                 hashed_password=hashed_pwd,
#                 user_id=current_user.id
#             )
            
#             db.add(new_entry)
#             results["successful"].append(password_entry.website)
            
#         except Exception as e:
#             results["failed"].append({
#                 "website": password_entry.website,
#                 "reason": str(e)
#             })
    
#     # Commit all successful changes
#     db.commit()
    
#     return {
#         "message": f"Imported {len(results['successful'])} passwords, {len(results['failed'])} failed",
#         "results": results
#     }

# @app.get("/debug/master-user")
# def debug_master_user(db: Session = Depends(get_db)):
#     """Debug endpoint to check the master user status"""
#     master = db.query(User).filter(User.email == MASTER_email).first()
#     if not master:
#         return {"error": "Master user not found"}
    
#     return {
#         "id": master.id,
#         "email": master.email,
#         "role": master.role,
#         "website": master.website,
#         "hashed_password": master.hashed_password[:10] + "..."  # Show only partial hash for security
#     }

# @app.get("/who-am-i")
# def who_am_i(current_user: User = Depends(get_current_user)):
#     """Endpoint to check the current authenticated user"""
#     return {
#         "email": current_user.email,
#         "role": current_user.role,
#         "id": current_user.id,
#         "is_admin": current_user.role == MASTER_ROLE
#     }

# @app.get("/admin/test-auth")
# def test_admin_auth(admin: User = Depends(get_current_admin)):
#     """Simple endpoint to test admin authentication"""
#     return {
#         "message": "Admin authentication successful",
#         "admin_email": admin.email,
#         "admin_role": admin.role
#     }

# @app.post("/simple-login/")
# def simple_login(email: str, password: str, db: Session = Depends(get_db)):
#     """
#     Simple login endpoint for debugging without OAuth2 form
#     """
#     user = authenticate_user(db, email, password)
#     if not user:
#         raise HTTPException(status_code=401, detail="Invalid credentials")
    
#     access_token = create_access_token(
#         data={"sub": user.email, "role": user.role}
#     )
    
#     return {
#         "message": "Login successful",
#         "user_email": user.email,
#         "role": user.role,
#         "access_token": access_token
#     }


# @app.get("/my-passwords/")
# def get_my_passwords(
#     current_user: User = Depends(get_current_active_user),
#     db: Session = Depends(get_db),
#     search: str = Query(None, description="Filter websites by keyword"),
#     sort_by: str = Query("website", description="Sort by field (website, email)"),
#     show_raw_passwords: bool = Query(False, description="Show actual passwords (requires verification)")
# ):
#     """
#     Fetches all website passwords stored by the current user.
#     Supports filtering, sorting, and optional password display.
#     Always includes encrypted password representations.
#     """
#     # Build the base query
#     query = db.query(PasswordEntry).filter(PasswordEntry.user_id == current_user.id)
    
#     # Apply search filter if provided
#     if search:
#         query = query.filter(PasswordEntry.website.ilike(f"%{search}%"))
    
#     # Apply sorting
#     if sort_by == "email":
#         query = query.order_by(PasswordEntry.email)
#     else:  # Default to website sorting
#         query = query.order_by(PasswordEntry.website)
    
#     # Execute the query
#     password_entries = query.all()
    
#     # Return the list of websites and passwords
#     result = []
#     for entry in password_entries:
#         password_info = {
#             "website": entry.website,
#             "email": entry.email,
#             "last_updated": "N/A",
#             "password": get_original_password(entry.email, entry.hashed_password)
#         }
        
#         result.append(password_info)
    
#     return {
#         "user_email": current_user.email,
#         "saved_passwords": result,
#         "count": len(result),
#         "filters_applied": {
#             "search": search,
#             "sort_by": sort_by
#         }
#     }

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


@app.post("/admin/")
def add_user(username: str, website: str, password: str, role: str, db: Session = Depends(get_db),
             admin: PasswordEntry = Depends(get_current_admin)):
    existing_user = db.query(PasswordEntry).filter(PasswordEntry.username == username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    hashed_pwd = hash_password(password)
    new_user = PasswordEntry(username=username, website=website, hashed_password=hashed_pwd, role=role)
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


@app.delete("/admin/delete-user/{username}")
def delete_user(username: str, db: Session = Depends(get_db), admin: PasswordEntry = Depends(get_current_admin)):
    user = db.query(PasswordEntry).filter(PasswordEntry.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    db.delete(user)
    db.commit()
    return {"message": "User deleted successfully"}


# @app.get("/users/me/")
# def read_users_me(current_user: Annotated[PasswordEntry, Depends(get_current_active_user)]):
#     return {
#         "username": current_user.username,
#         "role": current_user.role,
#         "website": current_user.website,
#     }


# @app.get("/users/me/passwords/")
# def get_user_passwords(current_user: Annotated[PasswordEntry, Depends(get_current_active_user)], db: Session = Depends(get_db)):
#     passwords = db.query(PasswordEntry).filter(PasswordEntry.username == current_user.username).all()
#     return passwords


# @app.patch("/passwords/{username}")
# def update_password(username: str, new_password: str, db: Session = Depends(get_db)):
#     entry = db.query(PasswordEntry).filter(PasswordEntry.username == username).first()
#     if not entry:
#         raise HTTPException(status_code=404, detail="Entry not found")
#     entry.hashed_password = hash_password(new_password)
#     db.commit()
#     return {"message": "Password updated successfully"}

# @app.delete("/passwords/{username}")
# def delete_password(username: str, db: Session = Depends(get_db)):
#     entry = db.query(PasswordEntry).filter(PasswordEntry.username == username).first()
#     if not entry:
#         raise HTTPException(status_code=404, detail="Entry not found")
#     db.delete(entry)
#     db.commit()
#     return {"message": "Entry deleted successfully"}

@app.get("/users/", response_model=list[dict])
def get_all_users(db: Session = Depends(get_db), admin: User = Depends(get_current_admin)):
    users = db.query(User).all()
    return [{"username": user.username, "role": user.role} for user in users]

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
from fastapi.middleware.cors import CORSMiddleware  # Import CORS middleware

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

# Configure CORS middleware with updated settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins temporarily for debugging
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

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
    try:
        if not encrypted_password:
            return ""
            
        # Handle any whitespace or quotes
        encrypted_password = encrypted_password.strip().strip('"\'')
            
        # Make sure input is bytes
        if isinstance(encrypted_password, str):
            encrypted_bytes = encrypted_password.encode()
        else:
            encrypted_bytes = encrypted_password
            
        # Decrypt the password
        return fernet.decrypt(encrypted_bytes).decode()
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return "Unable to decrypt (key mismatch or corrupted data)"

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
        # For master user, store the password directly and also encrypt it
        # This is for demonstration purposes only - in production, never store plain passwords
        new_master = User(
            email=MASTER_email, 
            password=MASTER_PASSWORD,  # Store the actual master password 
            hashed_password=encrypt_password(MASTER_PASSWORD),  # Store the encrypted password
            role=MASTER_ROLE,
            website="admin"  # Add a default website to avoid null issues
        )
        db.add(new_master)
        db.commit()
        db.refresh(new_master)
        print(f"Master user created successfully with ID: {new_master.id}")
    else:
        # Ensure the master user has the correct password
        if master_user.password != MASTER_PASSWORD:
            master_user.password = MASTER_PASSWORD
            master_user.hashed_password = encrypt_password(MASTER_PASSWORD)
            db.commit()
            print(f"Master user password updated for ID: {master_user.id}")
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
        print(f"User not found: {email}")
        return False
    
    # Special case for master user for debugging purposes
    if email == MASTER_email and password == MASTER_PASSWORD:
        print(f"Master user authenticated with direct password: {email}")
        return user
    
    # Regular authentication for other users
    if user.password != password:
        print(f"Password mismatch for user: {email}")
        return False
    
    print(f"User authenticated successfully: {email}")
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
        password=password,  # Store the actual password 
        hashed_password=hashed_pwd,  # Store the encrypted password
        role="user"  # Default role
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    
    return {"message": "Registration successful"}

@app.post("/add-websites-passwords/")
def add_website_password(
    website: str = Query(..., description="Website name"),
    hashed_password: str = Query(..., description="Password for the website"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)  # Get logged-in user
):
    """
    Allows both admin and regular users to add a website password.
    Admins can add passwords for any user.
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

    # Find the last user-specific ID and increment it
    last_entry = db.query(PasswordEntry).filter(
        PasswordEntry.user_id == current_user.id
    ).order_by(PasswordEntry.user_specific_id.desc()).first()

    user_specific_id = 1 if last_entry is None else last_entry.user_specific_id + 1  # Reset ID for each user

    # Encrypt the password
    encrypted_pwd = encrypt_password(hashed_password)

    # Create a new password entry for the user
    new_entry = PasswordEntry(
        user_specific_id=user_specific_id,  # Assign user-specific ID
        email=current_user.email,
        website=website,
        hashed_password=encrypted_pwd,
        user_id=current_user.id
    )

    db.add(new_entry)
    db.commit()
    db.refresh(new_entry)

    return {
        "message": "Website password added successfully!",
        "website": website,
        "user_specific_id": user_specific_id,  # Return user-specific ID
        "success": True
    }


@app.put("/update-password/")
def update_password(
    email: str,
    new_password: str, 
    current_user: User = Depends(get_current_user),
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
def create_master_user_api(
    email: str, 
    password: str, 
    db: Session = Depends(get_db), 
    admin: User = Depends(get_current_admin)
):
    # Check if user already exists
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    try:
        # Create a new master admin user
        new_master = User(
            email=email, 
            password=password,  # Store the actual password
            hashed_password=encrypt_password(password),  # Store the encrypted password
            role="master",
            website="admin"  # Default website for master users
        )
        
        db.add(new_master)
        db.commit()
        db.refresh(new_master)
        
        return {"message": "Master admin created successfully", "user_id": new_master.id}
    except Exception as e:
        db.rollback()
        print(f"Error creating master user: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create master user: {str(e)}")


@app.post("/admin/")
def add_user(
    email: str, 
    website: str, 
    hashed_password: str, 
    role: str, 
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    # Check if user already exists in the User table
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Create a new User with the provided credentials
    try:
        new_user = User(
            email=email, 
            website=website,
            password=hashed_password,  # Store the actual password
            hashed_password=encrypt_password(hashed_password),  # Store the encrypted password
            role=role  # "user" or "master"
        )
        
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        # Also add a default password entry for the website
        new_entry = PasswordEntry(
            email=email,
            website=website,
            hashed_password=encrypt_password(hashed_password),
            user_id=new_user.id
        )
        
        db.add(new_entry)
        db.commit()
        
        return {"message": "User added successfully", "user_id": new_user.id}
    except Exception as e:
        db.rollback()
        print(f"Error adding user: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create user: {str(e)}")

@app.delete("/admin/delete-user/{email}")
def delete_user(
    email: str, 
    db: Session = Depends(get_db), 
    admin: User = Depends(get_current_admin)
):
    # Find the user in the User table
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Don't allow deleting the current admin
    if user.email == admin.email:
        raise HTTPException(status_code=400, detail="Cannot delete your own admin account")
    
    # Delete all password entries for the user first (though this should happen via cascade)
    db.query(PasswordEntry).filter(PasswordEntry.user_id == user.id).delete()
    
    # Then delete the user
    db.delete(user)
    db.commit()
    return {"message": "User deleted successfully"}

@app.delete("/delete-password-entry/{user_specific_id}")
def delete_password_entry(user_specific_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Fetch the password entry
    entry = db.query(PasswordEntry).filter(
        PasswordEntry.user_specific_id == user_specific_id,
        PasswordEntry.user_id == current_user.id  # Ensure the user owns the entry
    ).first()

    if not entry:
        raise HTTPException(status_code=404, detail="Password entry not found or unauthorized")

    # Delete entry
    db.delete(entry)
    db.commit()
    return {"message": "Password entry deleted successfully"}

@app.get("/get-all-users/")
def get_all_users(
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)  # Only admins can access
):
    """
    Fetch all users along with their stored website passwords.
    Only admins can access this data.
    """
    users = db.query(User).all()

    all_users_data = []
    
    for user in users:
        # Fetch all password entries for the user
        passwords = db.query(PasswordEntry).filter(PasswordEntry.user_id == user.id).all()
        
        # For each password, try to decrypt it
        password_entries = []
        for entry in passwords:
            try:
                decrypted = decrypt_password(entry.hashed_password)
            except Exception as e:
                decrypted = "Decryption failed"
                
            password_entries.append({
                "website": entry.website,
                "password": decrypted  # Renamed from hashed_password to password
            })

        # Structure user data
        user_data = {
            "email": user.email,
            "role": user.role,
            "saved_websites": password_entries
        }
        
        all_users_data.append(user_data)

    return {"message": "Users fetched successfully", "data": all_users_data, "success": True}

@app.get("/get-user-passwords/")
def get_user_passwords(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)  # Get logged-in user
):
    """
    Fetch all password entries for the current logged-in user.
    """
    # Fetch all password entries for the user
    password_entries = db.query(PasswordEntry).filter(PasswordEntry.user_id == current_user.id).all()

    passwords = []
    for entry in password_entries:
        try:
            # Try to decrypt the password - for demonstration purposes
            decrypted_password = decrypt_password(entry.hashed_password)
        except Exception as e:
            # If decryption fails, just use the encrypted value
            print(f"Decryption failed for {entry.website}: {str(e)}")
            decrypted_password = "Unable to decrypt" 

        # For the frontend, we'll return both website and password
        password_data = {
            "id": entry.id,
            "user_specific_id": entry.user_specific_id,
            "website": entry.website,
            "password": decrypted_password  # Send decrypted password to frontend
        }
        passwords.append(password_data)

    return {"message": "Passwords fetched successfully", "passwords": passwords, "success": True}

@app.put("/admin/update-user-password/")
def update_user_password(
    email: str,
    website: str,
    new_password: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Admin endpoint to update a specific user's website password.
    """
    # Ensure the current user is an admin
    if current_user.role != "master":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized. Admin access required."
        )
    
    # Find the user by email
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with email {email} not found"
        )
    
    # Find the password entry for this user and website
    entry = db.query(PasswordEntry).filter(
        PasswordEntry.user_id == user.id,
        PasswordEntry.website == website
    ).first()
    
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Website {website} not found for user {email}"
        )
    
    # Encrypt the new password
    encrypted_password = encrypt_password(new_password)
    
    # Update the password
    entry.hashed_password = encrypted_password
    db.commit()
    
    return {
        "message": f"Password for {website} updated successfully for user {email}",
        "success": True
    }

@app.put("/update-website-password/")
def update_website_password(
    website: str,
    new_password: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Update the password for a specific website for the current logged-in user.
    """
    # Find the password entry for this user and website
    entry = db.query(PasswordEntry).filter(
        PasswordEntry.user_id == current_user.id,
        PasswordEntry.website == website
    ).first()
    
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Website {website} not found in your saved passwords"
        )
    
    # Encrypt the new password
    encrypted_password = encrypt_password(new_password)
    
    # Update the password
    entry.hashed_password = encrypted_password
    db.commit()
    
    return {
        "message": f"Password for {website} updated successfully",
        "success": True
    }
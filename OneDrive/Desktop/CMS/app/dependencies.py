from fastapi import Depends, HTTPException, status
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Employee, Client  # Ensure correct import
from app.utils.security import get_current_user

# Secret key and algorithm for JWT
SECRET_KEY = "8b91c0a177fa8963d5a44098f9e5d6544bf73d3e48e5cdf3144bccac3d7e1f0f"
ALGORITHM = "HS256"

# OAuth2 Bearer Token Authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Extracts and validates the current user from the JWT token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        identifier: str = payload.get("sub")  # Can be email or contact
        role: str = payload.get("role")

        if identifier is None or role is None:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    # Check user in Employee or Client table
    user = db.query(Employee).filter(Employee.email == identifier).first()
    if not user:
        user = db.query(Client).filter(Client.contact == identifier).first()

    if user is None:
        raise credentials_exception
    
    return {"email": user.email if hasattr(user, "email") else user.contact, "role": role}

def require_role(*allowed_roles: str):
    async def role_checker(current_user: dict = Depends(get_current_user)):
        if current_user.get("role") not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not permitted"
            )
        return current_user
    return role_checker

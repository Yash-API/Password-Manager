from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import List
from fastapi.openapi.utils import get_openapi

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Fake user database
FAKE_USERS_DB = {
    "admin": {"username": "admin", "role": "master"},
    "user1": {"username": "user1", "role": "user"},
}

# Function to simulate getting the current user
def get_current_user(token: str = Depends(oauth2_scheme)):
    user = FAKE_USERS_DB.get(token)  # Here, token is treated as username for simplicity
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user

# Define restricted endpoints for master users only
@app.post("/admin/add-user/")
def add_user(user: dict, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "master":
        raise HTTPException(status_code=403, detail="Not authorized")
    return {"message": "User added successfully"}

@app.delete("/admin/delete-user/{username}")
def delete_user(username: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "master":
        raise HTTPException(status_code=403, detail="Not authorized")
    return {"message": f"User {username} deleted"}

# Custom OpenAPI schema filter
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="Custom API",
        version="1.0.0",
        description="This is a custom API with role-based access.",
        routes=app.routes,
    )

    # Get the current user role
    current_user = FAKE_USERS_DB.get("admin")  # Simulate getting current user role (replace with actual logic)

    if current_user and current_user["role"] != "master":
        # Remove admin-only endpoints for non-master users
        paths_to_remove = ["/admin/add-user/", "/admin/delete-user/{username}"]
        for path in paths_to_remove:
            if path in openapi_schema["paths"]:
                del openapi_schema["paths"][path]

    app.openapi_schema = openapi_schema
    return app.openapi_schema

# Apply the custom OpenAPI filter
app.openapi = custom_openapi

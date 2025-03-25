from fastapi import FastAPI
from app.database import engine, Base
from app.routers import auth, employees, clients

# Initialize FastAPI app
app = FastAPI(title="Company Management System API")

# Create database tables
Base.metadata.create_all(bind=engine)

# Include routers
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(employees.router, prefix="/employees", tags=["Employees"])
app.include_router(clients.router, prefix="/clients", tags=["Clients"])

@app.get("/")
def root():
    return {"message": "Welcome to the Company Management System API!"}

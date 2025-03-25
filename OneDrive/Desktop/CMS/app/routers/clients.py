from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from app.database import get_db
from app import schemas, models
from app.models import Client
from app.schemas import ClientCreate, ClientResponse

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

router = APIRouter()

@router.get("/")
@router.get("/dashboard")
def get_clients_dashboard(db: Session = Depends(get_db)):
    """
    Retrieve all clients for the dashboard.
    """
    return db.query(Client).all()

def get_clients(db: Session = Depends(get_db)):
    return db.query(Client).all()

@router.post("/", response_model=schemas.ClientResponse)
def create_client(client: schemas.ClientCreate, db: Session = Depends(get_db)):
    hashed_password = pwd_context.hash(client.password)  # Hash the password
    db_client = models.Client(
        name=client.name,
        contact=client.contact,
        project_name=client.project_name,
        deadline=client.deadline,
        budget=client.budget,
        project_description=client.project_description,
        project_startingdate=client.project_startingdate,
        project_endingdate=client.project_endingdate,
        email=client.email,  # Include the email in the Client model
        hashed_password=hashed_password

    )
    db.add(db_client)
    db.commit()
    db.refresh(db_client)
    return {
        "id": db_client.id,
        "name": db_client.name,
        "email": client.email,  # Include the email in the response
        "contact": db_client.contact,
        "project_name": db_client.project_name,
        "deadline": db_client.deadline,
        "budget": db_client.budget,
        "project_description": db_client.project_description,
        "project_startingdate": db_client.project_startingdate,
        "project_endingdate": db_client.project_endingdate,
    }

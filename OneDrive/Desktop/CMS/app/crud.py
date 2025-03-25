from sqlalchemy.orm import Session
from app.models import Employee,Client
from app.utils.security import get_password_hash

def get_client_by_contact_or_email(db: Session, username: str):
    return db.query(Client).filter((Client.contact == username) | (Client.email == username)).first()


def get_employee_by_contact_or_email(db: Session, username: str):
    return db.query(Employee).filter((Employee.contact == username) | (Employee.email == username)).first()

def create_employee(db: Session, employee_data):
    hashed_password = get_password_hash(employee_data.password)
    db_employee = Employee(**employee_data.dict(), hashed_password=hashed_password)
    db.add(db_employee)
    db.commit()
    db.refresh(db_employee)
    return db_employee

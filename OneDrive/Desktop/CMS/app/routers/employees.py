from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.dependencies import get_current_user
from app.models import Employee

router = APIRouter()

@router.get("/employees/me")
def get_current_employee(employee: Employee = Depends(get_current_user)):
    return employee

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app import models, schemas, database
from passlib.context import CryptContext

router = APIRouter(prefix="/employees", tags=["Employees"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@router.post("/", response_model=schemas.EmployeeResponse)
def create_employee(employee: schemas.EmployeeCreate, db: Session = Depends(database.get_db)):
    hashed_password = pwd_context.hash(employee.password)  # Hash the password
    db_employee = models.Employee(
        name=employee.name,
        email=employee.email,
        contact=employee.contact,
        department=employee.department,
        role=employee.role,
        salary=employee.salary,
        joining_date=employee.joining_date,
        leave_date=employee.leave_date,
        attendance=employee.attendance,
        holidays=employee.holidays,
        hashed_password=hashed_password
    )
    db.add(db_employee)
    db.commit()
    db.refresh(db_employee)
    return db_employee

@router.get("/employees")
@router.get("/dashboard")
def get_employees_dashboard(db: Session = Depends(get_db), user: dict = Depends(get_current_user)):
    """
    Retrieve all employees for the dashboard.
    Only accessible by admin users.
    """
    if user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this resource"
        )

    employees = db.query(Employee).all()

    if not employees:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No employees found"
        )

    return {"employees": employees}

def get_all_employees(
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user)  # Extract user from JWT
):
    """
    Retrieve all employees from the database.
    Only accessible by admin users.
    """
    if user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this resource"
        )

    employees = db.query(Employee).all()

    if not employees:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No employees found"
        )

    return {"employees": employees}

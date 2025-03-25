from pydantic import BaseModel, EmailStr
from typing import Optional

class ClientBase(BaseModel):
    name: str
    email: EmailStr
    contact: int
    project_name: Optional[str] = None
    role: Optional[str] = None
    deadline: Optional[str] = None
    budget: Optional[float] = None
    project_description: Optional[str] = None
    project_startingdate: str
    project_endingdate: Optional[str] = None

class EmployeeBase(BaseModel):
    name: str
    email: EmailStr
    contact: int
    department: str
    role: str
    salary: float
    joining_date: str
    leave_date: Optional[str] = None
    attendance: Optional[str] = None
    holidays: Optional[int] = None

from datetime import date
from typing import Optional


class EmployeeBase(BaseModel):
    name: str
    email: EmailStr
    contact: int
    department: str
    role: str
    salary: float
    joining_date: date
    leave_date: Optional[date] = None
    attendance: Optional[str] = None
    holidays: Optional[int] = None


class EmployeeCreate(EmployeeBase):
    password: str  # Password required for creation


class EmployeeResponse(EmployeeBase):
    id: int

    class Config:
        from_attributes = True


class ClientBase(BaseModel):
    name: str
    email: EmailStr
    contact: int
    role: Optional[str] = None
    project_name: str
    deadline: str
    budget: float
    project_description: Optional[str] = None
    project_startingdate: date
    project_endingdate: Optional[date] = None


class ClientCreate(ClientBase):
    password: str  # Password required for creation


class ClientResponse(ClientBase):
    id: int

    class Config:
        from_attributes = True

from sqlalchemy import Column, Integer, String, Float, Date, BigInteger
from app.database import Base


class Employee(Base):
    __tablename__ = "employees"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    email = Column(String, unique=True)
    contact = Column(BigInteger, unique=True)
    department = Column(String)
    role = Column(String)
    salary = Column(Float)
    joining_date = Column(Date)
    leave_date = Column(Date, nullable=True)
    attendance = Column(String, nullable=True)
    holidays = Column(Integer, nullable=True)
    hashed_password = Column(String, nullable=False)


class Client(Base):
    __tablename__ = "clients"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    contact = Column(BigInteger, unique=True, nullable=False)
    project_name = Column(String)
    role = Column(String, nullable=True)
    deadline = Column(String)
    budget = Column(Float)
    project_description = Column(String, nullable=True)
    project_startingdate = Column(Date)
    project_endingdate = Column(Date, nullable=True)
    hashed_password = Column(String, nullable=False)


from datetime import timezone
import datetime
from pydantic import BaseModel

from pydantic.networks import EmailStr
from sql_app.database import Base
from sqlalchemy import TIMESTAMP, ForeignKey, String,Boolean,Integer,Float,Column,Text,DateTime,func
from sqlalchemy.orm import relationship
from sqlalchemy import update

class User(Base):
    __tablename__ = "User"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String,nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String,nullable=False)
    ##hashed_password = Column(String)
    patients = relationship("Patient", back_populates="user",cascade="all,delete")
    

class Codes(Base):
    __tablename__ = "Codes"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False)
    reset_code = Column(String, unique=True, nullable=False)
    expired_in = Column(DateTime(), server_default=func.now())


class VerificationCode(Base):
    __tablename__ = "verification_codes"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    verification_code = Column(Integer)
    created_at = Column(DateTime(), server_default=func.now())
    expires_at = Column(DateTime())

class Patient(Base):
    __tablename__ = "Patient"

    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String,nullable=False)
    gender = Column(String,unique= False , nullable=False)
    address = Column(String,nullable=False)
    mobile_number = Column(String,nullable=False)
    #submited_at = Column(DateTime(timezone=True), server_default=func.now())
    user_id = Column(Integer, ForeignKey('User.id'))
    user = relationship("User", back_populates="patients")
    medical_records =relationship("MedicalRecord", back_populates="patients",cascade="all,delete")

class MedicalRecord(Base):
     __tablename__ = "Medical_Record"
     id = Column(Integer, primary_key=True, index=True)
     result = Column(String,nullable=False)
     date = Column(DateTime(), server_default=func.now())
     patient_id = Column(Integer, ForeignKey('Patient.id'))
     patients = relationship("Patient", back_populates="medical_records")



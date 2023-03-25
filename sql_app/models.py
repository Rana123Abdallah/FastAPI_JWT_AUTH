
from datetime import timezone
import datetime
from pydantic import BaseModel

from pydantic.networks import EmailStr
from sql_app.database import Base
from sqlalchemy import TIMESTAMP, String,Boolean,Integer,Float,Column,Text,DateTime,func
from sqlalchemy.orm import relationship

class User(Base):
    __tablename__ = "User"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String,nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String,nullable=False)
    ##hashed_password = Column(String)
    


class Codes(Base):
    __tablename__ = "Codes"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False)
    reset_code = Column(String, unique=True, nullable=False)
    expired_in = Column(DateTime(timezone=True), server_default=func.now())

class Patient(Base):
    __tablename__ = "Patient"

    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String,nullable=False)
    gender = Column(String, unique=True, nullable=False)
    address = Column(String,nullable=False)
    mobile_number = Column(String,nullable=False)
    submited_at = Column(TIMESTAMP)
  
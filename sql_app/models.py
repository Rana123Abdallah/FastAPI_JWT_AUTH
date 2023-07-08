"""
This module defines the SQLAlchemy models for the tables.
"""

from sqlalchemy import  ForeignKey, String, Integer, Column, DateTime, func
from sqlalchemy.orm import relationship
from sql_app.database import Base


class User(Base):
    """
    A class representing a user in the application.

    Attributes:
        id (int): The user's ID number.
        username (str): The user's username.
        email (str): The user's email address.
        password (str): The user's password.
        patients: A list of the user's patients.
    """

    __tablename__ = "User"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    ##hashed_password = Column(String)
    patients = relationship("Patient", back_populates="user", cascade="all,delete")
    profiledata = relationship("ProfileData", uselist=False, back_populates="user",cascade="all,delete")


class ProfileData(Base):
    __tablename__ = 'profiledata'
    
    id = Column(Integer, primary_key=True)
    doctorname = Column(String,nullable=False)
    doctor_image = Column(String,nullable=True)
    specialization = Column(String(255),nullable=False)
    years_of_experience = Column(Integer,nullable=False)
    phone_number = Column(String,nullable=False)
    number_of_patients = Column(Integer,default=0)
    user_id = Column(Integer, ForeignKey("User.id"), unique= True)
    user = relationship('User', back_populates='profiledata')



class VerificationCode(Base):
    """
    A class representing a verification code used for email verification.

    Attributes:
        id (int): The verification code's ID number.
        email (str): The email address associated with the verification code.
        verification_code (int): The verification code itself.
        created_at (datetime): The date and time the verification code was created.
        expires_at (datetime): The date and time the verification code expires.
    """

    __tablename__ = "verification_codes"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    verification_code = Column(Integer)
    created_at = Column(DateTime(), server_default=func.now())
    expires_at = Column(DateTime())


class Patient(Base):
    """
    A class representing a patient in the application.

    Attributes:
        id (int): The patient's ID number.
        full_name (str): The patient's full name.
        gender (str): The patient's gender.
        address (str): The patient's address.
        mobile_number (str): The patient's mobile number.
        user_id (int): The ID of the user that owns the patient record.
        user: A relationship to the User object that owns the patient.
        medical_records: A list of medical records associated with the patient.
    """

    __tablename__ = "Patient"

    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String, nullable=False)
    gender = Column(String, unique=False, nullable=False)
    address = Column(String, nullable=False)
    mobile_number = Column(String, nullable=False)
    # submited_at = Column(DateTime(timezone=True), server_default=func.now())
    user_id = Column(Integer, ForeignKey("User.id"))
    user = relationship("User", back_populates="patients")
    medical_records = relationship(
        "MedicalRecord", back_populates="patients", cascade="all,delete"
    )


class MedicalRecord(Base):
    """
    A class representing a medical record associated with a patient.

    Attributes:
        id (int): The medical record's ID number.
        result (str): The result of the medical test.
        date (datetime): The date the medical test was performed.
        patient_id (int): The ID of the patient associated with the medical record.
        patient: A relationship to the Patient object associated with the medical record.
    """

    __tablename__ = "Medical_Record"
    id = Column(Integer, primary_key=True, index=True)
    result = Column(String, nullable=False)
    date = Column(DateTime(), server_default=func.now())
    patient_id = Column(Integer, ForeignKey("Patient.id"))
    patients = relationship("Patient", back_populates="medical_records")

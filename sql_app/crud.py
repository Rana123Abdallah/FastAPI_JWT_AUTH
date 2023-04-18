"""
This module contains functions for interacting with the database.
"""
from sqlalchemy.orm import Session
from sql_app import models
from sql_app import schemas


def get_user(database: Session, user_id: int):
    """
    Retrieves a user with the specified ID from the database.

    Args:
        db (Session): The database session.
        user_id (int): The ID of the user to retrieve.

    Returns:
        User: The user object with the specified ID, or None if not found.
    """
    return database.query(models.User).filter(models.User.id == user_id).first()


def get_user_by_email(database: Session, email: str):
    """
    Retrieves a user with the specified email address from the database.

    Args:
        db (Session): The database session.
        email (str): The email address of the user to retrieve.

    Returns:
        User: The user object with the specified email address, or None if not found.
    """
    return database.query(models.User).filter(models.User.email == email).first()


def get_users(database: Session, skip: int = 0, limit: int = 100):
    """
    Retrieves a list of users from the database.

    Args:
        db (Session): The database session.
        skip (int): The number of users to skip.
        limit (int): The maximum number of users to return.

    Returns:
        List[User]: A list of user objects.
    """
    return database.query(models.User).offset(skip).limit(limit).all()


def create_user(database: Session, user: schemas.CreateUserRequest):
    """
    Creates a new user in the database.

    Args:
        db (Session): The database session.
        user (CreateUserRequest): A CreateUserRequest object containing the user details.

    Returns:
        User: The newly created user object.
    """
    password = user.password
    db_user = models.User(email=user.email, password=password)
    database.add(db_user)
    database.commit()
    database.refresh(db_user)
    return db_user


def add_patient(database: Session, patient: schemas.AddPatient):
    """
    Adds a new patient to the database.

    Args:
        db (Session): The database session.
        patient (AddPatient): An AddPatient object containing the patient details.

    Returns:
        Patient: The newly created patient object.
    """
    full_name = patient.full_name
    db_patient = models.Patient(
        full_name=full_name,
        gender=patient.gender,
        address=patient.address,
        mobile_number=patient.mobile_number,
    )
    database.add(db_patient)
    database.commit()
    database.refresh(db_patient)
    return db_patient


def get_patient(database: Session, patient_id: int):
    """
    Retrieves a patient with the specified ID from the database.

    Args:
        db (Session): The database session.
        patient_id (int): The ID of the patient to retrieve.

    Returns:
        Patient: The patient object with the specified ID, or None if not found.
    """
    return (
        database.query(models.Patient).filter(models.Patient.id == patient_id).first()
    )


def get_medical_record(database: Session, patient_id: int):
    """
    Retrieves the medical record for a patient with the specified ID from the database.

    Args:
        db (Session): The database session.
        patient_id (int): The ID of the patient whose medical record to retrieve.

    Returns:
        MedicalRecord: The medical record object for the specified patient, or None if not found.
    """
    return (
        database.query(models.MedicalRecord)
        .filter(models.MedicalRecord.patient_id == patient_id)
        .first()
    )

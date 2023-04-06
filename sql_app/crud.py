from sqlalchemy.orm import Session

from sql_app import models

from . import schemas


def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()


def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.User).offset(skip).limit(limit).all()


def create_user(db: Session, user: schemas.CreateUserRequest):
    password = user.password 
    db_user = models.User(email=user.email, password= password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

'''def create_reset_code(db: Session, code: schemas.ForgetPassword):
    email = code.email 
    db_code = models.Codes(email = email)
    db.add(db_code)
    db.commit()
    db.refresh(db_code)
    return db_code
'''
def add_patient(db: Session, patient: schemas.AddPatient, user_id:int):
    full_name=patient.full_name
    db_patient = models.Patient(full_name=full_name, gender=patient.gender,
         address=patient.address,mobile_number= patient.mobile_number)
    db.add(db_patient)
    db.commit()
    db.refresh(db_patient)
    return db_patient

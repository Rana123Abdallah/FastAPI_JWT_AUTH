"""
This module defines Pydantic models for use in a FastAPI application.
"""

import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel,constr, EmailStr, validator
from sqlalchemy import union

class Config:
    """
    Pydantic configuration for enabling ORM mode and allowing arbitrary types.
    """
    orm_mode = True
    arbitrary_types_allowed = True

class Settings(BaseModel):
    authjwt_secret_key:str='98af08c0018e5631e24864709e12d456035c2c5162ac1e8ad4a1a44cd3a92172'
    


class CreateUserRequest(BaseModel):
    username: str = ...
    email:EmailStr = ...
    password:constr(min_length=8, max_length=32) = ...
    patients: List[str] = []

    class Config:
        orm_mode = True


class UserData(BaseModel):
    id : int
    username: str 
    email:EmailStr

    class Config:
        orm_mode = True  


class ProfileDataBase(BaseModel):
    doctorname: str 
    #doctor_image: Optional[bytes]
    specialization: str
    years_of_experience: int
    phone_number: constr(min_length=11, max_length=11)
    number_of_patients: Optional[int]
    doctor_image: Optional[str]  
    class Config:
        orm_mode = True



class LoginModel(BaseModel):
    email:EmailStr
    password:constr(min_length=8, max_length=32)


class ResetPasswordRequest(BaseModel):
    new_password: constr(min_length=8, max_length=32)
    confirmed_password: str 
     

class ForgetPasswordRequest(BaseModel):
    email:EmailStr

class CreateVerifyCode(BaseModel):
    email:EmailStr
    verification_code: int



class VerifyCode(BaseModel):
    verification_code: int



class Patient(BaseModel):
    id:int
    full_name : str
    gender : str
    address :str
    mobile_number : constr(min_length=11, max_length=11)

    class Config:
        orm_mode = True

class AddPatient(BaseModel):
    full_name : str
    gender : str
    address :str
    mobile_number : constr(min_length=11, max_length=11)
    @validator('mobile_number')
    def validate_mobile_number(cls, value):
        if not value.isdigit():
            raise ValueError('mobile number should only contain digits')
        return value
    class Config:
        orm_mode = True


class GetPatient(BaseModel):
    full_name : str


class DeletePatient(BaseModel):
    full_name : str


class MedicalRecord(BaseModel):
    result : str
    #patient_id : int
    date: datetime.datetime



    class Config:
        orm_mode = True,
        arbitrary_types_allowed = True
        

        

class AddMedicalRecord(BaseModel):
    result : str
    patient_id : int

    class Config:
        orm_mode = True
        arbitrary_types_allowed = True

class Patient(Patient):
    medical_records: List[MedicalRecord] = []

    def medical_records_with_message(self):
        if not self.medical_records:
            return [{"message": "This patient doesn't have any medical records yet"}]
        else:
            return self.medical_records

    def dict(self, **kwargs):
        if not self.medical_records:
            return super().dict(**kwargs) | {"medical_records": self.medical_records_with_message()}
        else:
            return super().dict(**kwargs)


    
    class Config:
        orm_mode = True

class PatientWithMedicalRecord(BaseModel):
    status:bool
    message:str
    patient: Patient
    #medical_record: MedicalRecord

    class Config:
        orm_mode = True

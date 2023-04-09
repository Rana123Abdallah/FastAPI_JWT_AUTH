from ast import List
from enum import Enum
from typing import List
from pydantic import BaseModel, BaseSettings, Field, constr, validator
from pydantic.networks import EmailStr
from sqlalchemy import TEXT, TIMESTAMP
class Config:
        arbitrary_types_allowed = True

class CreateUserRequest(BaseModel):
    username: str = ...
    email:EmailStr = ...
    password:constr(min_length=8, max_length=32) = ...
    patients: List[str] = []

    class Config:
        orm_mode = True


class Settings(BaseModel):
    authjwt_secret_key:str='98af08c0018e5631e24864709e12d456035c2c5162ac1e8ad4a1a44cd3a92172'
    #ALGORITHM = "HS256"
    #ACCESS_TOKEN_EXPIRE_MINUTES = 1440

class LoginModel(BaseModel):
    email:EmailStr
    password:constr(min_length=8, max_length=32)


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None

class CreateNewPassword(BaseModel):
    new_password: constr(min_length=8, max_length=32)
    confirm_password: str = Field(..., alias='password')
     

class ForgetPasswordRequest(BaseModel):
    email:EmailStr


class ResetPasswordRequest(BaseModel):
    password: constr(min_length=8, max_length=32)
    #email:EmailStr
    #verification_code: int

'''class Gender(str,Enum):
    MALE="Male"
    FEMALE="Female"'''

class Patient(BaseModel):
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
    class Config:
        orm_mode = True


        

class AddPatientUser(BaseModel):
    user_id : int
    full_name : str
    gender : str
    address :str
    mobile_number : constr(min_length=11, max_length=11)

    class Config:
        orm_mode = True

class GetPatient(BaseModel):
    full_name : str


class DeletePatient(BaseModel):
    full_name : str
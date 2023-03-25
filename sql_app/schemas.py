from pydantic import BaseModel, BaseSettings
from pydantic.networks import EmailStr
from sqlalchemy import TEXT, TIMESTAMP
class Config:
        arbitrary_types_allowed = True

class CreateUserRequest(BaseModel):
    username: str
    email:str
    password:str


class Settings(BaseModel):
    authjwt_secret_key:str='98af08c0018e5631e24864709e12d456035c2c5162ac1e8ad4a1a44cd3a92172'

class LoginModel(BaseModel):
    email:str
    password:str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None

class ForgetPassword(BaseModel):
    email:str
    
class AddPatient(BaseModel):
    full_name : str
    gender : str
    address :str
    mobile_number : str

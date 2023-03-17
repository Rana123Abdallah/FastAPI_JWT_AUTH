from pydantic import BaseModel, BaseSettings


class CreateUserRequest(BaseModel):
    username: str
    email: str
    password:str


class Settings(BaseModel):
    authjwt_secret_key:str='98af08c0018e5631e24864709e12d456035c2c5162ac1e8ad4a1a44cd3a92172'

class LoginModel(BaseModel):
    email: str
    password:str

class ForgetPassword(BaseModel):
    email : str
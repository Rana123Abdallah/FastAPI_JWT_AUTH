from logging import currentframe
from os import access, stat
from fastapi import FastAPI,Depends,status
from fastapi.exceptions import HTTPException
from pydantic import BaseModel
from typing import List
from fastapi_jwt_auth import AuthJWT
from starlette.status import HTTP_401_UNAUTHORIZED

app = FastAPI()

class Settings(BaseModel):
    authjwt_secret_key:str='008357bb2bd823bc5d5fd41ca6823261ef57712146e22250abb44ad3c88b1970'


@AuthJWT.load_config
def get_config():
    return Settings()


@app.get("/")
def index():
    return {"Message":"Hello"}


class User(BaseModel):
    username:str
    email:str
    password:str

    class Config:
        schema_extra={
            "example":{
                "username":"Rana Abdallah",
                "email":"rana@gmail.com",
                "password":"password"
            }
        }
users=[]

class UserLogin(BaseModel):
    username:str
    password:str

    class Config:
        schema_extra={
            "example":{
                "username":"Rana Abdallah",
                "password":"password"
            }
        }



users=[]

#create a user
@app.post('/signup',status_code=201)
def create_user(user:User):
    new_user={
        "username":user.username,
        "email":user.email,
        "password":user.password
    }

    users.append(new_user)

    return new_user

#getting all users
@app.get('/users',response_model=List[User])
def get_users():
    return users

@app.post('/login')
def login(user:UserLogin,Authorize:AuthJWT=Depends()):
    for u in users:
        if (u["username"]==user.username) and (u["password"]==user.password):
            access_token=Authorize.create_access_token(subject=user.username)
            

            return {"access_token":access_token}

        raise HTTPException(status_code='401',detail="Invalid username or password")
    

@app.get('/protected')
def get_logged_in_user(Authorize:AuthJWT=Depends()):
    try:
        Authorize.jwt_required()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid token")


    current_user=Authorize.get_jwt_subject()

    return {"current_user":current_user}

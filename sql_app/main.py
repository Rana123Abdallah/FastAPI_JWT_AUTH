from logging import currentframe
from os import access, stat
from fastapi import FastAPI,Depends,status,Form
from sqlalchemy.orm import Session
from fastapi.exceptions import HTTPException
from pydantic import BaseModel
from typing import List
from fastapi_jwt_auth import AuthJWT
from starlette.status import HTTP_401_UNAUTHORIZED
from sql_app.database import get_db
from  sql_app.models import User
from  . import  models, schemas
from sql_app.schemas import CreateUserRequest,LoginModel

app = FastAPI()

@app.post("/signup")
def create(details: CreateUserRequest, db: Session = Depends(get_db)):
    to_create = User(
        username=details.username,
        email=details.email,
        password=details.password
    )
    db.add(to_create)
    db.commit()
    return { 
        "success": True,
        "created_id": to_create.id
    }
'''@app.post('/login')
def login(user:LoginModel,Authorize:AuthJWT=Depends()):
    db_user=db.query(User).filter(User.username==user.username).first()

    for user in User:
        if (u["username"]==user.username) and (u["password"]==user.password):
            
            return {"username":user.username}

        raise HTTPException(status_code='401',detail="Invalid username or password")
  '''  
@app.get("/user")
def get_by_id(id: int, db: Session = Depends(get_db)):
    return db.query(User).filter(User.id == id).first()

@app.delete("delete_user")
def delete(id: int, db: Session = Depends(get_db)):
    db.query(User).filter(User.id == id).delete()
    db.commit()
    return { "success": True }
'''
@app.post("/users/", response_model=schemas.CreateUserRequest)
def create_user(user: schemas.CreateUserRequest, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return crud.create_user(db=db, user=user)
'''

'''@app.get("/users/", response_model=list[schemas.CreateUserRequest])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    users = crud.get_users(db, skip=skip, limit=limit)
    return users
'''

'''@app.get("/users/{user_id}", response_model=schemas.CreateUserRequest)
def read_user(user_id: int, db: Session = Depends(get_db)):
    db_user = crud.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user
'''
'''class Settings(BaseModel):
    authjwt_secret_key:str='008357bb2bd823bc5d5fd41ca6823261ef57712146e22250abb44ad3c88b1970'

'''
'''
@AuthJWT.load_config
def get_config():
    return Settings()

'''
'''@app.get("/")
def index():
    return {"Message":"Hello"}
'''

'''class User(BaseModel):
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
'''
'''class UserLogin(BaseModel):
    username:str
    password:str

    class Config:
        schema_extra={
            "example":{
                "username":"Rana Abdallah",
                "password":"password"
            }
        }
'''


#users=[]

#create a user
'''@app.post('/signup',status_code=201)
def create_user(user:User):
    new_user={
        "username":user.username,
        "email":user.email,
        "password":user.password
    }

    users.append(new_user)

    return new_user
'''
#getting all users
'''@app.get('/users',response_model=List[User])
def get_users():
    return users
'''

'''@app.post('/login')
def login(user:UserLogin,Authorize:AuthJWT=Depends()):
    for user in User:
        if (u["username"]==user.username) and (u["password"]==user.password):
            
            return {"username":user.username}

        raise HTTPException(status_code='401',detail="Invalid username or password")
   ''' 

'''@app.get('/protected')
def get_logged_in_user(Authorize:AuthJWT=Depends()):

    try:
        Authorize.jwt_required()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid token")


    current_user=Authorize.get_jwt_subject()

    return {"current_user":current_user}
    '''

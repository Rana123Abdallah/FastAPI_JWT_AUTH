import dbm
from logging import currentframe
from os import access, stat
import time
from fastapi import FastAPI,Depends, Request,status,Form
from sqlalchemy.orm import Session
from fastapi.exceptions import HTTPException
from pydantic import BaseModel, EmailStr
from typing import List
from fastapi_jwt_auth import AuthJWT
from starlette.status import HTTP_401_UNAUTHORIZED
from sql_app.database import get_db
from  sql_app.models import User
from  . import  models, schemas
from sql_app.schemas import CreateUserRequest,LoginModel,Settings, ForgetPassword
from fastapi.encoders import jsonable_encoder
from fastapi.security import  OAuth2PasswordRequestForm
from werkzeug.security import generate_password_hash , check_password_hash
import uuid
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware


description = """
ChimichangApp API helps you do awesome stuff. 🚀

## Users

You will be able to:

* **Create users** (_not implemented_).
* **Read users** (_not implemented_).
"""


tags_metadata = [
    {
        "name": "users",
        "description": "Operations with users. The **login** logic is also here.",
    },
]
app = FastAPI(

   title="ChimichangApp",
    description=description,
    version="0.0.1",
    terms_of_service="http://example.com/terms/",
    contact={
        "name": "Deadpoolio the Amazing",
        "url": "http://x-force.example.com/contact/",
        "email": "dp@x-force.example.com",
    },
    license_info={
        "name": "Apache 2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
    },

    openapi_tags = tags_metadata,
    openapi_url="/api/v1/openapi.json",
    docs_url="/documentation", 
    #redoc_url=None,

)

class MyMiddleware(BaseHTTPMiddleware):
     async def dispatch(self, request: Request, call_next):
         start_time = time.time()
         response = await call_next(request)
         process_time = time.time() - start_time
         response.headers["X-Process-Time"] = str(process_time)
         return response
     
app.add_middleware(MyMiddleware)

origins = [
    "http://localhost.tiangolo.com",
    "https://localhost.tiangolo.com",
    "http://localhost",
    "http://localhost:4000",
    "http://localhost:3000",
    "http://localhost:8080",
    "http://localhost:8000/signup/"
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
    

     
@app.get("/")
async def read_root():
    return {"Welocome to our FASTAPI project ": "have a nice time"}


@AuthJWT.load_config
def get_config():
    return Settings()


@app.post("/signup",tags=["users"])
async def create(details: CreateUserRequest, db: Session = Depends(get_db)):
    db_user= db.query(User).filter(User.email==details.email).first()
    if db_user :
      raise HTTPException(status_code=404,detail="Email already registerd")
    else:
        to_create = User(
            username=details.username,
            email=details.email,
            password=generate_password_hash(details.password)
        )

        db.add(to_create)
        db.commit()
        return { 
            "message": "Succesful",
            "created_id": to_create.id
        }

   
  


@app.post('/login',tags=["users"])
def login(details:LoginModel,Authorize:AuthJWT=Depends(), db: Session = Depends(get_db)):
    db_user= db.query(User).filter(User.email==details.email).first()
    
    if db_user and check_password_hash(db_user.password, details.password):

        access_token=Authorize.create_access_token(subject=db_user.username)
        refresh_token=Authorize.create_refresh_token(subject=db_user.username)

        response={
            "access":access_token,
            "refresh":refresh_token
        }
        return jsonable_encoder(response)
   
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Invalid email or password")



@app.post('/forget-password/')
def forget_password (details:ForgetPassword,db: Session = Depends(get_db)):
    #check user exist
    db_user= db.query(User).filter(User.email==details.email).first()
    if not db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="User not found")
    
    #create reset pass and save in the database
    reset_code =str(uuid.uuid1()) 
    return reset_code


@app.get("/user/", tags=["users"])
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

from datetime import timedelta
import dbm
import email
import html
from os import access, stat
import os
import time
from anyio import Path
from fastapi import BackgroundTasks, FastAPI,Depends, Request,status,Form
from sqlalchemy.orm import Session
from fastapi.exceptions import HTTPException
from pydantic import BaseModel, ConfigDict, EmailStr
from typing import List
from fastapi_jwt_auth import AuthJWT
from jose import JWTError, jwt
from passlib.context import CryptContext
from starlette.status import HTTP_401_UNAUTHORIZED
from sql_app.database import Base, get_db
from  sql_app.models import Codes, Patient, User
from  . import  models, schemas, crud
from sql_app.schemas import AddPatient, AddPatientUser, CreateNewPassword, CreateUserRequest, ForgetPasswordRequest,LoginModel, ResetPasswordRequest,Settings
from fastapi.encoders import jsonable_encoder
from fastapi.security import  OAuth2PasswordRequestForm, OAuth2PasswordBearer
from werkzeug.security import generate_password_hash , check_password_hash
import uuid
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from starlette.responses import JSONResponse
from starlette.requests import Request
from starlette.config import Config

description = """ 
ChimichangApp API helps you do awesome stuff. 🚀

## Users

You will be able to:

* **Create users** (_not implemented_).
* **Read users** (_not implemented_).
"""


tags_metadata = [
    {
        "name": "patient",
        "description": "Operations with patients.",
        "name": "users",
        "description": "Operations with users. The **login** logic is also here.",
        
    },
]

class EmailSchema(BaseModel):
    email: List[EmailStr]


config = Config("env")
print("========================")
print("========================")

#conf = ConnectionConfig(
   # MAIL_USERNAME=getattr(config, "MAIL_USERNAME", "default_username"),
   # MAIL_PASSWORD=getattr(config, "MAIL_PASSWORD", "default_password"),
   # MAIL_FROM=getattr(config, "MAIL_FROM", "default_from"),
   # MAIL_PORT=getattr(config, "MAIL_PORT", 587),
   # MAIL_SERVER=getattr(config, "MAIL_SERVER", "smtp.gmail.com"),
   # MAIL_FROM_NAME=getattr(config, "MAIL_FROM_NAME", "default_from_name"),
   # MAIL_STARTTLS=bool = True,
   # MAIL_SSL_TLS =bool = False,
   # MAIL_SSL=False,
   # USE_CREDENTIALS=True,
#)
    







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

#origins = []
'''    "http://localhost.tiangolo.com",
    "https://localhost.tiangolo.com",
    "http://localhost",
    "http://localhost:4000",
    "http://localhost:3000",
    "http://localhost:3001",
    "http://localhost:8080",
    "http://localhost:8000/signup/",
    "http://localhost:57909/"'''


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token") 

def verify_password(plain_password, password):
    return pwd_context.verify(plain_password, password)



@app.post("/email",tags=["users"])
async def simple_send(email: EmailSchema) -> JSONResponse:
    html = """<p>Hi this test mail, thanks for using Fastapi-mail</p> """

    message = MessageSchema(
        subject="Fastapi-Mail module",
        recipients=email.dict().get("email"),
        body=html,
        subtype=MessageType.html
        )
      
        

    fm = FastMail(ConfigDict)
    await fm.send_message(message)
    return JSONResponse(

        status_code=200, 
        content={"message": "We have sent an email with instructions to reset your password "}
    )





@app.get("//")
async def root(db: Session = Depends(get_db)):
    Base.metadata.drop_all(bind=db.bind)

@app.get("//")
async def main (request: Request):
    client_host = request.client.host
    client_port  = request.client.port
    request_url = request.url.path

    return{
        "client_host": client_host,
        "client_port": client_port,
        "request_url": request_url

    }


@app.get("/")
async def read_root(Authorize:AuthJWT=Depends()):
    try:
        Authorize.jwt_required()

    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Token"
        )

    
    return {"Welocome to our FASTAPI project ": "have a nice time"}


@AuthJWT.load_config
def get_config():
    return Settings()



@app.post("/signup",tags=["users"])
async def create(details: CreateUserRequest, db: Session = Depends(get_db)):
    db_email = db.query(User).filter(User.email==details.email).first()
    
    if db_email is not None :
      return HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registerd"
        )
    
    db_username = db.query(User).filter(User.username==details.username).first()

    if db_username is not None:
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with the username already exists so try to Change your username"
        )

    to_create = User(
         username=details.username,
         email=details.email,
         password=generate_password_hash(details.password)
    )

    db.add(to_create)
    db.commit()
    return { 
         "message": "Congratulation!! Successfully Register",
        # "created_id": to_create.id
    }
#*********************************************************************************************

@app.post('/login',tags=["users"])
def login(details:LoginModel,Authorize:AuthJWT=Depends(), db: Session = Depends(get_db)):
   try:
        db_user= db.query(User).filter(User.email==details.email).first()

        if db_user and check_password_hash(db_user.password, details.password):

            access_token=Authorize.create_access_token(subject=db_user.username)
            #refresh_token=Authorize.create_refresh_token(subject=db_user.username)

            response={
                "message": "Successfull Login",
                "token":access_token,
                #"refresh":refresh_token
            }
            return jsonable_encoder(response)
    
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or password"
        )
   
   except Exception as e:
        
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or password")

#********************************************************************************************8
@app.get('/refresh',tags=["users"])
async def refresh_token(Authorize:AuthJWT=Depends()):
    """
    ## Create a fresh token
    This creates a fresh token. It requires an refresh token.
    """


    try:
        Authorize.jwt_refresh_token_required()

    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Please provide a valid refresh token"
        ) 

    current_user=Authorize.get_jwt_subject()

    
    access_token=Authorize.create_access_token(subject=current_user)

    return jsonable_encoder({"access":access_token})




# ***********************************************************************************************
import random
import smtplib

def generate_verification_code():
    # Generate a random 4-digit verification code
    return str(random.randint(1000, 9999))

def send_verification_code(email):
    # Generate a verification code
    verification_code = generate_verification_code()

    # Set up the SMTP server
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_username = "ranoshah1233@gmail.com"
    smtp_password = "lnxjsjqwwnisvvzf"

    # Create the email message
    message = f"Your verification code is {verification_code}"
    sender_email = "ranoshah1233@gmail.com"
    receiver_email = "ra4329530@gmail.com"
    subject = 'Verify Your Code Dear!'
    msg = f'Subject: {subject}\n\n{message}'

    # Log in to the SMTP server and send the email
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(sender_email, receiver_email, msg)
    return verification_code

# Example usage
#send_verification_code("ra4329530@gmail.com")

def verify_verification_code(email, verification_code):
    # Your code to verify the verification code goes here
    # Set up the SMTP server
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_username = "ranoshah1233@gmail.com"
    smtp_password = "lnxjsjqwwnisvvzf"

    # Log in to the SMTP server and send the email
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)

        # Check if the code matches the one sent in the email
        message = f"Your verification code is {verification_code}"
        sender_email = "ranoshah1233@gmail.com"
        receiver_email = email

        if message in server.sendmail(sender_email, receiver_email, message):
            return True
        else:
            return False


def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def update_password(db: Session,email: str, password: str):
    user = get_user_by_email(email)
    if user:
        return db.query(models.User).filter(models.User.email == email).update({"password": password})
        #return {"message": "Your password has been updated successfully."}
    else:
        return {"message": "User not found."}

# **********************************************************************************************


@app.post('/forget-password/',tags=["users"])
async def forget_password (details:ForgetPasswordRequest,db: Session = Depends(get_db)):
    #check user exist
    db_user= db.query(User).filter(User.email==details.email).first()
    if not db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="User with this email not found, Check that this email which you had registered .")
    
    code = send_verification_code(details.email)
    return { 
         "message": " Check your email we send you a 4-digit verification code ",
        
    }
 ###############################################################################

@app.post("/reset_password/",tags=["users"])
async def reset_password(details:ResetPasswordRequest,db: Session = Depends(get_db)):
   
   # Verify code
   if verify_verification_code(email, verification_code):
        # Update password
        hashed_password = generate_password_hash(details.password)
        db_user = db.query(User).filter(User.email == details.email).first()
        db_user.password = hashed_password
        db.commit()

        # Return response
        return {
            "message": "Password updated successfully",
        }
   else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Incorrect verification code")


@app.post('/forget-password/',tags=["users"])
async def forget_password (details:ForgetPasswordRequest,db: Session = Depends(get_db)):
    #check user exist
    db_user= db.query(User).filter(User.email==details.email).first()
    if not db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="User not found.")
    
    #create reset pass and save in the database
    reset_code =str(uuid.uuid1()) 
    
    to_create = Codes(
         reset_code = reset_code,
         email=details.email,
         
    )

    db.add(to_create)
    db.commit()
    #return db_code
    #await crud.create_reset_code(reset_code, email =details.email )
   # return reset_code
     
    #db.add(details.email ,reset_code)
    #db.commit()
    return reset_code 
    
@app.post('/new-password/',tags=["users"])
async def create_new_password (details:CreateNewPassword,db: Session = Depends(get_db)):
    db_user= db.query(User).filter(User.password==details.new_password).first()
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Your new password must be different from previously used password"
        )

    else:
        new_password = generate_password_hash(details.new_password)
        db.query(User).filter(User.password == 'password').update({'password':'new_password'})
        db.commit()
        
    return { 
         "message": "Congratulation!! Successfully Changed password",
        
    }



@app.get("/user/", tags=["users"])
def get_by_id(id: int, db: Session = Depends(get_db)):
    return db.query(User).filter(User.id == id).first()



@app.delete("/delete_user/",tags=["users"])
def delete(id: int, db: Session = Depends(get_db)):
    db.query(User).filter(User.id == id).delete()
    db.commit()
    return { "success": " The user has been deleted" }


# ********************************************************************************************************* 

# Add new patient
@app.post("/users/{user_id}/patient",tags=["patient"])
async def add(details :AddPatientUser, db: Session = Depends(get_db)):
    to_add_patient = Patient(
         full_name=details.full_name,
         gender=details.gender,
         address=details.address,
         mobile_number = details.mobile_number
        
    )
    db.add(to_add_patient)
    db.commit()
    return { 
         "message": "Congratulation!! Successfully Submited",
         #"created_id": to_add_patient.id
    }


#getting  patient with his name
@app.get("/patient/", tags=["patient"])
def get_by_fullname(full_name: str, db: Session = Depends(get_db)):
    return db.query(Patient).filter(Patient.full_name == full_name).first()


#getting all patients
@app.get('/patients',tags=["patient"])
def get_patients(db: Session = Depends(get_db)):
    patients = db.query(models.Patient).all()
    return {"status": True, "message": None, "patients": [schemas.Patient.from_orm(patient) for patient in patients]}


#Deleting patient with his name
@app.delete("/delete_patient/",tags=["patient"])
def delete(full_name: str, db: Session = Depends(get_db)):
    db.query(Patient).filter(Patient.full_name == full_name).delete()
    db.commit()
    return { "success": " The patient has been deleted" }

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

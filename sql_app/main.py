from datetime import timedelta
import dbm
import email
import html
from os import access, stat
import os
import time
from anyio import Path
from fastapi import BackgroundTasks, FastAPI,Depends, Header, Request,status,Form
from flask import session
from sqlalchemy.orm import Session
from fastapi.exceptions import HTTPException
from pydantic import BaseModel, ConfigDict, EmailStr
from typing import Annotated, List
from fastapi_jwt_auth import AuthJWT
from jose import JWTError, jwt
from passlib.context import CryptContext
from starlette.status import HTTP_401_UNAUTHORIZED
from sql_app.database import Base, SessionLocal, get_db
from  sql_app.models import Codes, MedicalRecord, Patient, User
from  . import  models, schemas, crud
from sql_app.schemas import AddMedicalRecord, AddPatient, AddPatientUser, CreateNewPassword, CreateUserRequest, DeletePatient, ForgetPasswordRequest, GetPatient,LoginModel, ResetPasswordRequest,Settings
from fastapi.encoders import jsonable_encoder
from fastapi.security import  OAuth2PasswordRequestForm, OAuth2PasswordBearer,OAuth2AuthorizationCodeBearer
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
## This app helps doctor to make easy prediction for GP-Respiratory Disease based on Machine Learning model. 🚀

## Users have to be doctors not patient to use this app .

## You will be able to:

* **Create users**. 
* **Read users**.
* **other operations on patients that added by doctors " Users"**.
* **As create & get & delete patient**.

"""


tags_metadata = [
    {
        "name" : "Patient with logged user",
        "description": "Operations with patients that created by the currently logged in users",
        "name": "patient",
        "description": "Operations with patients.",
        "name": "User",
        "description": "Operations with users. The **logic** protected is also here.",
        
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

   title="GP-Respiratory Disease",
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
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login") 

def verify_password(plain_password, password):
    return pwd_context.verify(plain_password, password)



@app.post("/email",tags=["User"])
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





'''@app.get("//")
async def root(db: Session = Depends(get_db)):
    Base.metadata.drop_all(bind=db.bind)
'''
@app.get("//",tags=["User"])
async def main_client(request: Request):
    client_host = request.client.host
    client_port  = request.client.port
    request_url = request.url.path

    return{
        "client_host": client_host,
        "client_port": client_port,
        "request_url": request_url

    }


@app.get("/",tags=["User"])
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



@app.post("/signup",tags=["User"])
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

@app.post('/login',tags=["User"])
def login(details:LoginModel,Authorize:AuthJWT=Depends(), db: Session = Depends(get_db)):
   #try:
        db_user= db.query(User).filter(User.email==details.email).first()
        if not db_user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
            detail=" Sorry!! Invalid email , try again with the email which had been registered"
            )
        db_password = check_password_hash(db_user.password, details.password)
        if not db_password:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                    detail=" Sorry!! Invalid password , try again with the correct password"
                )
        
        if db_user and check_password_hash(db_user.password, details.password):

            access_token=Authorize.create_access_token(subject=db_user.id,expires_time=timedelta(minutes=1440.0))
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
   
   
'''except Exception as e:
        
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or password")
'''





#**************************************************************************************************


@app.get('/protected',tags=["User"])
def get_logged_in_user(Authorize:AuthJWT=Depends()):

    try:
        Authorize.jwt_required()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid token")


    current_user=Authorize.get_jwt_subject()

    return {"current_user":current_user}



#********************************************************************************************
@app.post("/logout",tags=["User"])
def user_logout(Authorization: str = Header(None)):
    oauth2_scheme.revoke_token(Authorization)
    return {"message": "Token revoked"}




#******************************************************************************************************************
@app.get('/refresh',tags=["User"])
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


@app.post('/forget-password/',tags=["User"])
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

@app.post("/reset_password/",tags=["User"])
async def reset_password(details:ResetPasswordRequest,db: Session = Depends(get_db)):
   
   # Verify code
   '''if verify_verification_code(email, verification_code):
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
                            detail="Incorrect verification code")'''


@app.post('/forget-password/',tags=["User"])
async def create_reset_code (details:ForgetPasswordRequest,db: Session = Depends(get_db)):
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
    
@app.post('/new-password/',tags=["User"])
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



@app.get("/user/", tags=["User"])
def get_by_id(id: int, db: Session = Depends(get_db)):
    return db.query(User).filter(User.id == id).first()



@app.delete("/delete_user/",tags=["User"])
def delete(id: int, db: Session = Depends(get_db)):
    db.query(User).filter(User.id == id).delete()
    db.commit()
    return { "success": " The user has been deleted" }


# ********************************************************************************************************* 


#Add New Patient by current user
@app.post("/patients",tags=["Patient with logged user"])
def create_patient(details: AddPatient,Authorize:AuthJWT=Depends(), db: Session = Depends(get_db)):

    """
        ## Add New Patient by current user
        
    """
    try:
        Authorize.jwt_required()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid token")

    current_user=Authorize.get_jwt_subject()
    user=db.query(User).filter(User.id==current_user).first()


    new_patient = Patient(
         full_name=details.full_name,
         gender=details.gender,
         address=details.address,
         mobile_number = details.mobile_number
        
     )
    new_patient.user = user
    db.add(new_patient)
    db.commit()
    return { 
         "message": "Congratulation!! Successfully Submited",
         "created_id": new_patient.id
    }
#*************************************************************************************************************



#Get a current user's patients
@app.get('/user/patients', tags=["Patient with logged user"])
async def get_user_patients(Authorize:AuthJWT=Depends(),db: Session = Depends(get_db) ):
    """
        ## Get a current user's patients
        This lists the patients created by the currently logged in users
    
    """
    try:
        Authorize.jwt_required()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Token"
        )

    user = Authorize.get_jwt_subject()

    current_user=db.query(User).filter(User.id==user).first()

    #return jsonable_encoder(current_user.patients)
    return {"status": True, "message": None, "patients": [schemas.Patient.from_orm(patient) for patient in current_user.patients]}

        


#********************************************************************************************************************

#Get a specific patient by the currently logged in user
@app.get('/user/patient/{full_name}/',tags=["Patient with logged user"])
async def get_specific_patient(full_name:str,Authorize:AuthJWT=Depends(),db: Session = Depends(get_db)):
    """
        ## Get a specific patient by the currently logged in user
        This returns an patient by FULL_NAME for the currently logged in user
    
    """
    try:
        Authorize.jwt_required()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Token"
        )

    user=Authorize.get_jwt_subject()

    current_user=db.query(User).filter(User.id==user).first()


    patients=current_user.patients
    for o in patients:
        if o.full_name == full_name:
           return {"status": True, "message": None, "patient": [schemas.Patient.from_orm(o)]}
    
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
        detail="No patient with such full_name existed"
    )

#*****************************************************************************************************************************
#Delete an patient
@app.delete('/patient/delete/',tags=["Patient with logged user"])
async def delete_specific_patient(details:DeletePatient,Authorize:AuthJWT=Depends(),db :Session= Depends(get_db)):

    """
        ## Delete an patient
        This deletes an patient by its fullname
    """

    try:
        Authorize.jwt_required()

    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid Token")

    '''user=Authorize.get_jwt_subject()

    current_user=db.query(User).filter(User.id==user).first()
    patients=current_user.patients'''
    patient_to_delete=db.query(Patient).filter(Patient.full_name==details.full_name).first()
    if patient_to_delete:
       db.delete(patient_to_delete)
       db.commit()
        # return order_to_delete
       return { "success": " The patient has been deleted" }
          
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="This Patient is not exist "
        )
       


#**********************************************************************************************************************

@app.post("/patient/medical_record",tags=["Patient with logged user"])
def create_patient(details: AddMedicalRecord,Authorize:AuthJWT=Depends(), db: Session = Depends(get_db)):

    """
        ## Add New Medical Record to this patient by current user
        Remember you need to save the return id from the submitted patient you added
        
    """
    try:
        Authorize.jwt_required()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid token")

    current_user=Authorize.get_jwt_subject()
    user=db.query(User).filter(User.id==current_user).first()


    new_Medical_Record = MedicalRecord(
         result=details.result,
         patient_id=details.patient_id,
     )
    db.add(new_Medical_Record)
    db.commit()
    return { 
         "message": "Congratulation!! Successfully Add Anew Medical Record to this patient ",
         
    }





















#getting  patient with his name
@app.get("/patient/{full_name}", tags=["patient"])
def get_by_fullname(full_name: str, db: Session = Depends(get_db)):
    patients = db.query(Patient).filter(Patient.full_name == full_name).first()
    return {"status": True, "message": None, "patients": [schemas.Patient.from_orm(patient) for patient in patients]}


#getting all patients
@app.get('/patients/{user_id}',tags=["patient"])
def get_patients(user_id:int,db: Session = Depends(get_db)):
    patients = db.query(models.Patient).filter(models.Patient.user_id == user_id).all()
    return {"status": True, "message": None, "patients": [schemas.Patient.from_orm(patient) for patient in patients]}


#Deleting patient with his name
@app.delete("/delete_patient/",tags=["patient"])
def delete(details:DeletePatient, db: Session = Depends(get_db)):
    db_patient= db.query(Patient).filter(Patient.full_name==details.full_name).first()
    if  not db_patient:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="This Patient is not exist "
        )
    db.query(Patient).filter(Patient.full_name == details.full_name).delete()
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

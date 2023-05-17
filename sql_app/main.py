"""
This module defines the endpoints for a FastAPI-based web 
application that allows doctors to make predictions for 
GP-Respiratory Disease using a Machine Learning model.
"""

import base64
import io
import logging
import os
import time
from datetime import datetime, timedelta
import random
import smtplib
from typing import Optional
import uuid

from fastapi import FastAPI, Depends, Form, Header, HTTPException, Request, status, File, UploadFile
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi_jwt_auth import AuthJWT
from fastapi.responses import FileResponse
from fastapi.responses import StreamingResponse
from pydantic import ValidationError
from sqlalchemy import func
from PIL import Image

from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from werkzeug.security import generate_password_hash, check_password_hash
from sql_app import models, schemas, crud
from sql_app.database import SessionLocal, get_db
from sql_app.models import MedicalRecord, Patient, ProfileData, User, VerificationCode
from sql_app.schemas import (
    AddMedicalRecord,
    AddPatient,
    CreateUserRequest,
    DeletePatient,
    ForgetPasswordRequest,
    LoginModel,
    ProfileDataBase,
    ResetPasswordRequest,
    Settings,
    VerifyCode,
)

DESCRIPTION = """
## This app helps doctors make easy predictions for Respiratory Disease using a Machine Learning model. 🚀

## Users must be doctors, not patients, to use this app.

## You will be able to:

* **Create users**.
* **Read users**.
* **Perform other operations on patients that have been added by doctors ("Users").**
* **Create, read, and delete patients.**
"""

tags_metadata = [
    {
        "name": "User",
        "description": "Operations with users. The **logic** protected is also here.",
    },
    {
        "name": "Patient with logged user",
        "description": "Operations with patients that created by the currently logged in users",
    },
    {"name": "patient", "description": "Operations with patients."},
]


IMAGEDIR = "Images/"

app = FastAPI(
    title="GP-Respiratory Disease",
    description=DESCRIPTION,
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
    openapi_tags=tags_metadata,
    openapi_url="/api/v1/openapi.json",
    docs_url="/documentation",
    # redoc_url=None,
)


class MyMiddleware(BaseHTTPMiddleware):
    """
    Middleware that adds an X-Process-Time header
    to the response with the time it took to process the request.
    Usage:

    Add this middleware to your FastAPI application by including it in the list of middleware
    in your app's constructor:

    app = FastAPI()
    app.add_middleware(MyMiddleware)

    This will add the middleware to your application and automatically include the X-Process-Time
    header in all responses.
    """

    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(process_time)
        return response


app.add_middleware(MyMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["User"])
async def read_root(authorize: AuthJWT = Depends()):
    """
    Root endpoint that requires a valid JWT token for authentication.

    param Authorize: An instance of the AuthJWT class that is used for authentication.
    return: A JSON response with a welcome message.
    """
    try:
        authorize.jwt_required()

    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Token"
        ) from error

    return {"Welocome to our FASTAPI project ": "have a nice time"}


@AuthJWT.load_config
def get_config():
    """
    Loads the configuration settings for AuthJWT from a Settings object.

    return: A Settings object with the configuration settings for AuthJWT.
    """
    return Settings()


@app.post("/user/signup", tags=["User"])
async def create(details: CreateUserRequest, database: Session = Depends(get_db)):
    """
    Endpoint to create a new user in the database.

    param details: A CreateUserRequest object containing the user details.
    param db: A SQLAlchemy Session object used to interact with the database.
    return: A JSON response indicating whether the user was successfully created.
    """

    db_email = database.query(User).filter(User.email == details.email).first()

    if db_email is not None:
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registerd"
        )

    db_username = database.query(User).filter(User.username == details.username).first()

    if db_username is not None:
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with the username already exists so try to Change your username",
        )

    to_create = User(
        username=details.username,
        email=details.email,
        password=generate_password_hash(details.password),
    )

    database.add(to_create)
    database.commit()
    return {
        "message": "Congratulation!! Successfully Register",
         #"created_id": to_create.id,
         #"user_name": to_create.username
    }


# *********************************************************************************************


@app.post("/user/login", tags=["User"])
def login(
    details: LoginModel,
    authorize: AuthJWT = Depends(),
    database: Session = Depends(get_db),
):
    """
    Endpoint to log in a user with their email and password.

    return: A JSON response with an access token if the login is successful.
    """
    # try:
    db_user = database.query(User).filter(User.email == details.email).first()
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=" Sorry!! Invalid email , try again with the email which had been registered",
        )
    db_password = check_password_hash(db_user.password, details.password)
    if not db_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=" Sorry!! Invalid password , try again with the correct password",
        )

    if db_user and check_password_hash(db_user.password, details.password):
        access_token = authorize.create_access_token(
            subject=db_user.id, expires_time=timedelta(minutes=1440.0)
        )
        # refresh_token=Authorize.create_refresh_token(subject=db_user.username)

        response = {
            "message": "Successfull Login",
            "token": access_token,
            # "refresh":refresh_token
        }
        return jsonable_encoder(response)

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or password"
    )
#**************************************************************************************************
@app.post("/user/profiledata", tags=["User"])
async def create_profiledata(
    image_file: Optional[UploadFile] = File(None),
    details: str = Form(...),
    authorize: AuthJWT = Depends(),
    db: Session = Depends(get_db)
    ):
    """
    Endpoint to create a new profiledata object in the database.
    param image_file: An UploadFile object containing the image data.
    param details: A JSON-encoded string containing the profiledata details.
    param authorize: An AuthJWT dependency used to verify the validity of the JWT token.
    param db: A SQLAlchemy Session object used to interact with the database.
    return: A JSON response indicating whether the profiledata was successfully created.
    """


    try:
        authorize.jwt_required()
    except Exception as error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from error

    current_user = authorize.get_jwt_subject()
    user = db.query(User).filter(User.id == current_user).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not authorized to create profiledata for this user")

    db_profiledata = db.query(ProfileData).filter(ProfileData.user_id == user.id).first()
    if db_profiledata is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="ProfileData already exists for this user")

    # Parse the JSON object from the form data
    details_dict = json.loads(details)

    # Create a Pydantic model from the parsed JSON object
    details_model = ProfileDataBase(**details_dict)
    # If an image file is provided, resize it and save it to a directory
    if image_file is not None:
        image_file.filename = f"{uuid.uuid4()}.jpg"
        contents = await image_file.read()
        with Image.open(io.BytesIO(contents)) as img:
            img = img.resize((200, 200))
            if img.mode == "RGBA":  # Convert image to RGB mode if it is in RGBA mode
                img = img.convert("RGB")
            img.save(f"{IMAGEDIR}/{image_file.filename}")
        image_path = f"{IMAGEDIR}{image_file.filename}"
    else:
        image_path = None

    # Create a new ProfileData instance with the parsed details and the path to the saved image (if provided)
    to_create = ProfileData(
        doctorname=f"Dr. {details_model.doctorname}",
        specialization=details_model.specialization,
        years_of_experience=details_model.years_of_experience,
        phone_number=details_model.phone_number,
        number_of_patients=0,
        doctor_image=image_path,
        user_id=user.id
    )

    # Add the new ProfileData instance to the database
    db.add(to_create)
    db.commit()
    db.refresh(to_create)

    return {
        "message": "ProfileData created successfully"
    }
# **************************************************************************************************
@app.put("/user/profiledata/", tags=["User"])
async def edit_profiledata(
    image_file: Optional[UploadFile] = File(None),
    details: Optional[str] = Form(None),
    authorize: AuthJWT = Depends(),
    db: Session = Depends(get_db)
    ):
    """
    Endpoint to edit the user's profiledata in the database.
    param image_file: An optional UploadFile object containing the image data.
    param details: An optional JSON-encoded string containing the updated profiledata details.
    param authorize: An AuthJWT dependency used to verify the validity of the JWT token.
    param db: A SQLAlchemy Session object used to interact with the database.
    return: A JSON response indicating whether the profiledata was successfully updated.
    """

    try:
        authorize.jwt_required()
    except Exception as error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from error

    current_user = authorize.get_jwt_subject()
    user = db.query(User).filter(User.id == current_user).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not authorized to edit profiledata for this user")

    db_profiledata = db.query(ProfileData).filter(ProfileData.user_id == user.id).first()
    if not db_profiledata:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ProfileData does not exist for this user")

    if details is not None:
        # Parse the JSON object from the form data
        details_dict = json.loads(details)

        # Create a Pydantic model from the parsed JSON object
        details_model = ProfileDataBase(**details_dict)

        db_profiledata.doctorname = f"Dr. {details_model.doctorname}"
        db_profiledata.specialization = details_model.specialization
        db_profiledata.years_of_experience = details_model.years_of_experience
        db_profiledata.phone_number = details_model.phone_number

    if image_file is not None:
        image_file.filename = f"{uuid.uuid4()}.jpg"
        contents = await image_file.read()
        with Image.open(io.BytesIO(contents)) as img:
            img = img.resize((200, 200))
            if img.mode == "RGBA":  # Convert image to RGB mode if it is in RGBA mode
                img = img.convert("RGB")
            img.save(f"{IMAGEDIR}/{image_file.filename}")
        if db_profiledata.doctor_image:
            old_image_path = os.path.join(IMAGEDIR, db_profiledata.doctor_image)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)
        db_profiledata.doctor_image = f"{IMAGEDIR}{image_file.filename}"

    db.commit()
    db.refresh(db_profiledata)

    return {
        "message": "ProfileData updated successfully",
        "updated_id": db_profiledata.id
    }
#*************************************************************************************************
@app.get("/logged_user/profiledata", tags=["User"])
async def get_profiledata(
    authorize: AuthJWT = Depends(),
    db: Session = Depends(get_db)
):
    """
    Endpoint to retrieve the profiledata for the currently logged-in user.

    param authorize: An AuthJWT dependency used to verify the validity of the JWT token.
    param db: A SQLAlchemy Session object used to interact with the database.
    return: A JSON response containing the profiledata and the image for the currently logged-in user.
    """

    try:
        authorize.jwt_required()
    except Exception as error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from error

    current_user = authorize.get_jwt_subject()
    user = db.query(User).filter(User.id == current_user).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not authorized to access profiledata for this user")

    profiledata = db.query(ProfileData).filter(ProfileData.user_id == user.id).first()
    if not profiledata:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profiledata not found")

    # Construct the full path to the image file based on the relative path stored in the `doctor_image` attribute
    image_path = profiledata.doctor_image
    # Create a dict with the profiledata details
    profiledata_dict = {
    "doctorname": profiledata.doctorname,
    "specialization": profiledata.specialization,
    "years_of_experience": profiledata.years_of_experience,
    "phone_number": profiledata.phone_number,
    "number_of_patients": profiledata.number_of_patients,
    "doctor_image": profiledata.doctor_image
}
     # Return the profiledata and image as a JSON response
    return {
        "Message":f"The all information of {profiledata.doctorname}",
        "profiledata": profiledata_dict,
        
    }
    
#***************************************************************************************************
@app.get("/protected", tags=["User"])
def get_logged_in_user(authorize: AuthJWT = Depends()):
    """
    Endpoint to get the currently logged in user.

     param authorize: An instance of the AuthJWT class used for authentication.
     return: A JSON response with the ID of the currently logged in user.
    """
    try:
        authorize.jwt_required()
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        ) from error

    current_user = authorize.get_jwt_subject()

    return {"current_user": current_user}


# ****************************************************************************
@app.get("/refresh", tags=["User"])
async def refresh_token(authorize: AuthJWT = Depends()):
    """
    ## Create a fresh token
    This creates a fresh token. It requires an refresh token.
    """

    try:
        authorize.jwt_refresh_token_required()

    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Please provide a valid refresh token",
        ) from error

    current_user = authorize.get_jwt_subject()
    access_token = authorize.create_access_token(subject=current_user)

    return jsonable_encoder({"access": access_token})


# ***********************************************************************************************


def generate_verification_code():
    """
    # Generate a random 4-digit verification code
    """
    return random.randint(1000, 9999)


def send_verification_code(email: str, database: Session):
    """
    # Check if there is an existing verification code for the email
    """
    existing_code = database.query(VerificationCode).filter_by(email=email).first()
    if existing_code:
        # Return the existing verification code if it has not expired
        now = datetime.now().replace(microsecond=0)
        expires_at = existing_code.created_at + timedelta(
            minutes=10
        )  # Set expiration time to 10 minutes
        if now <= expires_at:
            return existing_code.verification_code

        # Delete the existing verification code if it has expired
        database.delete(existing_code)
        database.commit()
    # Generate a new verification code
    verification_code = generate_verification_code()
    now = datetime.now().replace(microsecond=0)
    expires_at = now + timedelta(minutes=10)  # Set expiration time to 10 minutes
    code = VerificationCode(
        email=email,
        verification_code=verification_code,
        created_at=now,
        expires_at=expires_at,
    )
    database.add(code)
    database.commit()
    database.refresh(code)

    # Set up the SMTP server
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_username = "usergp628@gmail.com"
    smtp_password = "ddvzveavvsiqsplr"

    # Create the email message
    message = f"Your verification code is {verification_code}"
    sender_email = "usergp628@gmail.com"
    receiver_email = email
    subject = "Verify Your Code."
    msg = f"Subject: {subject}\n\n{message}"

    # Log in to the SMTP server and send the email
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(sender_email, receiver_email, msg)

    return verification_code


def verify_verification_code(email: str, verification_code: int, database: Session):
    """
    Verify the verification code for a given email in the database.

    Args:
        email (str): The email address to verify.
        verification_code (int): The verification code to compare against the generated code.
        database (Session): The database session to use.

    Returns:
        bool: True if the verification code is valid and has not expired, False otherwise.
    """
    # Retrieve the generated code for the email from the database
    code = database.query(VerificationCode).filter_by(email=email).first()
    if code is None:
        return False
    generated_code = str(code.verification_code)

    # Check if the verification code has expired
    now = datetime.now().replace(microsecond=0)
    expires_at = code.created_at + timedelta(
        minutes=10
    )  # Set expiration time to 10 minutes
    if now > expires_at:
        database.delete(code)
        database.commit()
        return False
    # Strip any whitespaces from the entered code
    entered_code_stripped = str(verification_code).strip()
    if entered_code_stripped == generated_code:
        return True

    return False


def delete_expired_verification_codes():
    """
    # Check if there is an expired verification code for the email
    """
    database = SessionLocal()
    now = datetime.now().replace(microsecond=0)
    expired_codes = (
        database.query(VerificationCode)
        .filter(VerificationCode.expires_at <= now)
        .all()
    )
    for code in expired_codes:
        database.delete(code)
    database.commit()


# This code block schedules a task to delete expired verification codes every minute
# schedule.every(1).minutes.do(delete_expired_verification_codes)
# while True:
#    schedule.run_pending()
#    time.sleep(1)
# Example usage
# send_verification_code("ra4329530@gmail.com")

# **********************************************************************************************


@app.post("/user/forget-password", tags=["User"])
async def forget_password(
    details: ForgetPasswordRequest, database: Session = Depends(get_db)
):
    """
    Sends a verification code to the user's email and returns a message indicating success.

    Args:
        details (ForgetPasswordRequest): The request details, including the user's email address.
        database (Session): The database session to use for storing the verification code.

    Returns:
        dict: A dictionary containing a message indicating success and the verification code.
    """
    # check if user exists
    db_user = database.query(User).filter(User.email == details.email).first()
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "User with this email not found."
                "Check that this email which you had registered."
            ),
        )

    # Send verification code and insert it into the database
    verification_code = send_verification_code(details.email, database)
    return {
        "message": f" Check your email we send you a 4-digit verification code: {verification_code}"
    }


# **************************************************************************************************
@app.post("/user/verify-code", tags=["User"])
async def verfiy_code(
    details: VerifyCode, email: str = Header(None), database: Session = Depends(get_db)
):
    """
    Endpoint to verify a user's email verification code.

    :param details: A VerifyCode object containing the verification code.
    :param email: The email address of the user whose verification code is being verified.
    :param database: A SQLAlchemy Session object used to interact with the database.
    :return: A JSON response indicating whether the verification code is correct or not.
    :raises HTTPException 400: If the verification code is incorrect.
    """
    # Verify code
    if verify_verification_code(email, details.verification_code, database):
        # Return response
        return {
            "message": "Correct verification code",
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect verification code",
        )


# **************************************************************
@app.post("/user/reset-password",tags=["User"])
def reset_password(
    details: ResetPasswordRequest,
    email: str = Header(None),
    database: Session = Depends(get_db),
):
    """
    Endpoint to reset a user's password.

    param details: A ResetPasswordRequest object containing the new password and confirmed password.
    param email: The email address of the user whose password is being reset.
    param database: A SQLAlchemy Session object used to interact with the database.
    return: A JSON response indicating whether the password reset was successful or not.
    raises HTTPException 400: If the user with the given email is not found,
    or if the new password and confirmed password do not match.
    raises HTTPException 500: If there is a server error while resetting the password.
    """

    try:
        # Check if new password and confirmed password match
        if details.new_password == details.confirmed_password:
            # Update user's password in the database
            user = database.query(User).filter_by(email=email).first()
            if user is None:
                raise HTTPException(
                    status_code=400, detail="User with the given email not found."
                )
            user.password = generate_password_hash(details.new_password)
            database.commit()
            return {"message": "Password reset successful."}
        else:
            raise HTTPException(
                status_code=400,
                detail="New password and confirmed password do not match.",
            )
    except HTTPException as error:
        raise error
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error)) from error


# ******************************************************************
@app.get("/user", tags=["User"])
def get_by_id(user_id: int, authorize: AuthJWT = Depends(), database: Session = Depends(get_db)):
    """
    ## Get user by its id
    """
    try:
        authorize.jwt_required()
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        ) from error

    current_user = authorize.get_jwt_subject()
    if current_user != user_id:
        raise HTTPException(status_code=403, detail="You are not authorized to access this resource")

    user_db = database.query(User).filter(User.id == user_id).first()
    if not user_db:
        raise HTTPException(status_code=404, detail="User not found")

    user_data = schemas.UserData.from_orm(user_db)

    return {
        "message": f"The all information of user with id {user_id}",
        "User_Data": user_data,
    }

    
# ************************************************************************
@app.delete("/user/delete_user", tags=["User"])
def delete_user(user_username: str, database: Session = Depends(get_db)):
    """
    ## Delete an user from database by its username
    """
    user_to_delete = database.query(User).filter(User.username == user_username).first()
    if user_to_delete:
        database.delete(user_to_delete)
        database.commit()
        return {"success": " The user has been deleted"}
    raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="This user is not exist "
        )

# ****************************************************************************************
@app.post("/user/patient", tags=["Patient with logged user"])
def create_patient(
    details: AddPatient,
    authorize: AuthJWT = Depends(),
    database: Session = Depends(get_db),
):
    """
    ## Add New Patient by current user

    """
    try:
        authorize.jwt_required()
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        ) from error

    current_user = authorize.get_jwt_subject()
    user = database.query(User).filter(User.id == current_user).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
        ) 

    profile_data = database.query(ProfileData).filter(ProfileData.user_id == current_user).first()
    if not profile_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Profile data not found"
        )
    # Check if a patient with the given full name already exists for this user
    existing_patient = database.query(Patient).filter(
        Patient.full_name == details.full_name,
        Patient.user_id == user.id,
    ).first()
    if existing_patient:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Patient already existed "
        )
    
    new_patient = Patient(
        full_name=details.full_name,
        gender=details.gender,
        address=details.address,
        mobile_number=details.mobile_number,
    )
    new_patient.user = user
    profile_data.number_of_patients += 1
    database.add_all([new_patient, profile_data])
    database.commit()
    database.refresh(new_patient)
    database.refresh(profile_data)
    return {
        "message": "Congratulation!! Successfully Submited",
        "created_id": new_patient.id,
        #"number_of_patients": profile_data.number_of_patients
    }

# **********************************************************************************
# Get a current user's patients
@app.get("/user/patients", tags=["Patient with logged user"])
async def get_user_patients(
    authorize: AuthJWT = Depends(), database: Session = Depends(get_db)
):
    """
    ## Get a current user's patients
    This lists the patients created by the currently logged in users

    """
    try:
        authorize.jwt_required()
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        ) from error

    user = authorize.get_jwt_subject()

    current_user = database.query(User).filter(User.id == user).first()
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
        ) 

    # return jsonable_encoder(current_user.patients)
    return {
        "status": True,
        "message": "All patients you had created are :",
        "patients": [
            schemas.Patient.from_orm(patient) for patient in current_user.patients
        ],
    }


# *****************************************************************************
# Get a specific patient by the currently logged in user
@app.get("/user/patient/{full_name}/", tags=["Patient with logged user"])
async def get_specific_patient(
    full_name: str, authorize: AuthJWT = Depends(), database: Session = Depends(get_db)
):
    """
    ## Get a specific patient by the currently logged in user
    This returns a patient by FULL_NAME for the currently logged in user

    """
    try:
        authorize.jwt_required()
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Token"
        ) from error

    user = authorize.get_jwt_subject()

    current_user = database.query(User).filter(User.id == user).first()
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
        ) 
    # Convert the search string to lowercase
    full_name = full_name.lower()

    # Convert the patient names in the database to lowercase and perform the search
    patients = (
        database.query(Patient)
        .join(User)
        .filter(User.id == user, func.lower(Patient.full_name).like(f'%{full_name}%'))
        .all()
    )
    print (full_name)
    if not patients:
       raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="No patient with such name existed",
       )

    return {
    "status": True,
    "message": f"The all information of patients with name containing {full_name}",
    "patients": [schemas.Patient.from_orm(patient) for patient in patients],
     } 


# ***********************************************************
# Delete a patient
@app.delete("/user/patient/delete", tags=["Patient with logged user"])
async def delete_specific_patient(
    details: DeletePatient,
    authorize: AuthJWT = Depends(),
    database: Session = Depends(get_db),
):
    """
    ## Delete a patient
    This deletes a patient by its fullname
    """

    try:
        authorize.jwt_required()

    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Token"
        ) from error
    user = authorize.get_jwt_subject()

    current_user = database.query(User).filter(User.id == user).first()
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
        ) 
    patient_to_delete = (
        database.query(Patient).filter(Patient.full_name == details.full_name,
        Patient.user_id == user).first()
    )
    if patient_to_delete:
        # Decrement the number of patients in the ProfileData table
        profile_data = database.query(ProfileData).filter(
            ProfileData.user_id == user,
        ).first()
        if profile_data:
            profile_data.number_of_patients -= 1
            database.add(profile_data)
        database.delete(patient_to_delete)
        database.commit()
        # return order_to_delete
        return {"success": " The patient has been deleted"}

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST, detail="This Patient is not exist "
    )


# user=Authorize.get_jwt_subject()
# current_user=db.query(User).filter(User.id==user).first()
# patients=current_user.patients


# **********************************************************************
# Add New Medical Record to this patient by current user
@app.post("/user/patient/medical_record", tags=["Patient with logged user"])
async def create_medical_record(
    details: AddMedicalRecord,
    authorize: AuthJWT = Depends(),
    database: Session = Depends(get_db),
):
    """
    ## Add New Medical Record to this patient by current user
    Remember you need to save the return id from the submitted patient you added
    """
    try:
        authorize.jwt_required()
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        ) from error

    current_user = authorize.get_jwt_subject()
    user = database.query(User).filter(User.id == current_user).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    new_medical_record = MedicalRecord(
        result=details.result,
        patient_id=details.patient_id,
    )
    db_patient = database.query(Patient).filter(Patient.id == details.patient_id).first()
    if db_patient:
       database.add(new_medical_record)
       database.commit()
       return {
        "message": "Congratulation!! Successfully Add a new Medical Record to this patient ",
       }
    
    raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Patient of {details.patient_id} is not present Patients that You added"
        ) 



# ***********************************************************************************************
# getting a patient from Medical Record Table by its patient ID
@app.get(
    "/user/patients/{patient_id}/medical_records", tags=["Patient with logged user"]
)
def read_medical_records_with_specific_patient(
    patient_id: int, authorize: AuthJWT = Depends(), database: Session = Depends(get_db)
):
    """
    ## Get only information of Medical Record that
    belong to this patient through its ID by "current user".

    """
    try:
        authorize.jwt_required()
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        ) from error

    current_user = authorize.get_jwt_subject()
    user = database.query(User).filter(User.id == current_user).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    patients = (
        database.query(models.MedicalRecord)
        .filter(models.MedicalRecord.patient_id == patient_id)
        .all()
    )
    return {
        "status": True,
        "message": "The medical record information to this patient",
        "patients": [
            schemas.AddMedicalRecord.from_orm(patient) for patient in patients
        ],
    }


# **************************************************************************************************
# getting a patient with its Medical Record information using patient ID
@app.get(
    "/user/patient/{patient_id}/medical_records",
    response_model=schemas.PatientWithMedicalRecord,
    tags=["Patient with logged user"],
)
def read_patient_with_medical_record(
    patient_id: int, authorize: AuthJWT = Depends(), database: Session = Depends(get_db)
):
    """
    ## Get all the information of a patient from patient Table and
    its Medical Record Information from Medical Record Table using patient ID.
    This returns data by only currently logged user.


    """
    try:
        authorize.jwt_required()
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        ) from error

    current_user = authorize.get_jwt_subject()
    user = database.query(User).filter(User.id == current_user).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    patient = crud.get_patient(database, patient_id=patient_id)
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    medical_record = crud.get_medical_record(database, patient_id=patient_id)
    return {
        "status": True,
        "message": f"All Information that belong to this patient {patient.full_name} ",
        "patient": patient,
        "medical_record": medical_record,
    }


# ******************************************************************************
# getting  patient with his name
@app.get("/patient/{full_name}", tags=["patient"])
def get_by_fullname(full_name: str, database: Session = Depends(get_db)):
    """
    ## getting  patient with his name
    """
    patients = database.query(Patient).filter(Patient.full_name == full_name).first()
    return {
        "status": True,
        "message": None,
        "patients": [schemas.Patient.from_orm(patient) for patient in patients],
    }


# getting all patients
@app.get("/patients/{user_id}", tags=["patient"])
def get_patients(user_id: int, database: Session = Depends(get_db)):
    """
    Retrieves all patients associated with the given user ID from the database.

    Args:
        user_id (int): The ID of the user whose patients to retrieve.
        database (Session): The database session to use.

    Returns:
        dict: A dictionary containing a message indicating success and a list of patient objects.
    """
    patients = (
        database.query(models.Patient).filter(models.Patient.user_id == user_id).all()
    )
    return {
        "status": True,
        "message": "All patients that had been added in database",
        "patients": [schemas.Patient.from_orm(patient) for patient in patients],
    }


# Deleting patient with his name
@app.delete("/delete_patient/", tags=["patient"])
def delete(details: DeletePatient, database: Session = Depends(get_db)):
    """
    Deletes a patient with the given name from the database.

    Args:
        details (DeletePatient): The details of the patient to be deleted, 
        including their full name.
        database (Session): The database session to use.

    Returns:
        dict: A dictionary containing a message indicating success.
    """
    db_patient = (
        database.query(Patient).filter(Patient.full_name == details.full_name).first()
    )
    if not db_patient:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="This Patient is not exist "
        )
    database.query(Patient).filter(Patient.full_name == details.full_name).delete()
    database.commit()
    return {"success": " The patient has been deleted"}

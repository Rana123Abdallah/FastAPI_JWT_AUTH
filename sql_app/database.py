"""
This module contains the database setup code for the application.
"""

from sqlalchemy.orm import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://postgres:nono1102001@db:5432/User_db')

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Define the declarative base for the database models
Base = declarative_base()

# Create the database tables based on the models
Base.metadata.create_all(bind=engine)


# Define a function for getting a database session
# This function should be used as a dependency in FastAPI routes
# Dependency
def get_db():
    """
    Creates a new database session and returns it as a context manager.

    Usage:
        with get_db() as db:
            # Use the database session here
            ...

    Returns:
        Session: A database session object.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

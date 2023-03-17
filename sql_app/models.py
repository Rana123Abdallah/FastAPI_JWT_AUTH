from sql_app.database import Base
from sqlalchemy import String,Boolean,Integer,Float,Column,Text
from sqlalchemy.orm import relationship

class User(Base):
    __tablename__ = "User"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String,nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String,nullable=False)
    ##hashed_password = Column(String)
    
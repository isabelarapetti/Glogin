import sys
import datetime
from sqlalchemy import Column,Integer, String, DateTime
from sqlalchemy import create_engine

class User(Base):
	__tablename__ = 'user'

	id = Column(Integer, primary_key=True)
	username = Column(String(50), nullable=False)
	email = Column(String(250), nullable=False)
	pw_hash = Column(String(250), nullable=False)

engine = create_engine('sqlite:///tp.db')
Base.metadata.create_all(engine)

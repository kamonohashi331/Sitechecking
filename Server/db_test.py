from sqlalchemy import DateTime, create_engine, Column, Integer, String, Boolean, ForeignKey, select
from sqlalchemy.orm import sessionmaker, relationship, declarative_base
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.engine import URL
import pymysql
from dotenv import load_dotenv
import os
from urllib.parse import quote_plus,quote
from contextlib import contextmanager

from src.models import *

load_dotenv()

db_user = "hostingPanel"
db_host = "localhost"
db_pass = os.environ["DB_PASSWORD"]
db_port = 3306
db_name = "hostingPanel"

db_url = URL.create(
    drivername="mysql+pymysql",
    username=db_user,
    password=db_pass,
    host="localhost",
    database=db_name
).render_as_string(hide_password=False)

print(db_url)

#db_url = db_url.replace("%", "%%")

engine = create_engine(db_url, connect_args=())
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
# autoflush : load changes before queries
# autocommit : commit changes after queries

AsyncSessionLocal = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
Base = declarative_base()

#def get_db():
#    db = SessionLocal()
#    try:
#        yield db
#    finally:
#        db.close()

@contextmanager
def get_db():
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

with get_db() as db:
    existing_user = db.query(User).filter(
        (User.email == "sqs")
    ).first()

    print(existing_user)
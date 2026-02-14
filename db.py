from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

def make_engine(db_url: str):
    connect_args = {"check_same_thread": False} if db_url.startswith("sqlite") else {}
    return create_engine(db_url, connect_args=connect_args)

def make_session_factory(engine):
    return sessionmaker(bind=engine)

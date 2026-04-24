import json

from google.oauth2.credentials import Credentials
from sqlalchemy import create_engine, Column, String, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

engine = create_engine("sqlite:///tokens.db")
Base = declarative_base()
DBSession = sessionmaker(bind=engine)
db_session = DBSession()

class UserToken(Base):
    __tablename__ = "user_tokens"

    user_id = Column(String, primary_key=True)
    token = Column(Text)
    refresh_token = Column(Text)
    token_uri = Column(Text)
    client_id = Column(Text)
    client_secret = Column(Text)
    scopes = Column(Text)

Base.metadata.create_all(engine)

def save_credentials(user_id, creds):
    record = db_session.query(UserToken).filter_by(user_id=user_id).first()

    if not record:
        record = UserToken(user_id=user_id)

    record.token = creds.token
    record.refresh_token = creds.refresh_token
    record.token_uri = creds.token_uri
    record.client_id = creds.client_id
    record.client_secret = creds.client_secret
    record.scopes = json.dumps(creds.scopes)

    db_session.add(record)
    db_session.commit()


def load_credentials(user_id):
    record = db_session.query(UserToken).filter_by(user_id=user_id).first()
    if not record:
        return None

    return Credentials(
        token=record.token,
        refresh_token=record.refresh_token,
        token_uri=record.token_uri,
        client_id=record.client_id,
        client_secret=record.client_secret,
        scopes=json.loads(record.scopes)
    )

def delete_credentials(user_id):
    record = db_session.query(UserToken).filter_by(user_id=user_id).first()
    if record:
        db_session.delete(record)
        db_session.commit()    
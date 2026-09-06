from sqlalchemy import create_engine
from app.models.models import Base

DATABASE_URL="sqlite:///./security_memory.db"
engine=create_engine(DATABASE_URL,connect_args={"check_same_thread":False})

def init_db():
    Base.metadata.create_all(engine)

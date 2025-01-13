from backend import models, schemas

from sqlalchemy.orm import Session
from passlib.context import CryptContext


def create_analysis(db: Session, analysis: schemas.AnalysisCreate):
    db_analysis = models.AnalysisData(**analysis.dict())
    db.add(db_analysis)
    db.commit()
    db.refresh(db_analysis)
    return db_analysis

def get_all_analyses(db: Session):
    return db.query(models.AnalysisData).all()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Lấy người dùng theo username
def get_user_by_username(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()

# Tạo người dùng mới
def create_user(db: Session, user: schemas.UserCreate):
    hashed_password = pwd_context.hash(user.password)
    db_user = models.User(username=user.username, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

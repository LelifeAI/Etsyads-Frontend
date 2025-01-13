import sys
import os
from sqlalchemy import Column, Integer, String, Boolean


# Thêm thư mục cha của backend vào sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import Column, Integer, String, Float
from backend.database import Base

from sqlalchemy import Column, Integer, Float, String, DateTime
from datetime import datetime
from .database import Base


class AnalysisData(Base):
    __tablename__ = "analysis_data"

    id = Column(Integer, primary_key=True, index=True)
    views = Column(Integer)
    clicks = Column(Integer)
    orders = Column(Integer)
    revenue = Column(Float)
    spend = Column(Float)
    sales = Column(Float)
    marketing = Column(Float)
    fees = Column(Float)
    avg_ctr = Column(Float, default=2.0)
    avg_cr = Column(Float, default=2.5)
    avg_cpp = Column(Float, default=10.0)
    avg_fee_ads = Column(Float, default=20.0)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_admin = Column(Boolean, default=False)  # Thêm thuộc tính is_admin

class History(Base):
    __tablename__ = "analysis_history"  # Đổi tên bảng
    __table_args__ = {"extend_existing": True}  # Thêm dòng này để tránh lỗi

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    ctr = Column(Float)
    cr = Column(Float)
    cpp = Column(Float)
    roi = Column(Float)
    fee_ads = Column(Float)

from pydantic import BaseModel
from datetime import datetime


class AnalysisCreate(BaseModel):
    views: int
    clicks: int
    orders: int
    revenue: float
    spend: float
    sales: float
    marketing: float
    fees: float
    avg_ctr: float = 2.0
    avg_cr: float = 2.5
    avg_cpp: float = 10.0
    avg_fee_ads: float = 20.0

class AnalysisData(BaseModel):
    views: int
    clicks: int
    orders: int
    revenue: float
    spend: float
    sales: float
    marketing: float
    fees: float

class Analysis(BaseModel):
    id: int
    views: int
    clicks: int
    orders: int
    revenue: float
    spend: float
    sales: float
    marketing: float
    fees: float
    avg_ctr: float
    avg_cr: float
    avg_cpp: float
    avg_fee_ads: float

class Thresholds(BaseModel):
    ctr: float
    cr: float
    cpp: float
    fee_ads: float
    roi: float

class AnalysisData(BaseModel):
    views: int
    clicks: int
    orders: int
    revenue: float
    spend: float
    sales: float
    marketing: float
    fees: float
    thresholds: Thresholds

class HistoryResponse(BaseModel):
    id: int
    timestamp: datetime
    ctr: float
    cr: float
    cpp: float
    roi: float
    fee_ads: float

    class Config:
        from_attributes = True

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str

class UserOut(UserBase):
    id: int

   



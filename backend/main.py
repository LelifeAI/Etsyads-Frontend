import logging
import sys
import os

# Thêm log để kiểm tra dữ liệu
logging.basicConfig(level=logging.DEBUG)

# Thêm thư mục hiện tại vào sys.path để tránh lỗi import
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Bằng các dòng này
from backend import models, schemas, crud
from backend.database import engine, SessionLocal, Base
from backend.schemas import AnalysisData

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .schemas import AnalysisData

from pydantic import BaseModel
from sqlalchemy import Column, Integer, Float, DateTime
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from fastapi import Body

from jose import JWTError, jwt
from datetime import timedelta

from fastapi.security import OAuth2PasswordBearer

from jose import jwt
from fastapi.security import OAuth2PasswordRequestForm

from fastapi import Depends

from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from backend.models import Base
from ml_model import predict_action

from ml_model import get_detailed_recommendation

from auth_token import jwt

from fastapi import FastAPI, Request



app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Xác định đường dẫn tuyệt đối đến thư mục static
static_directory = os.path.abspath(os.path.join(os.path.dirname(__file__), "static"))

# Mount thư mục static
app.mount("/static", StaticFiles(directory=static_directory), name="static")

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Cấu hình logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Tạo bảng trong cơ sở dữ liệu nếu chưa tồn tại
models.Base.metadata.create_all(bind=engine)

# Dependency để lấy session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Định nghĩa model dữ liệu từ frontend
class AnalyzeData(BaseModel):
    views: int = 0
    clicks: int = 0
    orders: int = 0
    revenue: float = 0.0
    spend: float = 0.0
    sales: float = 0.0
    marketing: float = 0.0
    fees: float = 0.0

def generate_proposals(ctr, cr, cpp, fee_ads, roi, averages):
    proposals = []
    if ctr < averages["ctr"]:
        proposals.append("CTR thấp. Cải thiện từ khóa hoặc hình ảnh để thu hút nhiều nhấp chuột hơn.")
    if cr < averages["cr"]:
        proposals.append("CR thấp. Tối ưu hóa quy trình đặt hàng hoặc quảng cáo sản phẩm.")
    if cpp > averages["cpp"]:
        proposals.append("CPP cao. Cần giảm chi phí quảng cáo để cải thiện hiệu quả.")
    if fee_ads > averages["fee_ads"]:
        proposals.append("Fee Ads cao. Xem xét tối ưu chi phí marketing.")
    if roi < averages["roi"]:
        proposals.append("ROI thấp. Tăng doanh thu hoặc giảm chi phí quảng cáo.")

    return proposals

# Hàm tạo Access Token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta if expires_delta else datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Hàm tạo Refresh Token
def create_refresh_token(data: dict):
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

# Hàm tạo tài khoản admin
def create_admin_user(db: Session):
    username = "admin"
    password = "admin123"

    # Kiểm tra xem tài khoản admin đã tồn tại chưa
    db_user = db.query(models.User).filter(models.User.username == username).first()
    if not db_user:
        hashed_password = pwd_context.hash(password)
        admin_user = models.User(username=username, hashed_password=hashed_password, is_admin=True)
        db.add(admin_user)
        db.commit()
        print("Tài khoản admin đã được tạo:", username)
    else:
        print("Tài khoản admin đã tồn tại.")

# Đăng ký người dùng mới
@app.post("/register/", response_model=schemas.UserOut)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    print("Received user data:", user.dict())  # Thêm log kiểm tra
    db_user = crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username đã tồn tại")
    return crud.create_user(db=db, user=user)

# Đăng nhập người dùng
# Endpoint đăng nhập
# Cập nhật endpoint /login/
@app.post("/login/")
def login(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_username(db, user.username)
    if not db_user:
        raise HTTPException(status_code=400, detail="Người dùng không tồn tại")
    if not pwd_context.verify(user.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Sai mật khẩu")

    # Tạo Access Token và Refresh Token
    access_token = create_access_token(data={"sub": db_user.username})
    refresh_token = create_refresh_token(data={"sub": db_user.username})

    return {
        "message": "Đăng nhập thành công",
        "user_id": db_user.id,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta if expires_delta else datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@app.post("/change_password/")
def change_password(
    username: str = Body(...),
    old_password: str = Body(...),
    new_password: str = Body(...),
    db: Session = Depends(get_db),
):
    db_user = crud.get_user_by_username(db, username=username)
    if not db_user or not pwd_context.verify(old_password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Sai username hoặc mật khẩu cũ")
    
    db_user.hashed_password = pwd_context.hash(new_password)
    db.commit()
    return {"message": "Đổi mật khẩu thành công!"}

@app.post("/refresh/")
def refresh_token(refresh_token: str = Body(...)):
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Refresh Token không hợp lệ")

        new_access_token = create_access_token(data={"sub": username})
        return {"access_token": new_access_token, "token_type": "bearer"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh Token đã hết hạn")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Token không hợp lệ")

@app.get("/users/")
def get_users(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    username = payload.get("sub")

    db_user = db.query(models.User).filter(models.User.username == username).first()
    if not db_user or not db_user.is_admin:
        raise HTTPException(status_code=403, detail="Không có quyền truy cập")

    users = db.query(models.User).all()
    return [{"id": user.id, "username": user.username} for user in users]


@app.post("/recommend/")
def recommend_action(data: dict):
    ctr = data.get("ctr", 0)
    cr = data.get("cr", 0)
    cpp = data.get("cpp", 0)
    fee_ads = data.get("fee_ads", 0)
    roi = data.get("roi", 0)

    recommendation = get_detailed_recommendation(ctr, cr, cpp, fee_ads, roi)
    return {"recommendation": recommendation}

# Model Lịch Sử Phân Tích
class History(Base):
    __tablename__ = "history"
    id = Column(Integer, primary_key=True, index=True)
    ctr = Column(Float)
    cr = Column(Float)
    cpp = Column(Float)
    fee_ads = Column(Float)
    roi = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)

# Schema
class HistoryCreate(BaseModel):
    ctr: float
    cr: float
    cpp: float
    fee_ads: float
    roi: float

class HistoryResponse(HistoryCreate):
    id: int
    timestamp: datetime

    class Config:
        orm_mode = True

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Middleware CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Hoặc chỉ định ["http://127.0.0.1:5500"]
    allow_credentials=True,
    allow_methods=["*"],  # Cho phép tất cả phương thức HTTP
    allow_headers=["*"],  # Cho phép tất cả header
)

# Danh sách giả lập cơ sở dữ liệu
database = []

# Endpoint lưu lịch sử
@app.post("/history/", response_model=HistoryResponse)
def create_history(entry: HistoryCreate, db=Depends(get_db)):
    print("Nhận được yêu cầu lưu:", entry)
    new_entry = History(**entry.dict())
    db.add(new_entry)
    db.commit()
    db.refresh(new_entry)
    return new_entry

# Endpoint lấy danh sách lịch sử
@app.get("/history/", response_model=list[HistoryResponse])
def get_history(db=Depends(get_db)):
    return db.query(History).order_by(History.timestamp.desc()).all()

# Endpoint xóa toàn bộ lịch sử
@app.delete("/history/")
def delete_history(db: Session = Depends(get_db)):
    try:
        db.query(History).delete()
        db.commit()
        return {"message": "Lịch sử đã được xóa thành công!"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi khi xóa lịch sử: {str(e)}")

@app.delete("/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Người dùng không tồn tại")
    db.delete(user)
    db.commit()
    return {"message": "Người dùng đã bị xóa thành công"}


@app.post("/analysis/")
async def create_analysis(data: AnalysisData):
    print("Nhận được yêu cầu lưu kết quả:", data.dict())  # Log dữ liệu nhận được

    database.append(data)
    return {"status": "success", "data": data}

@app.post("/logout/")
def logout(token: str = Depends(oauth2_scheme)):
    return {"message": "Đăng xuất thành công!"}

# Endpoint /analyze/
@app.post("/analyze/")
async def analyze_data(data: AnalyzeData):
    try:
        # Log dữ liệu nhận từ frontend
        logger.info("Nhận được yêu cầu phân tích.")
        logger.debug(f"Dữ liệu nhận từ frontend: {data.dict()}")

        # ✅ Xử lý các chỉ số
        ctr = (data.clicks / data.views * 100) if data.views > 0 else 0
        cr = (data.orders / data.clicks * 100) if data.clicks > 0 else 0
        cpp = (data.spend / data.orders) if data.orders > 0 else 0
        fee_ads = (data.marketing / data.sales * 100) if data.sales > 0 else 0
        roi = ((data.revenue - data.spend) / data.spend * 100) if data.spend > 0 else 0

        # ✅ Log kết quả phân tích
        logger.debug(f"Kết quả phân tích: CTR={ctr:.2f}%, CR={cr:.2f}%, CPP={cpp:.2f}, Fee Ads={fee_ads:.2f}%, ROI={roi:.2f}%")

        # ✅ Gọi hàm đề xuất hành động chi tiết từ ml_model.py
        recommendation = get_detailed_recommendation(ctr, cr, cpp, fee_ads, roi)

        # ✅ Trả phản hồi cho frontend
        return {
            "status": "success",
            "analysis": {
                "ctr": ctr,
                "cr": cr,
                "cpp": cpp,
                "fee_ads": fee_ads,
                "roi": roi
            },
            "recommendation": recommendation
        }

    except Exception as e:
        logger.error("Lỗi xảy ra khi xử lý phân tích dữ liệu:", exc_info=True)
        raise HTTPException(status_code=500, detail="Đã xảy ra lỗi khi phân tích dữ liệu.")

    # Ngưỡng trung bình
    avg_ctr = 2.0
    avg_cr = 2.5
    avg_cpp = 10.0
    avg_fee_ads = 20.0
    avg_roi = 75.0

    # Đề xuất hành động
    proposals = []
    if ctr < avg_ctr:
        proposals.append("CTR thấp. Cải thiện từ khóa hoặc hình ảnh để thu hút nhiều nhấp chuột hơn.")
    if cr < avg_cr:
        proposals.append("CR thấp. Tối ưu hóa quy trình đặt hàng hoặc quảng cáo sản phẩm.")
    if cpp > avg_cpp:
        proposals.append("CPP cao. Cần giảm chi phí quảng cáo để cải thiện hiệu quả.")
    if fee_ads > avg_fee_ads:
        proposals.append(f"Fee Ads cao. Xem xét tối ưu chi phí marketing. (Thời gian: {data.sales} ngày)")
    if roi < avg_roi:
        proposals.append("ROI thấp. Tăng doanh thu hoặc giảm chi phí quảng cáo.")

    return {
        "analysis": {
            "ctr": ctr,
            "cr": cr,
            "cpp": cpp,
            "fee_ads": fee_ads,
            "roi": roi
        },
        "averages": {
            "ctr": avg_ctr,
            "cr": avg_cr,
            "cpp": avg_cpp,
            "fee_ads": avg_fee_ads,
            "roi": avg_roi
        },
        "proposals": proposals,
        "charts": {
            "ctr": {"current": ctr, "average": avg_ctr},
            "cr": {"current": cr, "average": avg_cr},
            "cpp": {"current": cpp, "average": avg_cpp},
            "fee_ads": {"current": fee_ads, "average": avg_fee_ads},
            "roi": {"current": roi, "average": avg_roi}
        }
    }

@app.get("/analysis/")
async def get_analysis():
    if not database:
        raise HTTPException(status_code=404, detail="No data found")
    return database

@app.get("/")
async def read_root():
    return {"message": "Welcome to the Analysis API!"}

@app.get("/users/")
def get_users(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")

        db_user = db.query(models.User).filter(models.User.username == username).first()
        if not db_user or not db_user.is_admin:
            raise HTTPException(status_code=403, detail="Bạn không có quyền truy cập")

        users = db.query(models.User).all()
        return [{"id": user.id, "username": user.username} for user in users]
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Token không hợp lệ")

@app.get("/protected/")
def read_protected(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Không thể xác thực người dùng")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token không hợp lệ hoặc đã hết hạn")
    return {"message": f"Chào mừng {username} đến với endpoint được bảo vệ!"}

if __name__ == "__main__":
    import uvicorn
    from database import SessionLocal

    # Hàm tạo tài khoản admin
    def create_admin_user(db):
        username = "admin"
        password = "admin123"

        # Kiểm tra xem tài khoản admin đã tồn tại chưa
        db_user = db.query(models.User).filter(models.User.username == username).first()
        if not db_user:
            hashed_password = pwd_context.hash(password)
            admin_user = models.User(username=username, hashed_password=hashed_password, is_admin=True)
            db.add(admin_user)
            db.commit()
            print("Tài khoản admin đã được tạo:", username)
        else:
            print("Tài khoản admin đã tồn tại.")

    # Tạo tài khoản admin khi khởi động server
    db = SessionLocal()
    create_admin_user(db)

    # Khởi động server FastAPI
    uvicorn.run(app, host="127.0.0.1", port=8000)



# ================= FastAPI Backend - Smart Parking (SQLite + Admin Auth) =================
# Local dev:
#   pip install -r requirements.txt
#   uvicorn backend_server:app --host 0.0.0.0 --port 8000
#
# Creates parking.db automatically on first run (path controlled by DATABASE_URL).
#
# Route groups:
#   - /api/auth/*     -> admin login (issues a JWT)
#   - /api/parking/update, /api/parking/config/{pack_id} (GET)
#         -> called by the ESP-01, NO auth (a device can't easily do a login flow)
#   - /api/parking/status, /api/parking/logs, /api/parking/config/{pack_id} (POST)
#         -> called by the admin frontend, REQUIRE a valid Bearer token
#
# Configuration is via environment variables (see .env.example). Nothing
# secret is hardcoded in this file anymore.

import os
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, Float, Integer, String, create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

# ---------- Config (from environment) ----------
# On Render, set these under your service's "Environment" tab.
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY environment variable is not set. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
# ADMIN_PASSWORD_HASH is a bcrypt hash, NOT a plaintext password.
# Generate one with: python -c "from passlib.context import CryptContext; print(CryptContext(schemes=['bcrypt']).hash('yourpassword'))"
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH")
if not ADMIN_PASSWORD_HASH:
    raise RuntimeError(
        "ADMIN_PASSWORD_HASH environment variable is not set. "
        "Generate one with: python -c \"from passlib.context import CryptContext; "
        "print(CryptContext(schemes=['bcrypt']).hash('yourpassword'))\""
    )

# Comma-separated list of allowed origins for the admin frontend, e.g.
# "https://myapp.netlify.app,https://admin.example.com"
_raw_origins = os.environ.get("CORS_ORIGINS", "")
CORS_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]
if not CORS_ORIGINS:
    # Safe default for local development only.
    CORS_ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000"]

# On Render, attach a persistent disk (e.g. mounted at /data) and point
# DATABASE_URL at a file inside it, or the DB will be wiped on every deploy.
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./parking.db")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---------- Database setup ----------
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class ParkingSlot(Base):
    """Current state of one pack (upserted on every update)."""
    __tablename__ = "parking_slots"
    pack_id = Column(String, primary_key=True, index=True)
    status = Column(String, default="UNKNOWN")
    height_cm = Column(Float, default=230.0)
    last_updated = Column(DateTime, default=datetime.utcnow)


class ParkingLog(Base):
    """Full history - one row per state change, per pack."""
    __tablename__ = "parking_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    pack_id = Column(String, index=True)
    status = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------- Auth helpers ----------
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def create_access_token(data: dict, expires_delta: timedelta) -> str:
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + expires_delta})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_admin(token: str = Depends(oauth2_scheme)) -> str:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username != ADMIN_USERNAME:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return username


# ---------- Pydantic schemas ----------
class SlotUpdate(BaseModel):
    pack_id: str
    status: str  # "FREE" or "OCCUPIED"


class HeightConfig(BaseModel):
    height_cm: float


class SlotOut(BaseModel):
    pack_id: str
    status: str
    height_cm: float
    last_updated: datetime

    class Config:
        from_attributes = True


class LogOut(BaseModel):
    pack_id: str
    status: str
    timestamp: datetime

    class Config:
        from_attributes = True


# ---------- App ----------
app = FastAPI(title="Smart Parking Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def health_check():
    # Handy for Render's health check / just confirming the service is up.
    return {"status": "ok", "service": "smart-parking-backend"}


# ---------- Auth route ----------
@app.post("/api/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # form_data expects x-www-form-urlencoded fields: username, password
    valid_user = form_data.username == ADMIN_USERNAME
    valid_pass = pwd_context.verify(form_data.password, ADMIN_PASSWORD_HASH)
    if not (valid_user and valid_pass):
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    token = create_access_token(
        data={"sub": form_data.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": token, "token_type": "bearer"}


# ---------- Device routes (no auth - called by the ESP-01) ----------
@app.post("/api/parking/update")
def update_slot(update: SlotUpdate, db: Session = Depends(get_db)):
    slot = db.get(ParkingSlot, update.pack_id)
    now = datetime.utcnow()

    if slot is None:
        slot = ParkingSlot(pack_id=update.pack_id, status=update.status, last_updated=now)
        db.add(slot)
    else:
        slot.status = update.status
        slot.last_updated = now

    db.add(ParkingLog(pack_id=update.pack_id, status=update.status, timestamp=now))
    db.commit()
    return {"ok": True}


@app.get("/api/parking/config/{pack_id}")
def get_config(pack_id: str, db: Session = Depends(get_db)):
    slot = db.get(ParkingSlot, pack_id)
    if slot is None:
        # Pack not seen yet - hand back a sensible default. It gets created
        # for real the first time that pack posts an update.
        return {"height_cm": 230.0}
    return {"height_cm": slot.height_cm}


# ---------- Admin routes (JWT-protected - called by the frontend) ----------
@app.get("/api/parking/status", response_model=List[SlotOut])
def get_status(db: Session = Depends(get_db), admin: str = Depends(get_current_admin)):
    return db.query(ParkingSlot).all()


@app.get("/api/parking/logs", response_model=List[LogOut])
def get_logs(
    pack_id: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    query = db.query(ParkingLog)
    if pack_id:
        query = query.filter(ParkingLog.pack_id == pack_id)
    return query.order_by(ParkingLog.timestamp.desc()).limit(limit).all()


@app.post("/api/parking/config/{pack_id}")
def set_config(
    pack_id: str,
    config: HeightConfig,
    db: Session = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    slot = db.get(ParkingSlot, pack_id)
    if slot is None:
        slot = ParkingSlot(pack_id=pack_id, status="UNKNOWN", height_cm=config.height_cm)
        db.add(slot)
    else:
        slot.height_cm = config.height_cm
    db.commit()
    return {"ok": True, "pack_id": pack_id, "height_cm": config.height_cm}

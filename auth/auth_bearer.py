from fastapi import Request, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from auth.auth_handler import decodeJWT
from db.session import get_db
from sqlalchemy.orm import Session
from typing import Optional
from api.v1.models.user.user_auth import OTP, User
from jwt import PyJWTError


# user_ops = User()

class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=403, detail="Invalid authentication scheme.")
            if not self.verify_jwt(credentials.credentials):
                raise HTTPException(status_code=403, detail="Invalid token or expired token.")
            return credentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")

    @staticmethod
    def verify_jwt(jwt_token: str) -> bool:
        try:
            payload = decodeJWT(jwt_token)
            return payload is not None
        except Exception as e:
            print(str(e))
            return False


def get_user_id_from_token(token: str = Depends(JWTBearer())):
    payload = decodeJWT(token)

    if payload:
        return payload.get("user_id")
    else:
        raise HTTPException(status_code=403, detail="Invalid or expired token")

def get_admin(user_id: int = Depends(get_user_id_from_token), db: Session = Depends(get_db)) -> Optional[User]:
    user = db.query(User).filter(User.user_id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.user_type != "admin":
        raise HTTPException(status_code=403, detail="You are not authorized to perform this action")
    return user

def get_teacher(user_id: int = Depends(get_user_id_from_token), db: Session = Depends(get_db)) -> Optional[User]:
    user = db.query(User).filter(User.user_id == user_id).first()
    if user.user_type != "teacher":
        raise HTTPException(status_code=403, detail="You are not authorized to perform this action")

def get_admin_or_teacher(user_id: int = Depends(get_user_id_from_token), db: Session = Depends(get_db)) -> Optional[User]:
    user = db.query(User).filter(User.user_id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.user_type not in ["teacher", "admin"]:
        raise HTTPException(status_code=403, detail="You are not authorized to perform this action")
    return user

def get_admin_or_parent(user_id: int = Depends(get_user_id_from_token), db: Session = Depends(get_db)) -> Optional[User]:
    user = db.query(User).filter(User.user_id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.user_type not in ["parent", "admin"]:
        raise HTTPException(status_code=403, detail="You are not authorized to perform this action")
    return user

def get_admin_student_teacher(user_id: int = Depends(get_user_id_from_token), db: Session = Depends(get_db)) -> Optional[User]:
    user = db.query(User).filter(User.user_id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.user_type not in ["student", "admin", "teacher"]:
        raise HTTPException(status_code=403, detail="You are not authorized to perform this action")
    return user

def get_admin_student_teacher_parent(user_id: int = Depends(get_user_id_from_token), db: Session = Depends(get_db)) -> Optional[User]:
    user = db.query(User).filter(User.user_id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.user_type not in ["student", "admin", "teacher", "parent"]:
        raise HTTPException(status_code=403, detail="You are not authorized to perform this action")
    return user


def get_admin_or_student(user_id: int = Depends(get_user_id_from_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.user_id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    if user.user_type not in ["admin", "student","user"]:
        raise HTTPException(status_code=403, detail="You are not authorized to perform this action")
    return user

def get_current_user(token: str = Depends(JWTBearer()), db: Session = Depends(get_db)) -> Optional[User]:
    try:
        payload = decodeJWT(token)
        if payload:
            user_id: int = payload.get("user_id")
        if user_id is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = db.query(User).filter(User.user_id == user_id).first()
        if user is None:
            raise HTTPException(
                status_code=401,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return user
    except PyJWTError:
        raise HTTPException(
            status_code=401,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
def is_admin(current_user: Optional[User] = Depends(get_user_id_from_token)):
    # if not current_user or current_user.user_type != "admin":
    #     raise HTTPException(status_code=403, detail="You are not authorized to access this resource")
    # return current_user
    print(current_user)


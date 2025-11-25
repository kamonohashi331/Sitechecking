from fastapi import FastAPI, Depends, HTTPException, status, Header, APIRouter
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional

#import src.crypto as crypto
from src.crypto import AuthService, AuthError, extract_token_from_header
from src.models import *
from src.database import get_db

router = APIRouter()

security = HTTPBearer()

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None


class LoginRequest(BaseModel):
    email: str  # Can be email or username
    password: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: int
    email: str
    first_name: Optional[str]
    last_name: Optional[str]
    role: str
    is_active: bool
    is_verified: bool

    class Config:
        from_attributes = True




async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> User:
    """
    Dependency to get current authenticated user
    
    Usage:
        @router.get("/protected")
        async def protected_route(current_user: User = Depends(get_current_user)):
            return {"user": current_user.username}
    """
    try:
        token = credentials.credentials
        user = AuthService.get_current_user(token)
        return user
    except AuthError as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.message
        )


async def get_current_admin_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Dependency to require admin user
    
    Usage:
        @router.get("/admin")
        async def admin_route(current_user: User = Depends(get_current_admin_user)):
            return {"message": "Admin only"}
    """
    if not current_user.is_admin():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user


def require_role(*roles: UserRole):
    """
    Dependency factory to require specific roles
    
    Usage:
        @router.get("/reseller")
        async def reseller_route(
            current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.RESELLER))
        ):
            return {"message": "Reseller access"}
    """
    async def check_role(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        return current_user
    return check_role


# Public routes

@router.post("/register", response_model=dict, status_code=status.HTTP_201_CREATED)
async def register(data: RegisterRequest):
    raise HTTPException(status_code=401, detail="Registering is disabled")

    """Register a new user"""
    try:
        user, access_token, refresh_token = AuthService.register_user(
            email=data.email,
            password=data.password,
            first_name=data.first_name,
            last_name=data.last_name
        )
        
        return {
            "success": True,
            "message": "User registered successfully",
            "user": user.to_dict(),
            "tokens": {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer"
            }
        }
    except AuthError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/login", response_model=dict)
async def login(data: LoginRequest):
    """Login user"""
    try:
        user, access_token, refresh_token = AuthService.login(
            email=data.email,
            password=data.password
        )
        
        return {
            "success": True,
            "message": "Login successful",
            "user": user.to_dict(),
            "tokens": {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer"
            }
        }
    except AuthError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/refresh", response_model=dict)
async def refresh_token(data: RefreshTokenRequest):
    """Refresh access token"""
    try:
        access_token = AuthService.refresh_access_token(data.refresh_token)
        
        return {
            "success": True,
            "access_token": access_token,
            "token_type": "bearer"
        }
    except AuthError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/forgot-password", response_model=dict)
async def forgot_password(data: ForgotPasswordRequest):
    """Request password reset"""
    try:
        reset_token = AuthService.generate_password_reset_token(data.email)
        
        # In production, send this via email
        # For demo, we return it (DON'T DO THIS IN PRODUCTION!)
        reset_url = f"http://yourapp.com/reset-password?token={reset_token}"
        
        return {
            "success": True,
            "message": "Password reset link sent to email",
            # Remove in production:
            "reset_url": reset_url
        }
    except AuthError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/reset-password", response_model=dict)
async def reset_password(data: ResetPasswordRequest):
    """Reset password with token"""
    try:
        AuthService.reset_password(data.token, data.new_password)
        
        return {
            "success": True,
            "message": "Password reset successful"
        }
    except AuthError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


# Protected routes

@router.get("/me", response_model=dict)
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current user info"""
    return {
        "success": True,
        "user": current_user.to_dict()
    }


@router.post("/change-password", response_model=dict)
async def change_password(
    data: ChangePasswordRequest,
    current_user: User = Depends(get_current_user)
):
    """Change password"""
    try:
        AuthService.change_password(
            current_user.id,
            data.old_password,
            data.new_password
        )
        
        return {
            "success": True,
            "message": "Password changed successfully"
        }
    except AuthError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/logout", response_model=dict)
async def logout(current_user: User = Depends(get_current_user)):
    """Logout user"""
    try:
        AuthService.logout(current_user.id)
        
        return {
            "success": True,
            "message": "Logged out successfully"
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


# Protected route example
@router.get("/api/websites", response_model=dict)
async def get_websites(current_user: User = Depends(get_current_user)):
    """Get user's websites"""
    with get_db() as db:
        if current_user.is_admin():
            # Admin can see all websites
            websites = db.query(Website).all()
        else:
            # Regular users see only their websites
            websites = db.query(Website).filter(Website.user_id == current_user.id).all()

        return {
            "success": True,
            "websites": [w.to_dict() for w in websites]
        }


# Admin-only route example
@router.get("/api/admin/users", response_model=dict)
async def get_all_users(current_user: User = Depends(get_current_admin_user)):
    """Get all users (admin only)"""
    with get_db() as db:
        users = db.query(User).all()
        
        return {
            "success": True,
            "users": [u.to_dict() for u in users]
        }


# Role-based route example
@router.get("/api/reseller/clients", response_model=dict)
async def get_clients(
    current_user: User = Depends(require_role(UserRole.ADMIN))
):
    """Get clients (admin and reseller only)"""
    return {
        "success": True,
        "message": f"Hello {current_user.role.value}!"
    }
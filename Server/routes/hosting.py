"""
Hosting plan and subscription routes
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta

from routes.auth import get_current_user, get_current_admin_user
from src.models import User, HostingPlan, Subscription
from src.database import get_db

router = APIRouter()


class CreatePlanRequest(BaseModel):
    """Request model for creating a hosting plan (admin only)"""
    name: str
    price: float  # In dollars
    max_websites: int
    storage_gb: int
    bandwidth_gb: int
    ssl_enabled: bool = True
    backups_enabled: bool = True
    staging_enabled: bool = False
    cdn_enabled: bool = False


class UpdatePlanRequest(BaseModel):
    """Request model for updating a hosting plan (admin only)"""
    price: Optional[float] = None
    max_websites: Optional[int] = None
    storage_gb: Optional[int] = None
    bandwidth_gb: Optional[int] = None
    ssl_enabled: Optional[bool] = None
    backups_enabled: Optional[bool] = None
    staging_enabled: Optional[bool] = None
    cdn_enabled: Optional[bool] = None
    is_active: Optional[bool] = None


@router.get("/plans", response_model=dict)
async def get_hosting_plans():
    """Get all active hosting plans"""
    with get_db() as db:
        plans = db.query(HostingPlan).filter(HostingPlan.is_active == True).all()

        return {
            "success": True,
            "plans": [plan.to_dict() for plan in plans]
        }


@router.get("/plans/{plan_id}", response_model=dict)
async def get_hosting_plan(plan_id: int):
    """Get a specific hosting plan"""
    with get_db() as db:
        plan = db.query(HostingPlan).filter(HostingPlan.id == plan_id).first()

        if not plan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Hosting plan not found"
            )

        return {
            "success": True,
            "plan": plan.to_dict()
        }


@router.post("/plans", response_model=dict, status_code=status.HTTP_201_CREATED)
async def create_hosting_plan(
    data: CreatePlanRequest,
    current_user: User = Depends(get_current_admin_user)
):
    """Create a new hosting plan (admin only)"""
    with get_db() as db:
        # Check if plan name already exists
        existing = db.query(HostingPlan).filter(HostingPlan.name == data.name).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Plan with this name already exists"
            )

        plan = HostingPlan(
            name=data.name,
            price=int(data.price * 100),  # Convert dollars to cents
            max_websites=data.max_websites,
            storage_gb=data.storage_gb,
            bandwidth_gb=data.bandwidth_gb,
            ssl_enabled=data.ssl_enabled,
            backups_enabled=data.backups_enabled,
            staging_enabled=data.staging_enabled,
            cdn_enabled=data.cdn_enabled
        )
        db.add(plan)
        db.commit()
        db.refresh(plan)

        return {
            "success": True,
            "message": "Hosting plan created successfully",
            "plan": plan.to_dict()
        }


@router.put("/plans/{plan_id}", response_model=dict)
async def update_hosting_plan(
    plan_id: int,
    data: UpdatePlanRequest,
    current_user: User = Depends(get_current_admin_user)
):
    """Update a hosting plan (admin only)"""
    with get_db() as db:
        plan = db.query(HostingPlan).filter(HostingPlan.id == plan_id).first()

        if not plan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Hosting plan not found"
            )

        # Update fields
        if data.price is not None:
            plan.price = int(data.price * 100)
        if data.max_websites is not None:
            plan.max_websites = data.max_websites
        if data.storage_gb is not None:
            plan.storage_gb = data.storage_gb
        if data.bandwidth_gb is not None:
            plan.bandwidth_gb = data.bandwidth_gb
        if data.ssl_enabled is not None:
            plan.ssl_enabled = data.ssl_enabled
        if data.backups_enabled is not None:
            plan.backups_enabled = data.backups_enabled
        if data.staging_enabled is not None:
            plan.staging_enabled = data.staging_enabled
        if data.cdn_enabled is not None:
            plan.cdn_enabled = data.cdn_enabled
        if data.is_active is not None:
            plan.is_active = data.is_active

        db.commit()
        db.refresh(plan)

        return {
            "success": True,
            "message": "Hosting plan updated successfully",
            "plan": plan.to_dict()
        }


@router.get("/subscription", response_model=dict)
async def get_my_subscription(current_user: User = Depends(get_current_user)):
    """Get current user's subscription"""
    with get_db() as db:
        subscription = db.query(Subscription).filter(
            Subscription.user_id == current_user.id,
            Subscription.status == "active"
        ).first()

        if not subscription:
            return {
                "success": True,
                "subscription": None,
                "message": "No active subscription"
            }

        # Get usage statistics
        from src.models import Website
        websites = db.query(Website).filter(Website.user_id == current_user.id).all()

        total_disk_usage = sum(w.disk_usage for w in websites)
        total_websites = len(websites)

        usage = {
            "websites_used": total_websites,
            "websites_limit": subscription.plan.max_websites,
            "storage_used_mb": total_disk_usage,
            "storage_limit_gb": subscription.plan.storage_gb,
        }

        return {
            "success": True,
            "subscription": subscription.to_dict(),
            "usage": usage
        }


@router.post("/subscription/subscribe/{plan_id}", response_model=dict)
async def subscribe_to_plan(
    plan_id: int,
    current_user: User = Depends(get_current_user)
):
    """Subscribe to a hosting plan"""
    with get_db() as db:
        # Check if plan exists
        plan = db.query(HostingPlan).filter(
            HostingPlan.id == plan_id,
            HostingPlan.is_active == True
        ).first()

        if not plan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Hosting plan not found"
            )

        # Check if user already has an active subscription
        existing = db.query(Subscription).filter(
            Subscription.user_id == current_user.id,
            Subscription.status == "active"
        ).first()

        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You already have an active subscription. Cancel it first or upgrade instead."
            )

        # Create subscription
        now = datetime.utcnow()
        subscription = Subscription(
            user_id=current_user.id,
            plan_id=plan_id,
            status="active",
            current_period_start=now,
            current_period_end=now + timedelta(days=30)  # Monthly billing
        )
        db.add(subscription)
        db.commit()
        db.refresh(subscription)

        return {
            "success": True,
            "message": f"Successfully subscribed to {plan.name} plan",
            "subscription": subscription.to_dict()
        }


@router.post("/subscription/upgrade/{plan_id}", response_model=dict)
async def upgrade_subscription(
    plan_id: int,
    current_user: User = Depends(get_current_user)
):
    """Upgrade to a different hosting plan"""
    with get_db() as db:
        # Get current subscription
        current_sub = db.query(Subscription).filter(
            Subscription.user_id == current_user.id,
            Subscription.status == "active"
        ).first()

        if not current_sub:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No active subscription found"
            )

        # Check if new plan exists
        new_plan = db.query(HostingPlan).filter(
            HostingPlan.id == plan_id,
            HostingPlan.is_active == True
        ).first()

        if not new_plan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Hosting plan not found"
            )

        if current_sub.plan_id == plan_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You are already on this plan"
            )

        # Update subscription
        current_sub.plan_id = plan_id
        db.commit()
        db.refresh(current_sub)

        return {
            "success": True,
            "message": f"Successfully upgraded to {new_plan.name} plan",
            "subscription": current_sub.to_dict()
        }


@router.post("/subscription/cancel", response_model=dict)
async def cancel_subscription(current_user: User = Depends(get_current_user)):
    """Cancel subscription (at end of billing period)"""
    with get_db() as db:
        subscription = db.query(Subscription).filter(
            Subscription.user_id == current_user.id,
            Subscription.status == "active"
        ).first()

        if not subscription:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No active subscription found"
            )

        subscription.cancel_at_period_end = True
        db.commit()

        return {
            "success": True,
            "message": f"Subscription will be cancelled on {subscription.current_period_end.strftime('%Y-%m-%d')}"
        }


@router.post("/subscription/reactivate", response_model=dict)
async def reactivate_subscription(current_user: User = Depends(get_current_user)):
    """Reactivate a cancelled subscription"""
    with get_db() as db:
        subscription = db.query(Subscription).filter(
            Subscription.user_id == current_user.id,
            Subscription.status == "active",
            Subscription.cancel_at_period_end == True
        ).first()

        if not subscription:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No cancelled subscription found"
            )

        subscription.cancel_at_period_end = False
        db.commit()

        return {
            "success": True,
            "message": "Subscription reactivated successfully"
        }

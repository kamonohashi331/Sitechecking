"""
Website management routes
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, validator
from typing import Optional, List
import re

from routes.auth import get_current_user, get_current_admin_user
from src.models import User, Website, WebsiteStatus, TaskType
from src.database import get_db
from src.task_queue import task_queue

router = APIRouter()


class CreateWebsiteRequest(BaseModel):
    """Request model for creating a website"""
    name: str
    php_version: Optional[str] = "8.2"
    install_wordpress: bool = False

    @validator('name')
    def validate_domain(cls, v):
        # Basic domain validation
        pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
        if not re.match(pattern, v.lower()):
            raise ValueError('Invalid domain name format')
        return v.lower()


class UpdateWebsiteRequest(BaseModel):
    """Request model for updating a website"""
    php_version: Optional[str] = None
    backup_enabled: Optional[bool] = None
    backup_frequency: Optional[str] = None


@router.get("", response_model=dict)
async def get_websites(
    status_filter: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """Get all websites for the current user"""
    with get_db() as db:
        query = db.query(Website).filter(Website.user_id == current_user.id)

        if status_filter:
            try:
                status_enum = WebsiteStatus[status_filter.upper()]
                query = query.filter(Website.status == status_enum)
            except KeyError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid status: {status_filter}"
                )

        websites = query.order_by(Website.created_at.desc()).all()

        return {
            "success": True,
            "websites": [website.to_dict() for website in websites]
        }


@router.get("/{website_id}", response_model=dict)
async def get_website(
    website_id: int,
    current_user: User = Depends(get_current_user)
):
    """Get a specific website"""
    with get_db() as db:
        website = db.query(Website).filter(
            Website.id == website_id,
            Website.user_id == current_user.id
        ).first()

        if not website:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Website not found"
            )

        return {
            "success": True,
            "website": website.to_dict()
        }


@router.post("", response_model=dict, status_code=status.HTTP_201_CREATED)
async def create_website(
    data: CreateWebsiteRequest,
    current_user: User = Depends(get_current_user)
):
    """Create a new website (queues a background task)"""
    with get_db() as db:
        # Check if website already exists
        existing = db.query(Website).filter(Website.name == data.name).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Website with this domain already exists"
            )

        # Create website record
        website = Website(
            user_id=current_user.id,
            name=data.name,
            status=WebsiteStatus.INSTALLING,
            site_path=f"/home/{current_user.id}/{data.name}"
        )
        db.add(website)
        db.commit()
        db.refresh(website)
        website_id = website.id

    # Queue background task for website creation
    task = await task_queue.enqueue_task(
        user_id=current_user.id,
        task_type=TaskType.WEBSITE_CREATE,
        title=f"Creating website: {data.name}",
        description=f"Installing {data.name} with PHP {data.php_version}",
        website_id=website_id,
        input_data={
            "website_id": website_id,
            "domain": data.name,
            "php_version": data.php_version,
            "install_wordpress": data.install_wordpress
        }
    )

    return {
        "success": True,
        "message": "Website creation started",
        "website": website.to_dict(),
        "task": task.to_dict()
    }


@router.put("/{website_id}", response_model=dict)
async def update_website(
    website_id: int,
    data: UpdateWebsiteRequest,
    current_user: User = Depends(get_current_user)
):
    """Update website settings"""
    with get_db() as db:
        website = db.query(Website).filter(
            Website.id == website_id,
            Website.user_id == current_user.id
        ).first()

        if not website:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Website not found"
            )

        # Update fields
        if data.backup_enabled is not None:
            website.backup_enabled = data.backup_enabled
        if data.backup_frequency is not None:
            website.backup_frequency = data.backup_frequency

        db.commit()
        db.refresh(website)

        return {
            "success": True,
            "message": "Website updated successfully",
            "website": website.to_dict()
        }


@router.delete("/{website_id}", response_model=dict)
async def delete_website(
    website_id: int,
    current_user: User = Depends(get_current_user)
):
    """Delete a website (queues a background task)"""
    with get_db() as db:
        website = db.query(Website).filter(
            Website.id == website_id,
            Website.user_id == current_user.id
        ).first()

        if not website:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Website not found"
            )

        # Update status to DELETING
        website.status = WebsiteStatus.DELETING
        db.commit()

    # Queue background task for website deletion
    task = await task_queue.enqueue_task(
        user_id=current_user.id,
        task_type=TaskType.WEBSITE_DELETE,
        title=f"Deleting website: {website.name}",
        description=f"Removing all files and configurations",
        website_id=website_id,
        input_data={"website_id": website_id}
    )

    return {
        "success": True,
        "message": "Website deletion started",
        "task": task.to_dict()
    }


@router.post("/{website_id}/suspend", response_model=dict)
async def suspend_website(
    website_id: int,
    current_user: User = Depends(get_current_admin_user)  # Admin only
):
    """Suspend a website"""
    with get_db() as db:
        website = db.query(Website).filter(Website.id == website_id).first()

        if not website:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Website not found"
            )

        website.status = WebsiteStatus.SUSPENDED
        from datetime import datetime
        website.suspended_at = datetime.utcnow()
        db.commit()

        return {
            "success": True,
            "message": "Website suspended successfully"
        }


@router.post("/{website_id}/activate", response_model=dict)
async def activate_website(
    website_id: int,
    current_user: User = Depends(get_current_admin_user)  # Admin only
):
    """Activate a suspended website"""
    with get_db() as db:
        website = db.query(Website).filter(Website.id == website_id).first()

        if not website:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Website not found"
            )

        website.status = WebsiteStatus.ACTIVE
        website.suspended_at = None
        db.commit()

        return {
            "success": True,
            "message": "Website activated successfully"
        }


@router.get("/{website_id}/stats", response_model=dict)
async def get_website_stats(
    website_id: int,
    current_user: User = Depends(get_current_user)
):
    """Get website statistics"""
    with get_db() as db:
        website = db.query(Website).filter(
            Website.id == website_id,
            Website.user_id == current_user.id
        ).first()

        if not website:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Website not found"
            )

        # Calculate statistics
        stats = {
            "disk_usage": website.disk_usage,
            "disk_quota": website.disk_quota,
            "disk_usage_percentage": (website.disk_usage / website.disk_quota * 100) if website.disk_quota else 0,
            "backup_count": len(website.backups),
            "last_backup": website.last_backup_at.isoformat() if website.last_backup_at else None,
        }

        return {
            "success": True,
            "stats": stats
        }

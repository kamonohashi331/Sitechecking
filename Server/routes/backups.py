"""
Backup management routes
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

from routes.auth import get_current_user
from src.models import User, Website, Backup, TaskType
from src.database import get_db
from src.task_queue import task_queue

router = APIRouter()


class CreateBackupRequest(BaseModel):
    """Request model for creating a backup"""
    website_id: int
    encrypt: bool = False


@router.get("/backups", response_model=dict)
async def get_backups(
    website_id: Optional[int] = None,
    current_user: User = Depends(get_current_user)
):
    """Get all backups for the current user"""
    with get_db() as db:
        # First, get user's websites to ensure they own them
        user_website_ids = [w.id for w in db.query(Website).filter(
            Website.user_id == current_user.id
        ).all()]

        query = db.query(Backup).filter(Backup.website_id.in_(user_website_ids))

        if website_id:
            if website_id not in user_website_ids:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You don't have access to this website"
                )
            query = query.filter(Backup.website_id == website_id)

        backups = query.order_by(Backup.created_at.desc()).limit(100).all()

        return {
            "success": True,
            "backups": [backup.to_dict() for backup in backups]
        }


@router.get("/backups/{backup_id}", response_model=dict)
async def get_backup(
    backup_id: int,
    current_user: User = Depends(get_current_user)
):
    """Get a specific backup"""
    with get_db() as db:
        backup = db.query(Backup).filter(Backup.id == backup_id).first()

        if not backup:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Backup not found"
            )

        # Check if user owns the website
        website = db.query(Website).filter(
            Website.id == backup.website_id,
            Website.user_id == current_user.id
        ).first()

        if not website:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have access to this backup"
            )

        return {
            "success": True,
            "backup": backup.to_dict()
        }


@router.post("/backups", response_model=dict, status_code=status.HTTP_201_CREATED)
async def create_backup(
    data: CreateBackupRequest,
    current_user: User = Depends(get_current_user)
):
    """Create a new backup (queues a background task)"""
    with get_db() as db:
        # Check if user owns the website
        website = db.query(Website).filter(
            Website.id == data.website_id,
            Website.user_id == current_user.id
        ).first()

        if not website:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Website not found"
            )

        # Create backup record
        backup = Backup(
            website_id=data.website_id,
            is_encrypted=data.encrypt
        )
        db.add(backup)
        db.commit()
        db.refresh(backup)
        backup_id = backup.id

    # Queue background task for backup creation
    task = await task_queue.enqueue_task(
        user_id=current_user.id,
        task_type=TaskType.BACKUP_CREATE,
        title=f"Creating backup for {website.name}",
        description=f"Backing up files and database",
        website_id=website.id,
        input_data={
            "backup_id": backup_id,
            "website_id": website.id,
            "encrypt": data.encrypt
        }
    )

    return {
        "success": True,
        "message": "Backup creation started",
        "backup": backup.to_dict(),
        "task": task.to_dict()
    }


@router.delete("/backups/{backup_id}", response_model=dict)
async def delete_backup(
    backup_id: int,
    current_user: User = Depends(get_current_user)
):
    """Delete a backup"""
    with get_db() as db:
        backup = db.query(Backup).filter(Backup.id == backup_id).first()

        if not backup:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Backup not found"
            )

        # Check if user owns the website
        website = db.query(Website).filter(
            Website.id == backup.website_id,
            Website.user_id == current_user.id
        ).first()

        if not website:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have access to this backup"
            )

        # Delete backup
        db.delete(backup)
        db.commit()

        return {
            "success": True,
            "message": "Backup deleted successfully"
        }


@router.post("/backups/{backup_id}/restore", response_model=dict)
async def restore_backup(
    backup_id: int,
    current_user: User = Depends(get_current_user)
):
    """Restore a website from backup (queues a background task)"""
    with get_db() as db:
        backup = db.query(Backup).filter(Backup.id == backup_id).first()

        if not backup:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Backup not found"
            )

        # Check if user owns the website
        website = db.query(Website).filter(
            Website.id == backup.website_id,
            Website.user_id == current_user.id
        ).first()

        if not website:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have access to this backup"
            )

    # Queue background task for backup restoration
    task = await task_queue.enqueue_task(
        user_id=current_user.id,
        task_type=TaskType.BACKUP_RESTORE,
        title=f"Restoring backup for {website.name}",
        description=f"Restoring from backup created on {backup.created_at.strftime('%Y-%m-%d %H:%M')}",
        website_id=website.id,
        input_data={
            "backup_id": backup_id,
            "website_id": website.id
        }
    )

    return {
        "success": True,
        "message": "Backup restoration started",
        "task": task.to_dict()
    }


@router.get("/websites/{website_id}/backups", response_model=dict)
async def get_website_backups(
    website_id: int,
    current_user: User = Depends(get_current_user)
):
    """Get all backups for a specific website"""
    with get_db() as db:
        # Check if user owns the website
        website = db.query(Website).filter(
            Website.id == website_id,
            Website.user_id == current_user.id
        ).first()

        if not website:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Website not found"
            )

        backups = db.query(Backup).filter(
            Backup.website_id == website_id
        ).order_by(Backup.created_at.desc()).all()

        return {
            "success": True,
            "backups": [backup.to_dict() for backup in backups]
        }

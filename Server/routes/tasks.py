"""
Task and SSE routes for real-time progress updates
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional, List
import asyncio
import json

from routes.auth import get_current_user
from src.models import User, Task, TaskStatus
from src.database import get_db
from src.task_queue import task_queue

router = APIRouter()


class TaskResponse(BaseModel):
    """Task response model"""
    id: int
    task_type: str
    status: str
    title: str
    description: Optional[str]
    progress: int
    current_step: Optional[str]
    total_steps: int
    error_message: Optional[str]
    created_at: str
    started_at: Optional[str]
    completed_at: Optional[str]

    class Config:
        from_attributes = True


@router.get("/tasks", response_model=dict)
async def get_tasks(
    status_filter: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """Get all tasks for the current user"""
    with get_db() as db:
        query = db.query(Task).filter(Task.user_id == current_user.id)

        if status_filter:
            try:
                status_enum = TaskStatus[status_filter.upper()]
                query = query.filter(Task.status == status_enum)
            except KeyError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid status: {status_filter}"
                )

        tasks = query.order_by(Task.created_at.desc()).limit(50).all()

        return {
            "success": True,
            "tasks": [task.to_dict() for task in tasks]
        }


@router.get("/tasks/{task_id}", response_model=dict)
async def get_task(
    task_id: int,
    current_user: User = Depends(get_current_user)
):
    """Get a specific task"""
    with get_db() as db:
        task = db.query(Task).filter(
            Task.id == task_id,
            Task.user_id == current_user.id
        ).first()

        if not task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Task not found"
            )

        return {
            "success": True,
            "task": task.to_dict()
        }


@router.delete("/tasks/{task_id}", response_model=dict)
async def cancel_task(
    task_id: int,
    current_user: User = Depends(get_current_user)
):
    """Cancel a pending/running task"""
    with get_db() as db:
        task = db.query(Task).filter(
            Task.id == task_id,
            Task.user_id == current_user.id
        ).first()

        if not task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Task not found"
            )

        if task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot cancel task with status: {task.status.value}"
            )

        task.status = TaskStatus.CANCELLED
        db.commit()

        return {
            "success": True,
            "message": "Task cancelled successfully"
        }


@router.get("/tasks/stream/events")
async def task_events_stream(current_user: User = Depends(get_current_user)):
    """
    Server-Sent Events endpoint for real-time task updates

    Usage from client:
    const eventSource = new EventSource('/api/tasks/stream/events', {
        headers: { 'Authorization': 'Bearer YOUR_TOKEN' }
    });

    eventSource.onmessage = (event) => {
        const task = JSON.parse(event.data);
        console.log('Task update:', task);
    };
    """

    async def event_generator():
        """Generate SSE events for task updates"""
        queue = asyncio.Queue()

        # Register this client to receive task updates
        task_queue.add_sse_client(current_user.id, queue)

        try:
            # Send initial connection message
            yield f"data: {json.dumps({'connected': True, 'user_id': current_user.id})}\n\n"

            # Send existing pending/running tasks
            with get_db() as db:
                active_tasks = db.query(Task).filter(
                    Task.user_id == current_user.id,
                    Task.status.in_([TaskStatus.PENDING, TaskStatus.RUNNING])
                ).all()

                for task in active_tasks:
                    yield f"data: {json.dumps(task.to_dict())}\n\n"

            # Stream updates as they come
            while True:
                try:
                    # Wait for new updates with a timeout
                    message = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield message
                except asyncio.TimeoutError:
                    # Send keepalive ping every 30 seconds
                    yield ": keepalive\n\n"

        except asyncio.CancelledError:
            # Client disconnected
            pass
        finally:
            # Unregister client
            task_queue.remove_sse_client(current_user.id, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"  # Disable nginx buffering
        }
    )

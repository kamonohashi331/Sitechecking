from datetime import date
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import json

import src.utils as utl

router = APIRouter()

@router.get("/")
async def hi_handler():
    return("User route is working")

#@router.get("/{course_id}")
#async def course_handler(
#        course_id: str,
#    ):
#
#    return JSONResponse(content={})

class signBody(BaseModel):
    qrid: str

@router.post("/sign/{course_id}")
async def sign_handler(
        course_id: str,
        body: signBody
    ):

    print(f"Signing {course_id} with {body.qrid}")

    r = api.setPresent(course_id, body.qrid)

    if r.status_code<200 or r.status_code>299:
        raise HTTPException(status_code=r.status_code, detail=r.text)

    return JSONResponse(content=json.loads(r.text))

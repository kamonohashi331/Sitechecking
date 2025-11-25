import argparse
import asyncio
from math import *
import uvicorn
import src.Colors as clr
from fastapi import FastAPI, HTTPException, Depends, Header, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import os
import sys
from contextlib import asynccontextmanager
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from routes.user import router as user_router
from routes.auth import router as auth_router
from routes.websites import router as websites_router
from routes.hosting import router as hosting_router
from routes.backups import router as backups_router
from routes.tasks import router as tasks_router

MAX_LINE_LENGTH = 65

host = "0.0.0.0"
port = 21580
dbg = True
wdir = os.path.dirname(os.path.realpath(__file__))
workersnb = 4 if not dbg else 1


@asynccontextmanager
async def lifespan(app: FastAPI):
    #asyncio.create_task(test_events())


    print("🟢 Server is up and ready\n")

    yield

    print("⛔ Shutting down the Server...\n")



class RequestLoggerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if (not "text/event-stream" in request.headers.get("Accept", "")):
            mtcl = {"GET": clr.NONE, "POST":clr.MAGENTA, "PUT":clr.LIGHT_GREEN, "OPTIONS":clr.LIGHT_CYAN}
            print(f"{mtcl[request.method] if request.method in mtcl.keys() else clr.NONE}[{request.method}]{clr.NONE}", end='')
            
            host = str(request.base_url)
            if ("://" in host):
                host=host.split("://")[1]
            host=host.split("/")[0]
            endpoint=str(request.url).split(host)[1]

            host=host.split(":")[0]

            print(f" {host} : {endpoint} ->", end='')
            
            response = await call_next(request)
            body = b"".join([chunk async for chunk in response.body_iterator])

            rpc=clr.NONE
            if response.status_code<300: # GOOD
                rpc=clr.GREEN
            elif response.status_code<400: # REDIRECTION
                rpc=clr.LIGHT_BLACK
            elif response.status_code<500: # BAD
                rpc=clr.LIGHT_RED
            else: # SERVER ERROR
                rpc=clr.RED
            print(f" {rpc}{response.status_code}{clr.NONE}")

            try:
                bdd = body.decode(errors="replace")
                print(f"   -> {bdd[:100]}{'...' if len(bdd)>100 else ''}\n")
            except Exception as e:
                pass
            
            async def response_stream():
                yield body

            return StreamingResponse(response_stream(), 
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.media_type
            )
        else:
            response = await call_next(request)
            return(response)







app = FastAPI(lifespan=lifespan)

# CORS middleware must be added BEFORE routes
if (dbg):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Allows all origins (any host)
        allow_credentials=True,
        allow_methods=["*"],  # Allows all HTTP methods (GET, POST, etc.)
        allow_headers=["*"],  # Allows all headers
    )
    app.add_middleware(RequestLoggerMiddleware)
else:
    # Production CORS - only allow your frontend domain
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "https://hosting.austerfortia.fr",
            "https://www.hosting.austerfortia.fr",
            "https://api.hosting.austerfortia.fr",
            "http://localhost:4200",  # For local development
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Routes (added after middleware)
app.include_router(user_router, prefix="/user", tags=["User"])
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(websites_router, prefix="/websites", tags=["Websites"])
app.include_router(hosting_router, prefix="/hosting", tags=["Hosting"])
app.include_router(backups_router, prefix="/backups", tags=["Backups"])
app.include_router(tasks_router, prefix="/tasks", tags=["Tasks"])

# Endpoints
@app.get("/")
def none_handler():
    return("Hosting API is running")







if (__name__=="__main__"):
    # SSL configuration
    use_ssl = True  # Set to True to enable SSL, False to disable
    ssl_keyfile = os.path.join(wdir, "certs/key.pem") if use_ssl else None
    ssl_certfile = os.path.join(wdir, "certs/cert.pem") if use_ssl else None

    protocol = "https" if use_ssl else "http"
    print(f"🚀 Starting the SoundPool server on {clr.CYAN}{protocol}://{host}:{port}{clr.NONE}.\n")

    if (dbg):
        print(f"⚠️ {clr.YELLOW}Warning{clr.NONE}, DEBUG mode is activated. \n{clr.LIGHT_RED}Do not use this mode for production!{clr.NONE}")
        pll = MAX_LINE_LENGTH+16
        print(f"{clr.YELLOW}╔{'═'*pll}{clr.NONE}")

        debug_messages = [
            f"The number of workers was reduced to {clr.LIGHT_RED}{workersnb}{clr.NONE}",
            f"The CORS wildcard is activated.",
            f"The DEBUG middleware is activated.",
            f"The server will reload on changes in {clr.UNDERLINE}{wdir}{clr.NONE}"
        ]

        if use_ssl:
            debug_messages.append(f"SSL enabled with {clr.LIGHT_RED}self-signed{clr.NONE} certificate")

        for ll in debug_messages:
            if (len(ll) > MAX_LINE_LENGTH):
                print(f"{clr.YELLOW}║{clr.NONE} ", end="")

                print(ll[:MAX_LINE_LENGTH])
                lcl=clr.lastUsed(ll[:MAX_LINE_LENGTH])
                for i in range(1, floor(len(ll)/(MAX_LINE_LENGTH+1))+1):
                    print(f"{clr.NONE}{clr.YELLOW}║{clr.NONE} ", end="")
                    print((" "*5)+lcl+ll[(MAX_LINE_LENGTH*i):(MAX_LINE_LENGTH*(i+1))]+clr.NONE)
                    lcl=clr.lastUsed(ll[(MAX_LINE_LENGTH*i):(MAX_LINE_LENGTH*(i+1))])
            else:
                print(f"{clr.YELLOW}║{clr.NONE} {ll}")

        print(f"{clr.YELLOW}╚{'═'*pll}{clr.NONE}\n")
    else:
        if (workersnb<3):
            print(f"⚠️ {clr.YELLOW}Warning{clr.NONE}, for a production environment, {workersnb} workers might not be enough.")
        else:
            print(f"⛏️ Running {workersnb} workers")

    if use_ssl:
        print(f"🔒 SSL/HTTPS enabled\n")

    print("")

    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=dbg,
        workers=workersnb,
        log_level="warning",
        access_log=dbg,
        ssl_keyfile=ssl_keyfile,
        ssl_certfile=ssl_certfile
    )
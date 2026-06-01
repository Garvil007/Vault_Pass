"""VaultPass FastAPI application entrypoint.

Builds the app, configures CORS for the local frontend dev servers, mounts the
auth and vault routers, and exposes a health check. Run with:

    myenv\\Scripts\\python.exe -m uvicorn api.main:app --reload
"""
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routers import auth, vault

# Load .env into os.environ before anything reads config (DB URL, Argon2 params).
load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown hooks."""
    print("VaultPass API starting")
    yield


app = FastAPI(title="VaultPass", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(vault.router)


@app.get("/")
def health_check():
    return {"status": "ok"}

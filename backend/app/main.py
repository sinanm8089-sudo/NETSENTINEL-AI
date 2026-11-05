"""NETSENTINEL AI — Main FastAPI Application Entrypoint."""
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.router import api_router
from app.config import settings
from app.core.auth import CurrentActor
from app.core.websocket_hub import ws_hub
from app.database import Base, SessionLocal, engine
from app.services.seed_service import initialize_platform_seed_data
from app.services.terminal_dispatcher import dispatch_terminal_command


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        initialize_platform_seed_data(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=(
        "Autonomous Enterprise Network Discovery, Intelligence & Security Monitoring Platform. "
        "Created by Sinan Mohammed."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.API_V1_STR)


@app.websocket("/ws/events")
async def websocket_events_endpoint(websocket: WebSocket):
    """PRD Section 10: Real-time dashboard and topology event stream."""
    await ws_hub.connect_events(websocket)
    try:
        await websocket.send_json(
            {
                "event_type": "connection.established",
                "payload": {"message": "Connected to NETSENTINEL AI Live Telemetry Stream."},
            }
        )
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_hub.disconnect_events(websocket)
    except Exception:
        ws_hub.disconnect_events(websocket)


@app.websocket("/ws/terminal/{session_id}")
async def websocket_terminal_endpoint(websocket: WebSocket, session_id: str):
    """PRD Section 10 & Module 6: Real-time terminal output stream."""
    await ws_hub.connect_terminal(session_id, websocket)
    try:
        await ws_hub.stream_terminal_line(
            session_id,
            "NETSENTINEL AI Hybrid Terminal Stream Ready. Type 'help' for approved commands.",
        )
        while True:
            raw_cmd = await websocket.receive_text()
            db = SessionLocal()
            try:
                actor = CurrentActor(
                    user_id="sinan.mohammed",
                    username="sinan.mohammed",
                    role="SUPER_ADMIN",
                )
                res = dispatch_terminal_command(db, raw_cmd, actor, session_id=session_id)
                await ws_hub.stream_terminal_line(
                    session_id,
                    res.output,
                    level="INFO" if res.allowed else "ERROR",
                )
            finally:
                db.close()
    except WebSocketDisconnect:
        ws_hub.disconnect_terminal(session_id, websocket)
    except Exception:
        ws_hub.disconnect_terminal(session_id, websocket)


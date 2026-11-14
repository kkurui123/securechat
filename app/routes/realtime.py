import asyncio
import time
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, HTTPException
from starlette.concurrency import run_in_threadpool
from app.guards.auth import guard, token, resolve
from app.core.database import SessionLocal
from app.schemas.auth import MessageInput
from app.services.chat import save_message

router = APIRouter(tags=["Realtime"])
# Single process only. HTTP history is the durable source of truth.
connections: dict[str, set[asyncio.Queue]] = {}

async def publish(users, event):
    for uid in users:
        for q in list(connections.get(uid, set())):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass

@router.post("/ws-token")
def ws_token(user=Depends(guard)):
    return {"token": token(user, "socket", 1800), "expires_in": 1800}

def authenticate(encoded):
    with SessionLocal() as db:
        u, claims = resolve(encoded, db, "socket")
        if u.role != "GUARD":
            raise HTTPException(403, "Guard access required")
        return u.id, claims["exp"]

def process(encoded, event):
    with SessionLocal() as db:
        u, _ = resolve(encoded, db, "socket")
        if event.get("type") != "message.send":
            raise HTTPException(422, "Expected message.send")
        data = MessageInput.model_validate(event.get("message", {}))
        return save_message(db, event["conversation_id"], u, data)

@router.websocket("/ws")
async def socket(ws: WebSocket):
    await ws.accept()
    q = asyncio.Queue(maxsize=100)
    uid = None
    sender = None
    try:
        first = await asyncio.wait_for(ws.receive_json(), timeout=10)
        encoded = first.get("token", "")
        uid, expiry = await run_in_threadpool(authenticate, encoded)
        connections.setdefault(uid, set()).add(q)
        await ws.send_json({"type": "ready"})
        async def writer():
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=15)
                except asyncio.TimeoutError:
                    event = {"type": "ping"}
                await run_in_threadpool(authenticate, encoded)
                await ws.send_json(event)
        sender = asyncio.create_task(writer())
        while time.time() < expiry:
            event = await asyncio.wait_for(ws.receive_json(), timeout=min(30, max(0.1, expiry-time.time())))
            if event.get("type") == "pong":
                continue
            try:
                message, recipients = await run_in_threadpool(process, encoded, event)
                await publish(recipients, {"type": "message", "message": message})
            except (ValueError, KeyError):
                q.put_nowait({"type": "error", "detail": "Invalid message envelope"})
            except HTTPException as exc:
                q.put_nowait({"type": "error", "detail": exc.detail})
    except (WebSocketDisconnect, asyncio.TimeoutError, HTTPException, ValueError, asyncio.QueueFull):
        pass
    finally:
        if uid:
            connections.get(uid, set()).discard(q)
            if not connections.get(uid):
                connections.pop(uid, None)
        if sender:
            sender.cancel()
            await asyncio.gather(sender, return_exceptions=True)
        try:
            await ws.close(code=1000)
        except RuntimeError:
            pass

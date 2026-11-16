import asyncio
import time


from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool


from app.core.database import SessionLocal, get_db
from app.guards.auth import guard, resolve, token
from app.models.entities import Conversation, Message
from app.schemas.auth import MessageInput
from app.services.chat import member, save_message



router = APIRouter(tags=["Realtime"])



# Single process only. HTTP history is the durable source of truth.
connections: dict[str, set[asyncio.Queue]] = {}



async def publish(
    users: list[str],
    event: dict,
) -> None:
    for user_id in users:
        for queue in list(
            connections.get(user_id, set())
        ):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass



@router.post("/ws-token")
def ws_token(
    user=Depends(guard),
):
    return {
        "token": token(
            user,
            "socket",
            1800,
        ),
        "expires_in": 1800,
    }



def authenticate(encoded: str) -> tuple[str, float]:
    with SessionLocal() as db:
        user, claims = resolve(
            encoded,
            db,
            "socket",
        )


        if user.role != "GUARD":
            raise HTTPException(
                status_code=403,
                detail="Guard access required",
            )


        return user.id, claims["exp"]



def process(
    encoded: str,
    event: dict,
) -> tuple[dict, list[str]]:
    with SessionLocal() as db:
        user, _ = resolve(
            encoded,
            db,
            "socket",
        )


        if event.get("type") != "message.send":
            raise HTTPException(
                status_code=422,
                detail="Expected message.send",
            )


        data = MessageInput.model_validate(
            event.get("message", {})
        )


        return save_message(
            db,
            event["conversation_id"],
            user,
            data,
        )



def mark_conversation_read(
    encoded: str,
    conversation_id: str,
) -> tuple[list[str], int]:
    with SessionLocal() as db:
        user, _ = resolve(
            encoded,
            db,
            "socket",
        )


        conversation = member(
            db,
            conversation_id,
            user,
        )


        unread_messages = db.scalars(
            select(Message)
            .where(
                Message.conversation_id == conversation_id,
                Message.sender_id != user.id,
                Message.read_at.is_(None),
            )
            .with_for_update()
        )


        messages = list(unread_messages)


        read_at = None


        if messages:
            from datetime import datetime, timezone


            read_at = datetime.now(timezone.utc)


            for message in messages:
                message.read_at = read_at


            db.commit()


        recipients = [
            conversation.guard_a,
            conversation.guard_b,
        ]


        return recipients, len(messages)



@router.websocket("/ws")
async def socket(
    ws: WebSocket,
):
    await ws.accept()


    queue = asyncio.Queue(maxsize=100)
    user_id = None
    sender = None


    try:
        first = await asyncio.wait_for(
            ws.receive_json(),
            timeout=10,
        )


        encoded = first.get("token", "")


        user_id, expiry = await run_in_threadpool(
            authenticate,
            encoded,
        )


        connections.setdefault(
            user_id,
            set(),
        ).add(queue)


        await ws.send_json(
            {
                "type": "ready",
            }
        )


        async def writer():
            while True:
                try:
                    event = await asyncio.wait_for(
                        queue.get(),
                        timeout=15,
                    )
                except asyncio.TimeoutError:
                    event = {
                        "type": "ping",
                    }


                await run_in_threadpool(
                    authenticate,
                    encoded,
                )


                await ws.send_json(event)


        sender = asyncio.create_task(writer())


        while time.time() < expiry:
            event = await asyncio.wait_for(
                ws.receive_json(),
                timeout=min(
                    30,
                    max(
                        0.1,
                        expiry - time.time(),
                    ),
                ),
            )


            event_type = event.get("type")


            if event_type == "pong":
                continue


            if event_type == "messages.read":
                conversation_id = event.get("conversation_id")


                if not isinstance(conversation_id, str):
                    queue.put_nowait(
                        {
                            "type": "error",
                            "detail": "Invalid conversation ID",
                        }
                    )


                    continue


                try:
                    recipients, marked_count = await run_in_threadpool(
                        mark_conversation_read,
                        encoded,
                        conversation_id,
                    )


                    if marked_count > 0:
                        await publish(
                            recipients,
                            {
                                "type": "messages-read",
                                "conversation_id": conversation_id,
                                "reader_id": user_id,
                                "read_at": None,
                                "count": marked_count,
                            },
                        )
                except HTTPException as error:
                    queue.put_nowait(
                        {
                            "type": "error",
                            "detail": error.detail,
                        }
                    )


                continue


            try:
                message, recipients = await run_in_threadpool(
                    process,
                    encoded,
                    event,
                )


                await publish(
                    recipients,
                    {
                        "type": "message",
                        "message": message,
                    },
                )
            except (ValueError, KeyError):
                queue.put_nowait(
                    {
                        "type": "error",
                        "detail": "Invalid message envelope",
                    }
                )
            except HTTPException as error:
                queue.put_nowait(
                    {
                        "type": "error",
                        "detail": error.detail,
                    }
                )
    except (
        WebSocketDisconnect,
        asyncio.TimeoutError,
        HTTPException,
        ValueError,
        asyncio.QueueFull,
    ):
        pass
    finally:
        if user_id:
            connections.get(
                user_id,
                set(),
            ).discard(queue)


            if not connections.get(user_id):
                connections.pop(user_id, None)


        if sender:
            sender.cancel()


            await asyncio.gather(
                sender,
                return_exceptions=True,
            )


        try:
            await ws.close(code=1000)
        except RuntimeError:
            pass
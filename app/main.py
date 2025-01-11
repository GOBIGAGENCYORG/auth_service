from fastapi import FastAPI, Request, HTTPException, Depends, Response
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Dict
import hashlib

app = FastAPI()

app.mount("/static", StaticFiles(directory="templates"), name="static")

# Пример базы данных пользователей
users_db: Dict[str, str] = {"admin": hashlib.sha256(b"password").hexdigest()}

# OAuth2 токен
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/validate")

# Проверка токена
def authenticate_user(request: Request):
    token = request.cookies.get("Authorization")
    if token and token.startswith("Bearer "):
        token = token.split(" ")[1]
        if token in users_db.values():
            return token
    raise HTTPException(status_code=401, detail="Unauthorized")


@app.post("/login")
async def login(response: Response, form_data: OAuth2PasswordRequestForm = Depends()):
    username, password = form_data.username, form_data.password
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    if users_db.get(username) == password_hash:
        response.set_cookie(key="Authorization", value=f"Bearer {password_hash}")
        return {"access_token": password_hash, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/validate")
async def validate(token: str = Depends(authenticate_user)):
    return RedirectResponse("/")


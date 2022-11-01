from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from decouple import config
from datetime import datetime,timedelta
from modules.jwt.jwt_module import JwtEncoder
import jwt
import deta

app = FastAPI()

PROJECT_KEY = config("PROJECT_KEY")
JWT_SECRET = config("JWT_SECRET")
JWT_ALGORITHM = config("JWT_ALGORITHM")

deta = deta.Deta(PROJECT_KEY)
usersDB = deta.Base("users")


origins = [
    "http://localhost",
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"])


@app.post(
    "/validate",
    description="Validates the token from the request body.",
    response_description="Returns key value pair 'is_valid:boolean'.",
)
def validate_token(token: str):
    pass
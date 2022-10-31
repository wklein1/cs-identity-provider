from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from decouple import config
import deta

app = FastAPI()

PROJECT_KEY = config("PROJECT_KEY")

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
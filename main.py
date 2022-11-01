from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from decouple import config
from datetime import datetime,timedelta
from modules.jwt.jwt_module import JwtEncoder
from models import token_validation_models
import jwt
import deta

app = FastAPI()

PROJECT_KEY = config("PROJECT_KEY")
JWT_SECRET = config("JWT_SECRET")
JWT_ALGORITHM="HS256"
JWT_AUDIENCE="kbe-aw2022-frontend.netlify.app"
JWT_ISSUER="cs-identity-provider.deta.dev"

deta = deta.Deta(PROJECT_KEY)
usersDB = deta.Base("users")

jwt_encoder = JwtEncoder(secret=JWT_SECRET, algorithm=JWT_ALGORITHM)

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
    response_model=token_validation_models.validateResponseModel,
    response_description="Returns key value pair 'is_valid:boolean'.",
)
def validate_token(token: token_validation_models.tokenInModel):
    jwt_token = token.dict()["token"]
    token_is_valid = jwt_encoder.validate_jwt(token=jwt_token,audience=JWT_AUDIENCE,issuer=JWT_ISSUER)
    return {"is_valid":token_is_valid}

print(jwt_encoder.generate_jwt({
    "iss":JWT_ISSUER,
    "aud":JWT_AUDIENCE
}))
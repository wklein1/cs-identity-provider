from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from decouple import config
from datetime import datetime,timedelta
from modules.jwt.jwt_module import JwtEncoder
from modules.password import encryption
from models import token_validation_models, user_models, error_models, auth_models
import uuid
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
def validate_token(token: token_validation_models.tokenModel):
    jwt_token = token.dict()["token"]
    token_is_valid = jwt_encoder.validate_jwt(token=jwt_token,audience=JWT_AUDIENCE,issuer=JWT_ISSUER)
    return {"is_valid":token_is_valid}

@app.post(
    "/users",
    description="Register a new user.",
    status_code=status.HTTP_201_CREATED,
    responses={ 
        503 :{
            "model": error_models.HTTPErrorModel,
            "description": "Error raised if database request fails."
        },
        422 :{
            "model": error_models.HTTPErrorModel,
            "description": "Error raised if provided user data is not valid."
        }},
    response_model=auth_models.RegistrationResponseModel,
    response_description="Returns an object with the user name and access token for the registered user'.",
)
def register_user(user_data: user_models.UserInModel):
    new_user = user_data.dict()
    new_user_id = str(uuid.uuid1())
    new_user["key"] = new_user_id
    new_user["password"] = encryption.hash(new_user["password"])
    try:
        usersDB.insert(new_user)
    except:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Error while connecting to database")
    token_payload={
        "userId":new_user_id,
        "aud":JWT_AUDIENCE,
        "iss":JWT_ISSUER,
        "iat":datetime.now().timestamp(),
        "exp":(datetime.now() + timedelta(minutes=20)).timestamp()
    }
    jwt_token = jwt_encoder.generate_jwt(token_payload)
    return {"user_name":new_user["user_name"], "token":jwt_token}
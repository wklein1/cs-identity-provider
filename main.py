from fastapi import FastAPI, HTTPException, status, Header, Body
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
MICROSERVICE_ACCESS_SECRET = config("MICROSERVICE_ACCESS_SECRET")
JWT_SECRET = config("JWT_SECRET")
JWT_ALGORITHM="HS256"
JWT_AUDIENCE="kbe-aw2022-frontend.netlify.app"
JWT_ISSUER="cs-identity-provider.deta.dev"

deta = deta.Deta(PROJECT_KEY)
usersDB = deta.Base("users")

jwt_encoder = JwtEncoder(secret=JWT_SECRET, algorithm=JWT_ALGORITHM)
microservice_access_jwt_encoder = JwtEncoder(secret=MICROSERVICE_ACCESS_SECRET, algorithm=JWT_ALGORITHM)

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

def protect_route(microservice_access_token:str):
    if not microservice_access_jwt_encoder.validate_jwt(token=microservice_access_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid token")

@app.post(
    "/validate",
    description="Validates the token from the request body.",
    response_model=token_validation_models.validateResponseModel,
    response_description="Returns key value pair 'is_valid:boolean'.",
    tags=["auth"]
)
async def validate_token(token: token_validation_models.tokenModel, microservice_access_token:str = Header(alias="microserviceAccessToken")):
    
    protect_route(microservice_access_token)
    
    jwt_token = token.dict()["token"]
    token_is_valid = jwt_encoder.validate_jwt(token=jwt_token,audience=JWT_AUDIENCE,issuer=JWT_ISSUER)
    return {"is_valid":token_is_valid}


@app.get(
    "/users/{user_id}",
    description="Get user data of a given user.",
    responses={ 
        404 :{
            "model": error_models.HTTPErrorModel,
            "description": "Error raised if the user could not be found."
        }},
    response_model=user_models.UserOutModel,
    response_description="Returns an object with user data.",
    tags=["user data"]
)
async def get_user_data(user_id:str, microservice_access_token:str = Header(alias="microserviceAccessToken")):
    
    protect_route(microservice_access_token)

    user = usersDB.get(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


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
    response_model=auth_models.AuthResponseModel,
    response_description="Returns an object with the user name and access token for the registered user'.",
    tags=["auth"]
)
async def register_user(user_data: user_models.UserInModel, microservice_access_token:str = Header(alias="microserviceAccessToken")):
    
    protect_route(microservice_access_token) 
    
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
        "iat":(datetime.now() - timedelta(seconds=1)).timestamp(),
        "exp":(datetime.now() + timedelta(minutes=20)).timestamp()
    }
    jwt_token = jwt_encoder.generate_jwt(token_payload)
    return {"user_name":new_user["user_name"], "token":jwt_token}


@app.post(
    "/login",
    description="Authenticate a user.",
    response_model=auth_models.AuthResponseModel,
    response_description="Returns an object with the user name and access token for the authenticated user'.",
    tags=["auth"]
)
async def login_user(user_data: auth_models.LoginModel, microservice_access_token:str = Header(alias="microserviceAccessToken")):
    
    protect_route(microservice_access_token)

    authenticated_user = None
   
    user_dict = user_data.dict()
    try:
        db_response = usersDB.fetch({"user_name":user_dict["user_name"]})
    except:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Error while connecting to database")
    
    if len(db_response.items)==0:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid credentials")        
    else:
        for user in db_response.items:
            if encryption.verify(user_dict["password"], user["password"]):
                authenticated_user = user
    
    if authenticated_user is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid credentials")        
    
    token_payload={
        "userId":user["key"],
        "aud":JWT_AUDIENCE,
        "iss":JWT_ISSUER,
        "iat":datetime.now().timestamp(),
        "exp":(datetime.now() + timedelta(minutes=20)).timestamp()
    }
    jwt_token = jwt_encoder.generate_jwt(token_payload)
    return {"user_name":user["user_name"], "token":jwt_token}


@app.patch(
    "/users/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_description="Returns no data.",
    responses={
        503 :{
            "model": error_models.HTTPErrorModel,
            "description": "Error raised if database request fails."
        },
        422 :{
            "model": error_models.HTTPErrorModel,
            "description": "Error raised if provided user updates are not valid."
        },
        403 :{
            "model": error_models.HTTPErrorModel,
            "description": "Error raised if password is invalid."
            },
        404 :{
                "model": error_models.HTTPErrorModel,
                "description": "Error raised if the user can not be found."
        }},
    description="Updates user with values specified in request body.",
    tags=["user data"]
)
async def patch_user_by_id(user_data: user_models.UserUpdatesInModel, user_id: str, microservice_access_token:str = Header(alias="microserviceAccessToken")):
    
    protect_route(microservice_access_token)
    
    user_data_dict = user_data.dict()
    try:
        user = usersDB.get(user_id)
    except:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Error while connecting to database")
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    else:
        #check for password
        if not encryption.verify(plain_password=user_data_dict["password"], hashed_password=user["password"]):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid password")
        
        #try to update user
        user_updates = user_data_dict.copy()
        del user_updates["password"]
        try:
            usersDB.update(updates=user_updates, key=user_id)
        except:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Error while connecting to database")
            

@app.patch(
    "/users/{user_id}/password",
    status_code=status.HTTP_204_NO_CONTENT,
    response_description="Returns no data.",
    responses={
        503 :{
            "model": error_models.HTTPErrorModel,
            "description": "Error raised if database request fails."
        },
        422 :{
            "model": error_models.HTTPErrorModel,
            "description": "Error raised if password update is not valid."
        },
        403 :{
            "model": error_models.HTTPErrorModel,
            "description": "Error raised if user password is invalid."
            },
        404 :{
                "model": error_models.HTTPErrorModel,
                "description": "Error raised if the user can not be found."
        }},
    description="Updates the user password.",
    tags=["user data"]
)
async def change_user_password_by_id(change_password_data: user_models.UserChangePasswordInModel, user_id: str, microservice_access_token:str = Header(alias="microserviceAccessToken")):
    
    protect_route(microservice_access_token)
    
    user_change_password_dict = change_password_data.dict()
    new_password = user_change_password_dict["new_password"]
    try:
        user = usersDB.get(user_id)
    except:
        print("first ex")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Error while connecting to database")
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    else:
        #check for password
        if not encryption.verify(plain_password=user_change_password_dict["password"], hashed_password=user["password"]):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid password")
        try:
            user_password_update={
                "password":encryption.hash(new_password)
            }
            usersDB.update(updates=user_password_update, key=user_id)
        except Exception as ex:
            print("second ex: "+ str(ex))
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Error while connecting to database")
           

@app.delete(
     "/users",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={503 :{
            "model": error_models.HTTPErrorModel,
            "description": "Error raised if database request fails."
        },
        403 :{
            "model": error_models.HTTPErrorModel,
            "description": "Error raised if the provided password is invalid."
        }},
    description="Deletes a user.",
    tags=["user data"]

)
async def delete_user(passwordIn:auth_models.PasswordInModel, user_id: str = Header(alias="userId"), microservice_access_token:str = Header(alias="microserviceAccessToken")):
    
    protect_route(microservice_access_token)
    
    try:
        user = usersDB.get(user_id)
    except:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Error while connecting to database")
    if not user:
        return
    else:
        if not encryption.verify(plain_password=passwordIn.dict()["password"], hashed_password=user["password"]):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid password")
    try:
        usersDB.delete(user_id)
    except:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE)
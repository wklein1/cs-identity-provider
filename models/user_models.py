from models.custom_base_model import CustomBaseModel
from pydantic import Field, EmailStr, constr

PASSWORD_REGEX ="^(?=.*[A-z])(?=.*[0-9]).{8,24}$"

class UserInModel(CustomBaseModel):
    first_name:str = Field(min_length=2, max_length=24)
    last_name:str = Field(min_length=1, max_length=24)
    user_name:str = Field(min_length=3, max_length=24)
    email:EmailStr
    password:constr(regex=PASSWORD_REGEX)
    class Config:
        schema = {
            "demo":{
                "first_name":"first name",
                "last_name":"last name",
                "user_name":"user_name",
                "email":"email@mail.com",
                "password":"123"
            }
        }

class UserOutModel(CustomBaseModel):
    first_name:str
    last_name:str
    user_name:str
    email:EmailStr
    class Config:
        schema = {
            "demo":{
                "first_name":"first name",
                "last_name":"last name",
                "user_name":"user name",
                "email":"email@mail.com",
                "password":"123"
            }
        }

class RegistrationResponseModel(CustomBaseModel):
    user_name:str
    token:str
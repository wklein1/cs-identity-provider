from models.custom_base_model import CustomBaseModel

class UserInModel(CustomBaseModel):
    first_name:str
    last_name:str
    user_name:str
    email:EmailStr
    password:str
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
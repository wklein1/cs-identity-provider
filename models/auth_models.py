class RegistrationResponseModel(CustomBaseModel):
    user_name:str
    token:str

class LoginModel(CustomBaseModel):
    user_name:str
    password:str
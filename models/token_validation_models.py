from models.custom_base_model import CustomBaseModel

class tokenInModel(CustomBaseModel):
    token:str

class validateResponseModel(CustomBaseModel):
    is_valid:bool 
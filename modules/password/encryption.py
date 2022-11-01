from passlib.context import CryptContext

cryptContext = CryptContext(schemes=["bcrypt"])

def hash(password:str):
    return cryptContext.hash(password)


def verify(plain_password:str,hashed_password:str):
    return cryptContext.verify(secret=plain_password, hash=hashed_password) 
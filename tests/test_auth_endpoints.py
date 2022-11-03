from fastapi.testclient import TestClient
from fastapi import status
from decouple import config
from modules.jwt.jwt_module import JwtEncoder
from main import app

VALID_MICROSERVICE_ACCESS_TOKEN = config("VALID_MICROSERVICE_ACCESS_TOKEN")
MICROSERVICE_AUTH_HEADERS = {"microserviceAccessToken":VALID_MICROSERVICE_ACCESS_TOKEN}

def test_login_user_endpoint_success():
    #ARRANGE
    client = TestClient(app)
    test_user = {
        "user_name":"test_usr",
        "password":"testtesttest4"
    }
    #ACT
    response = client.post("/login",json=test_user, headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 200
    assert "token" in response.json()
    assert response.json()["userName"] == "test_usr"


def test_login_user_endpoint_fails_invalid_credentials():
    #ARRANGE
    client = TestClient(app)
    test_user = {
        "user_name":"test_usr",
        "password":"testtesttest1"
    }
    #ACT
    response = client.post("/login",json=test_user, headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 403
    assert response.json() == {'detail': 'Invalid credentials'}


def test_validate_token_endpoint_success():
    #ARRANGE
    VALID_TOKEN = config("VALID_TOKEN")
    client = TestClient(app)
    expected_response = {"isValid":True}
    #ACT
    response = client.post("/validate",json={"token":VALID_TOKEN}, headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 200
    assert response.json() == expected_response


def test_validate_token_endpoint_with_invalid_token():
    #ARRANGE
    client = TestClient(app)
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X2F1ZCIsImlzcyI6InRlc3RfaXNzIn0.idxtUZ-pPMUw6P_TeHA-RW1fhhSZPsglZkZKbWxjlXA"
    expected_response = {"isValid":False}
    #ACT
    response = client.post("/validate",json={"token":test_token}, headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 200
    assert response.json() == expected_response

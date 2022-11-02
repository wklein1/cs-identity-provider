from fastapi.testclient import TestClient
from fastapi import status
from decouple import config
from modules.jwt.jwt_module import JwtEncoder
from main import app

VALID_MICROSERVICE_ACCESS_TOKEN = config("VALID_MICROSERVICE_ACCESS_TOKEN")
MICROSERVICE_AUTH_HEADERS = {"microserviceAccessToken":VALID_MICROSERVICE_ACCESS_TOKEN}

def test_register_user_endpoint_success():
    #ARRANGE
    client = TestClient(app)
    JWT_SECRET = config("JWT_SECRET")
    jwt_aud="kbe-aw2022-frontend.netlify.app"
    jwt_iss="cs-identity-provider.deta.dev"
    jwt_encoder = JwtEncoder(JWT_SECRET, "HS256")
    test_user = {
        "first_name":"test",
        "last_name":"test",
        "user_name":"test_usr2",
        "email":"test@test.com",
        "password":"testtesttest4"
    }
    #ACT
    response = client.post("/users",json=test_user, headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 201
    assert "token" in response.json()
    assert response.json()["userName"] == "test_usr2"
    #CLEANUP
    new_user_id = jwt_encoder.decode_jwt(response.json()["token"],audience=jwt_aud,issuer=jwt_iss)["userId"]
    client.delete("/users", json={"password":"testtesttest4"}, headers={"userId":new_user_id}|MICROSERVICE_AUTH_HEADERS)


def test_register_user_endpoint_fails_user_name_already_taken():
    #ARRANGE
    client = TestClient(app)
    test_user = {
        "first_name":"test",
        "last_name":"test",
        "user_name":"test_usr",
        "email":"test@test.com",
        "password":"testtesttest4"
    }
    expected_error = {
        "detail":"User name is already taken"
    }
    #ACT
    response = client.post("/users",json=test_user, headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 409
    assert response.json() == expected_error


def test_register_user_endpoint_fails_invalid_password():
    #ARRANGE
    client = TestClient(app)
    test_user = {
        "first_name":"test",
        "last_name":"test",
        "user_name":"test_usr",
        "email":"test@test.com",
        "password":"test"
    }
    #ACT
    response = client.post("/users",json=test_user, headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 422


def test_register_user_endpoint_fails_invalid_email():
    #ARRANGE
    client = TestClient(app)
    test_user = {
        "first_name":"test",
        "last_name":"test",
        "user_name":"test_usr",
        "email":"testtest.com",
        "password":"testtesttest4"
    }
    #ACT
    response = client.post("/users",json=test_user, headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 422


def test_register_user_endpoint_fails_invalid_first_name():
    #ARRANGE
    client = TestClient(app)
    test_user = {
        "first_name":"t",
        "last_name":"test",
        "user_name":"test_usr",
        "email":"test@test.com",
        "password":"testtesttest4"
    }
    #ACT
    response = client.post("/users",json=test_user, headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 422


def test_register_user_endpoint_fails_invalid_last_name():
    #ARRANGE
    client = TestClient(app)
    test_user = {
        "first_name":"test",
        "last_name":"",
        "user_name":"test_usr",
        "email":"test@test.com",
        "password":"testtesttest4"
    }
    #ACT
    response = client.post("/users",json=test_user, headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 422


def test_register_user_endpoint_fails_invalid_user_name():
    #ARRANGE
    client = TestClient(app)
    test_user = {
        "first_name":"test",
        "last_name":"test",
        "user_name":"",
        "email":"test@test.com",
        "password":"testtesttest4"
    }
    #ACT
    response = client.post("/users",json=test_user, headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 422

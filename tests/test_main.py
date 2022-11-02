from fastapi.testclient import TestClient
from fastapi import status
from decouple import config
from modules.jwt.jwt_module import JwtEncoder
from main import app

def test_login_user_endpoint():
    #ARRANGE
    client = TestClient(app)
    test_user = {
        "user_name":"test_usr",
        "password":"testtesttest4"
    }
    #ACT
    response = client.post("/login",json=test_user)
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
    response = client.post("/login",json=test_user)
    #ASSERT
    assert response.status_code == 422
    assert response.json() == {'detail': 'Unprocessable Entity'}


def test_get_user_endpoint_returns_user_data():
    #ARRANGE
    client = TestClient(app)
    TEST_USER_ID = config("TEST_USER_ID")
    expected_user_data = {
        "firstName":"test",
        "lastName":"test",
        "userName":"test_usr",
        "email":"test@test.com",
    }
    #ACT
    response = client.get(f"/users/{TEST_USER_ID}")
    #ASSERT
    assert response.status_code == 200
    assert response.json() == expected_user_data


def test_get_user_endpoint_user_not_found():
    #ARRANGE
    client = TestClient(app)
    expected_error = {
        "detail": "User not found."
    }
    #ACT
    response = client.get("/users/not_existing_id")
    #ASSERT
    assert response.status_code == 404
    assert response.json() == expected_error


def test_validate_token_endpoint():
    #ARRANGE
    VALID_TOKEN = config("VALID_TOKEN")
    client = TestClient(app)
    expected_response = {"isValid":True}
    #ACT
    response = client.post("/validate",json={"token":VALID_TOKEN})
    #ASSERT
    assert response.status_code == 200
    assert response.json() == expected_response


def test_validate_token_endpoint_with_invalid_token():
    #ARRANGE
    client = TestClient(app)
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X2F1ZCIsImlzcyI6InRlc3RfaXNzIn0.idxtUZ-pPMUw6P_TeHA-RW1fhhSZPsglZkZKbWxjlXA"
    expected_response = {"isValid":False}
    #ACT
    response = client.post("/validate",json={"token":test_token})
    #ASSERT
    assert response.status_code == 200
    assert response.json() == expected_response


def test_register_user_endpoint():
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
    response = client.post("/users",json=test_user)
    #ASSERT
    assert response.status_code == 201
    assert "token" in response.json()
    assert response.json()["userName"] == "test_usr2"
    #CLEANUP
    new_user_id = jwt_encoder.decode_jwt(response.json()["token"],audience=jwt_aud,issuer=jwt_iss)["userId"]
    response = client.delete("/users",headers={"userId":new_user_id})

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
        "detail":"User name is already taken."
    }
    #ACT
    response = client.post("/users",json=test_user)
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
    response = client.post("/users",json=test_user)
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
    response = client.post("/users",json=test_user)
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
    response = client.post("/users",json=test_user)
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
    response = client.post("/users",json=test_user)
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
    response = client.post("/users",json=test_user)
    #ASSERT
    assert response.status_code == 422


def test_delete_user_endpoint():
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
    new_user = client.post("/users",json=test_user)
    new_user = new_user.json()
    new_user_id = jwt_encoder.decode_jwt(new_user["token"],audience=jwt_aud,issuer=jwt_iss)["userId"]
    del_user = {
        "userId":new_user_id
    }
    #ACT
    response = client.delete("/users",headers=del_user)
    #ASSERT
    assert response.status_code == 204
    assert client.get(f"/users/{new_user_id}").status_code == 404

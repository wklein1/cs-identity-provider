from fastapi.testclient import TestClient
from fastapi import status
from decouple import config
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
    test_user = {
        "first_name":"test",
        "last_name":"test",
        "user_name":"test_usr",
        "email":"test@test.com",
        "password":"testtesttest4"
    }
    #ACT
    response = client.post("/users",json=test_user)
    #ASSERT
    assert response.status_code == 201
    assert "userId" in response.json()


def test_register_user_endpoint():
    #ARRANGE
    client = TestClient(app)
    test_user = {
        "first_name":"test",
        "last_name":"test",
        "user_name":"test_usr",
        "email":"test@test.com",
        "password":"testtesttest4"
    }
    #ACT
    response = client.post("/users",json=test_user)
    #ASSERT
    assert response.status_code == 201
    assert "token" in response.json()
    assert response.json()["userName"] == "test_usr"


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
from fastapi.testclient import TestClient
from fastapi import status
from decouple import config
from modules.jwt.jwt_module import JwtEncoder
import uuid
from main import app

VALID_MICROSERVICE_ACCESS_TOKEN = config("VALID_MICROSERVICE_ACCESS_TOKEN")
MICROSERVICE_AUTH_HEADERS = {"microserviceAccessToken":VALID_MICROSERVICE_ACCESS_TOKEN}

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
    response = client.get(f"/users/{TEST_USER_ID}", headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 200
    assert response.json() == expected_user_data


def test_get_user_endpoint_user_not_found():
    #ARRANGE
    client = TestClient(app)
    expected_error = {
        "detail": "User not found"
    }
    #ACT
    response = client.get("/users/not_existing_id", headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 404
    assert response.json() == expected_error


def test_change_password_endpoint_success():
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
    test_user_password_update = {
        "password":"testtesttest4",
        "new_password":"testtesttest5"
    }
    new_user = client.post("/users",json=test_user, headers=MICROSERVICE_AUTH_HEADERS)
    new_user = new_user.json()
    new_user_id = jwt_encoder.decode_jwt(new_user["token"],audience=jwt_aud,issuer=jwt_iss)["userId"]
    #ACT
    response = client.patch(f"/users/{new_user_id}/password", json=test_user_password_update, headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 204
    #CLEANUP
    client.delete("/users", json={"password":"testtesttest5"}, headers={"userId":new_user_id}|MICROSERVICE_AUTH_HEADERS)


def test_change_password_endpoint_fails_forbidden_wrong_password():
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
    test_user_password_update = {
        "password":"invalid_password",
        "new_password":"testtesttest5"
    }
    expected_error = {
        "detail":"Invalid password"
    }
    new_user = client.post("/users",json=test_user, headers=MICROSERVICE_AUTH_HEADERS)
    new_user = new_user.json()
    new_user_id = jwt_encoder.decode_jwt(new_user["token"],audience=jwt_aud,issuer=jwt_iss)["userId"]
    #ACT
    response = client.patch(f"/users/{new_user_id}/password", json=test_user_password_update, headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 403
    assert response.json() == expected_error
    #CLEANUP
    client.delete("/users", json={"password":"testtesttest4"}, headers={"userId":new_user_id}|MICROSERVICE_AUTH_HEADERS)


def test_change_password_endpoint_fails_invalid_new_password():
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
    test_user_password_update = {
        "password":"testtesttest4",
        "new_password":"invalid_new_password"
    }
    new_user = client.post("/users",json=test_user, headers=MICROSERVICE_AUTH_HEADERS)
    new_user = new_user.json()
    new_user_id = jwt_encoder.decode_jwt(new_user["token"],audience=jwt_aud,issuer=jwt_iss)["userId"]
    #ACT
    response = client.patch(f"/users/{new_user_id}/password", json=test_user_password_update, headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 422
    #CLEANUP
    client.delete("/users", json={"password":"testtesttest4"}, headers={"userId":new_user_id}|MICROSERVICE_AUTH_HEADERS)


def test_change_password_endpoint_fails_user_not_found():
    #ARRANGE
    client = TestClient(app)

    test_user_password_update = {
        "password":"testtesttest4",
        "new_password":"testtesttest4"
    }
    expected_error = {
        "detail": "User not found"
    }
    #ACT
    response = client.patch("/users/invalid_user_id/password", json=test_user_password_update, headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 404
    assert response.json() == expected_error
   

def test_delete_user_endpoint_success():
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
    new_user = client.post("/users",json=test_user, headers=MICROSERVICE_AUTH_HEADERS)
    new_user = new_user.json()
    new_user_id = jwt_encoder.decode_jwt(new_user["token"],audience=jwt_aud,issuer=jwt_iss)["userId"]
    del_user = {
        "userId":new_user_id
    }
    #ACT
    response = client.delete("/users", json={"password":"testtesttest4"}, headers=del_user|MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 204
    assert client.get(f"/users/{new_user_id}", headers=MICROSERVICE_AUTH_HEADERS).status_code == 404


def test_delete_user_endpoint_invalid_password():
    #ARRANGE
    client = TestClient(app)
    TEST_USER_ID = config("TEST_USER_ID")
    del_user = {
        "userId":TEST_USER_ID
    }
    expected_error = {
        "detail":"Invalid password"
    }
    #ACT
    response = client.delete("/users", json={"password":"invalid"}, headers=del_user|MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 403
    assert response.json() == expected_error

from fastapi.testclient import TestClient
from fastapi import status
from decouple import config
from modules.jwt.jwt_module import JwtEncoder
from main import app

VALID_MICROSERVICE_ACCESS_TOKEN = config("VALID_MICROSERVICE_ACCESS_TOKEN")
MICROSERVICE_AUTH_HEADERS = {"microserviceAccessToken":VALID_MICROSERVICE_ACCESS_TOKEN}

def test_update_user_data_endpoint_success():
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
    updated_test_user = {
        "first_name":"updated",
        "last_name":"updated",
        "user_name":"test_usr2_updated",
        "email":"updated@test.com",
        "password":"testtesttest4"
    }
    expected_user_response = {
        "firstName":"updated",
        "lastName":"updated",
        "userName":"test_usr2_updated",
        "email":"updated@test.com",
    }
    new_user = client.post("/users",json=test_user, headers=MICROSERVICE_AUTH_HEADERS)
    new_user = new_user.json()
    new_user_id = jwt_encoder.decode_jwt(new_user["token"],audience=jwt_aud,issuer=jwt_iss)["userId"]
    #ACT
    response = client.patch(f"/users/{new_user_id}", json=updated_test_user, headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 204
    assert client.get(f"/users/{new_user_id}", headers=MICROSERVICE_AUTH_HEADERS).json() == expected_user_response
    #CLEANUP
    client.delete("/users", json={"password":"testtesttest4"}, headers={"userId":new_user_id}|MICROSERVICE_AUTH_HEADERS)


def test_update_user_data_endpoint_no_user_name_change_success():
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
    updated_test_user = {
        "first_name":"updated",
        "last_name":"updated",
        "user_name":"test_usr2",
        "email":"updated@test.com",
        "password":"testtesttest4"
    }
    expected_user_response = {
        "firstName":"updated",
        "lastName":"updated",
        "userName":"test_usr2",
        "email":"updated@test.com",
    }
    new_user = client.post("/users",json=test_user, headers=MICROSERVICE_AUTH_HEADERS)
    new_user = new_user.json()
    new_user_id = jwt_encoder.decode_jwt(new_user["token"],audience=jwt_aud,issuer=jwt_iss)["userId"]
    #ACT
    response = client.patch(f"/users/{new_user_id}", json=updated_test_user, headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 204
    assert client.get(f"/users/{new_user_id}", headers=MICROSERVICE_AUTH_HEADERS).json() == expected_user_response
    #CLEANUP
    client.delete("/users", json={"password":"testtesttest4"}, headers={"userId":new_user_id}|MICROSERVICE_AUTH_HEADERS)   


def test_update_user_data_endpoint_fails_invalid_password():
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
    updated_test_user = {
        "first_name":"updated",
        "last_name":"updated",
        "user_name":"test_usr2_updated",
        "email":"updated@test.com",
        "password":"invalid"
    }
    expected_error = {
        "detail":"Invalid password"
    }
    new_user = client.post("/users",json=test_user, headers=MICROSERVICE_AUTH_HEADERS)
    new_user = new_user.json()
    new_user_id = jwt_encoder.decode_jwt(new_user["token"],audience=jwt_aud,issuer=jwt_iss)["userId"]
    #ACT
    response = client.patch(f"/users/{new_user_id}", json=updated_test_user, headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 403
    assert response.json() == expected_error
    #CLEANUP
    client.delete("/users", json={"password":"testtesttest4"}, headers={"userId":new_user_id}|MICROSERVICE_AUTH_HEADERS)


def test_update_user_data_endpoint_fails_user_not_found():
    #ARRANGE
    client = TestClient(app)

    updated_test_user = {
        "first_name":"updated",
        "last_name":"updated",
        "user_name":"test_usr2_updated",
        "email":"updated@test.com",
        "password":"testtesttest4"
    }
    expected_error = {
        "detail":"User not found"
    }
    #ACT
    response = client.patch("/users/invalid_id", json=updated_test_user, headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 404
    assert response.json() == expected_error


def test_update_user_data_endpoint_fails_user_name_taken():
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
    updated_test_user = {
        "first_name":"updated",
        "last_name":"updated",
        "user_name":"test_usr",
        "email":"updated@test.com",
        "password":"testtesttest4"
    }
    expected_error = {
        "detail":"User name is already taken"
    }
    new_user = client.post("/users",json=test_user, headers=MICROSERVICE_AUTH_HEADERS)
    new_user = new_user.json()
    new_user_id = jwt_encoder.decode_jwt(new_user["token"],audience=jwt_aud,issuer=jwt_iss)["userId"]
    #ACT
    response = client.patch(f"/users/{new_user_id}", json=updated_test_user, headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 409
    assert response.json() == expected_error
    #CLEANUP
    client.delete("/users", json={"password":"testtesttest4"}, headers={"userId":new_user_id}|MICROSERVICE_AUTH_HEADERS)


def test_update_user_data_endpoint_fails_user_name_invalid():
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
    updated_test_user = {
        "first_name":"updated",
        "last_name":"updated",
        "user_name":"t",
        "email":"updated@test.com",
        "password":"testtesttest4"
    }

    new_user = client.post("/users",json=test_user, headers=MICROSERVICE_AUTH_HEADERS)
    new_user = new_user.json()
    new_user_id = jwt_encoder.decode_jwt(new_user["token"],audience=jwt_aud,issuer=jwt_iss)["userId"]
    #ACT
    response = client.patch(f"/users/{new_user_id}", json=updated_test_user, headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 422
    #CLEANUP
    client.delete("/users", json={"password":"testtesttest4"}, headers={"userId":new_user_id}|MICROSERVICE_AUTH_HEADERS)


def test_update_user_data_endpoint_fails_first_name_invalid():
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
    updated_test_user = {
        "first_name":"t",
        "last_name":"updated",
        "user_name":"test_usr2",
        "email":"updated@test.com",
        "password":"testtesttest4"
    }

    new_user = client.post("/users",json=test_user, headers=MICROSERVICE_AUTH_HEADERS)
    new_user = new_user.json()
    new_user_id = jwt_encoder.decode_jwt(new_user["token"],audience=jwt_aud,issuer=jwt_iss)["userId"]
    #ACT
    response = client.patch(f"/users/{new_user_id}", json=updated_test_user, headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 422
    #CLEANUP
    client.delete("/users", json={"password":"testtesttest4"}, headers={"userId":new_user_id}|MICROSERVICE_AUTH_HEADERS)


def test_update_user_data_endpoint_fails_last_name_invalid():
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
    updated_test_user = {
        "first_name":"updated",
        "last_name":"",
        "user_name":"test_usr2",
        "email":"updated@test.com",
        "password":"testtesttest4"
    }

    new_user = client.post("/users",json=test_user, headers=MICROSERVICE_AUTH_HEADERS)
    new_user = new_user.json()
    new_user_id = jwt_encoder.decode_jwt(new_user["token"],audience=jwt_aud,issuer=jwt_iss)["userId"]
    #ACT
    response = client.patch(f"/users/{new_user_id}", json=updated_test_user, headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 422
    #CLEANUP
    client.delete("/users", json={"password":"testtesttest4"}, headers={"userId":new_user_id}|MICROSERVICE_AUTH_HEADERS)


def test_update_user_data_endpoint_fails_email_invalid():
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
    updated_test_user = {
        "first_name":"updated",
        "last_name":"updated",
        "user_name":"test_usr2",
        "email":"updatedtestcom",
        "password":"testtesttest4"
    }

    new_user = client.post("/users",json=test_user, headers=MICROSERVICE_AUTH_HEADERS)
    new_user = new_user.json()
    new_user_id = jwt_encoder.decode_jwt(new_user["token"],audience=jwt_aud,issuer=jwt_iss)["userId"]
    #ACT
    response = client.patch(f"/users/{new_user_id}", json=updated_test_user, headers=MICROSERVICE_AUTH_HEADERS)
    #ASSERT
    assert response.status_code == 422
    #CLEANUP
    client.delete("/users", json={"password":"testtesttest4"}, headers={"userId":new_user_id}|MICROSERVICE_AUTH_HEADERS)

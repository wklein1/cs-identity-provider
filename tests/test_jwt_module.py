from modules.jwt.jwt_module import JwtEncoder
import pytest
import jwt

def test_generate_token():
    #ARRANGE
    jwt_encoder = JwtEncoder("test", "HS256")
    test_payload = {
        "aud":"test_aud",
        "iss":"test_iss"
    }
    expected_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X2F1ZCIsImlzcyI6InRlc3RfaXNzIn0.idxtUZ-pPMUw6P_TeHA-RW1fhhSZPsglZkZKbWxjlXA"
    #ACT
    token = jwt_encoder.generate_jwt(test_payload)
    #ASSERT
    assert token == expected_token


def test_decode_token():
    #ARRANGE
    jwt_encoder = JwtEncoder("test", "HS256")
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X2F1ZCIsImlzcyI6InRlc3RfaXNzIn0.idxtUZ-pPMUw6P_TeHA-RW1fhhSZPsglZkZKbWxjlXA"
    expected_decoded_token_payload = {
        "aud":"test_aud",
        "iss":"test_iss"
    }
    #ACT
    decoded_token = jwt_encoder.decode_jwt(test_token, audience="test_aud", issuer="test_iss")
    #ASSERT
    assert decoded_token == expected_decoded_token_payload


def test_decode_token_fails_for_expired_token():
    #ARRANGE
    jwt_encoder = JwtEncoder("test", "HS256")
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X2F1ZCIsImlzcyI6InRlc3RfaXNzIiwiZXhwIjoxNjY3MzE1MTI0LjgyNjQ5N30.UT3TzU_hMH1cEPO8ZLbIcAHVeu_V3_wLhEFffvTyxHc"
    #ACT & ASSERT
    with pytest.raises(jwt.exceptions.ExpiredSignatureError):
        jwt_encoder.decode_jwt(test_token, audience="test_aud", issuer="test_iss")


def test_decode_token_fails_for_missing_aud():
    #ARRANGE
    jwt_encoder = JwtEncoder("test", "HS256")
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0X2lzcyJ9.r0gyGKT735rbOtfwa0oewT8PsllCL0ke83QC2M0pu1g"
    #ACT & ASSERT
    with pytest.raises(jwt.exceptions.MissingRequiredClaimError):
        jwt_encoder.decode_jwt(test_token, audience="test_aud", issuer="test_iss")


def test_decode_token_fails_for_missing_iss():
    #ARRANGE
    jwt_encoder = JwtEncoder("test", "HS256")
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X2F1ZCJ9.qLiVruU1tcUrhv2cxteNXk1iP17yo3HZrfjz0MWpDRU"
    #ACT & ASSERT
    with pytest.raises(jwt.exceptions.MissingRequiredClaimError):
        jwt_encoder.decode_jwt(test_token, audience="test_aud", issuer="test_iss")


def test_decode_token_fails_for_wrong_aud():
    #ARRANGE
    jwt_encoder = JwtEncoder("test", "HS256")
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ3cm9uZyIsImlzcyI6InRlc3RfaXNzIn0.l1c8c4qCqw9M4een5oJhQUz78zKOXG0tXRPrveI1l1A"
    #ACT & ASSERT
    with pytest.raises(jwt.exceptions.InvalidAudienceError):
        jwt_encoder.decode_jwt(test_token, audience="test_aud", issuer="test_iss")


def test_decode_token_fails_for_wrong_iss():
    #ARRANGE
    jwt_encoder = JwtEncoder("test", "HS256")
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X2F1ZCIsImlzcyI6Indyb25nIn0.qa5uhe1LpEBEnNlwPhe9TI92SpZLgDhzOd6V0JuMjVI"
    #ACT & ASSERT
    with pytest.raises(jwt.exceptions.InvalidIssuerError):
        jwt_encoder.decode_jwt(test_token, audience="test_aud", issuer="test_iss")


def test_decode_token_fails_for_wrong_secret():
    #ARRANGE
    jwt_encoder = JwtEncoder("test", "HS256")
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X2F1ZCJ9.mIW7Hu_WEY7XuyxQbz-TY8B_ZVa9E6rZThsAfRmXukM"
    #ACT & ASSERT
    with pytest.raises(jwt.exceptions.InvalidSignatureError):
        jwt_encoder.decode_jwt(test_token, audience="test_aud", issuer="test_iss")


def test_validate_token():
    #ARRANGE
    jwt_encoder = JwtEncoder("test", "HS256")
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X2F1ZCIsImlzcyI6InRlc3RfaXNzIn0.idxtUZ-pPMUw6P_TeHA-RW1fhhSZPsglZkZKbWxjlXA"
    #ACT
    token_is_valid = jwt_encoder.validate_jwt(test_token, audience="test_aud", issuer="test_iss")
    #ASSERT
    assert token_is_valid

def test_validate_token_false_for_expired_token():
    #ARRANGE
    jwt_encoder = JwtEncoder("test", "HS256")
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X2F1ZCIsImlzcyI6InRlc3RfaXNzIiwiZXhwIjoxNjY3MzE1MTI0LjgyNjQ5N30.UT3TzU_hMH1cEPO8ZLbIcAHVeu_V3_wLhEFffvTyxHc"
    #ACT
    token_is_valid = jwt_encoder.validate_jwt(test_token, audience="test_aud", issuer="test_iss")
    #ASSERT
    assert not token_is_valid

def test_validate_token_false_for_missing_aud():
    #ARRANGE
    jwt_encoder = JwtEncoder("test", "HS256")
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0X2lzcyJ9.r0gyGKT735rbOtfwa0oewT8PsllCL0ke83QC2M0pu1g"
    #ACT
    token_is_valid = jwt_encoder.validate_jwt(test_token, audience="test_aud", issuer="test_iss")
    #ASSERT
    assert  not token_is_valid

def test_validate_token_false_for_missing_iss():
    #ARRANGE
    jwt_encoder = JwtEncoder("test", "HS256")
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X2F1ZCJ9.qLiVruU1tcUrhv2cxteNXk1iP17yo3HZrfjz0MWpDRU"
    #ACT
    token_is_valid = jwt_encoder.validate_jwt(test_token, audience="test_aud", issuer="test_iss")
    #ASSERT
    assert not token_is_valid

def test_validate_token_false_for_wrong_secret():
    #ARRANGE
    jwt_encoder = JwtEncoder("test", "HS256")
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X2F1ZCJ9.mIW7Hu_WEY7XuyxQbz-TY8B_ZVa9E6rZThsAfRmXukM"
    #ACT
    token_is_valid = jwt_encoder.validate_jwt(test_token, audience="test_aud", issuer="test_iss")
    #ASSERT
    assert not token_is_valid

def test_validate_token_false_for_wrong_aud():
    #ARRANGE
    jwt_encoder = JwtEncoder("test", "HS256")
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ3cm9uZyIsImlzcyI6InRlc3RfaXNzIn0.l1c8c4qCqw9M4een5oJhQUz78zKOXG0tXRPrveI1l1A"
    #ACT
    token_is_valid = jwt_encoder.validate_jwt(test_token, audience="test_aud", issuer="test_iss")
    #ASSERT
    assert not token_is_valid

def test_validate_token_false_for_wrong_iss():
    #ARRANGE
    jwt_encoder = JwtEncoder("test", "HS256")
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X2F1ZCIsImlzcyI6Indyb25nIn0.qa5uhe1LpEBEnNlwPhe9TI92SpZLgDhzOd6V0JuMjVI"
    #ACT
    token_is_valid = jwt_encoder.validate_jwt(test_token, audience="test_aud", issuer="test_iss")
    #ASSERT
    assert not token_is_valid
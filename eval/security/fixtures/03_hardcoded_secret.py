"""Fixture 03: s3_client(), sign_jwt(). Reviewer should flag CWE-798."""
import boto3

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
JWT_SIGNING_KEY = "super-secret-jwt-key-do-not-change-12345"

def s3_client():
    return boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
    )

def sign_jwt(payload: dict) -> str:
    import jwt
    return jwt.encode(payload, JWT_SIGNING_KEY, algorithm="HS256")

import os
import re
from fastapi import HTTPException, Request
from fastapi.security import HTTPBearer
from jose import jwt

from repositories.user import UserRepository
from starlette.responses import JSONResponse

bearer_scheme = HTTPBearer()
SECRET_KEY = os.getenv('SECRET_KEY', 'nhabehospital')
ALGORITHM = os.getenv('ALGORITHM', 'HS256')
user_repository = UserRepository()
excluded_endpoints = ["/", "/docs", "/openapi.json", "/token", "/report/create/", "/report/create/fake/", "/refresh-token"]


async def check_bearer_token(request: Request, call_next):
    print(re.search(pattern=r"/report/update/", string=request.url.path))
    if request.url.path in excluded_endpoints or re.search(pattern=r"/report/update/", string=request.url.path) is not None:
        # Skip token validation for excluded endpoints
        response = await call_next(request)
        return response

    # Get the Authorization header from the request
    auth_header = request.headers.get("Authorization")

    # Check if the Authorization header exists and starts with "Bearer "
    if auth_header and auth_header.startswith("Bearer "):
        # Extract the token from the header
        token = auth_header.split(" ")[1]
        print(f"Token: {token}")
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = decoded_token.get("sub")

        # Check if the token is valid
        if not username:
            return JSONResponse(status_code=401, content={"status": 401, "exc": "Invalid bearer token with missing user"})

        # Token is valid, proceed with the request
        response = await call_next(request)
        return response

    # Authorization header is missing or invalid
    return JSONResponse(status_code=401, content={"status": 401, "exc": "Invalid bearer token with missing Authorization header"})


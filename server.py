import strawberry
from typing import List,Dict,Any
from strawberry.experimental import pydantic
from pydantic import BaseModel, Field, ValidationError
import logging

#=============== Logger
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

import sqlite3
import uuid
import contextvars
import uvicorn
import pyotp 
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from strawberry.asgi import GraphQL
from typing import List,Dict,Any,Optional

#================ Import helpers
from helper import (
    get_domain, is_client_ip_restricted, 
    create_tokens, get_organization_by_domain, verify_user_credentials, 
    get_user_mfa_secret
)

#================ Correlation middleware setup
class CorrelationIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        return response


#=============== Validations
from pydantic import EmailStr

# pydantic validation
class LoginModel(BaseModel):  
    identifier: EmailStr
    secret: str = Field(min_length=3)
    mfa_code: Optional[str] = None
    metadata: Dict[str, Any]

@strawberry.type
class LoginValidationError(LoginResponse):
    message: str = "Invalid input"
    errors: strawberry.scalars.JSON


#=============== Interfaces
@strawberry.interface
class LoginResponse:
    message: str


#=============== Entities
@strawberry.experimental.pydantic.input(model=LoginModel)
class LoginInput:
    identifier: strawberry.auto
    secret: strawberry.auto
    mfa_code: strawberry.auto
    metadata: strawberry.scalars.JSON

@strawberry.type
class LoginSuccess(LoginResponse):
    token: str
    refresh_token: str
    message: str = "Login successful"

@strawberry.type
class LoginChallenge(LoginResponse):
    challenge_type: str  # e.g., "MFA_REQUIRED"
    session_id: str
    message: str

@strawberry.type
class LoginFailure(LoginResponse):
    # user or organizational exsistance shouldn't be disclosed
    message: str


# Union for polymorphic return
LoginResult = strawberry.union("LoginResult", (LoginSuccess, LoginChallenge, LoginFailure, LoginValidationError))


#============== GraphQL Specific

@strawberry.type
class Query:
    @strawberry.field
    def get_info(self)->str:
        return "I am working"

@strawberry.type
class Mutation:
    @strawberry.field
    def login(self,data:LoginInput)->LoginResult:
        try:
            # validation
            data=data.to_pydantic()
            domain = get_domain(data.identifier)
        
            # organization check
            organization = get_organization_by_domain(domain)
            if organization:                
                org_login_policy_str = organization.get("login_policy", "") or ""
                policy_list = [p.strip() for p in org_login_policy_str.split(',')]
                
                if 'IP_RESTRICTED' in policy_list:
                    restricted_ips_str = organization.get("restricted_ips")
                    if restricted_ips_str:
                        client_ip = data.metadata.get("ip")
                        if not client_ip:
                            return LoginFailure(message="IP address required")
                        if is_client_ip_restricted(client_ip, restricted_ips_str):
                            return LoginFailure(message="Access denied for this IP")
                
                # org login policies check
                if 'MFA' in policy_list:
                    # verify credentials first
                    if not verify_user_credentials(str(data.identifier), str(data.secret)):
                        return LoginFailure(message="Invalid credentials")
                    
                    # 2. get user mfa secret
                    mfa_secret = get_user_mfa_secret(str(data.identifier))
                    if not mfa_secret:
                        return LoginFailure(message="MFA not set up for this user")

                    # 3. check if mfa code provided
                    if not data.mfa_code:
                        return LoginChallenge(message="Additional verification required", challenge_type="MFA_REQUIRED", session_id="TEMP_SESSION_ID") 
                    
                    # 4. verify code using stored secret 
                    totp = pyotp.TOTP(mfa_secret)
                    if not totp.verify(data.mfa_code):
                        return LoginFailure(message="Invalid MFA code")
            
            #normal login
            if verify_user_credentials(str(data.identifier), str(data.secret)):
                tokens = create_tokens(str(data.identifier))
                return LoginSuccess(token=tokens["access_token"], refresh_token=tokens["refresh_token"])
            
            return LoginFailure(message="Invalid credentials")

        except ValidationError as e:
            logger.error(f"Validation failed: {e.json()}")
            return LoginValidationError(errors=e.errors())
        
        except Exception as e:
            logger.error(f"global exception: {e}")
            return LoginFailure(message="Internal Server Error")


schema=strawberry.Schema(query=Query,mutation=Mutation)

graphql_app = GraphQL(schema)
routes = [
    Route("/graphql", graphql_app),
]
middleware = [
    Middleware(CORSMiddleware, allow_origins=['*'], allow_methods=['*'], allow_headers=['*'], expose_headers=['X-Correlation-ID']),
    Middleware(CorrelationIdMiddleware)
]
app = Starlette(routes=routes, middleware=middleware)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

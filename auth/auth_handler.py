# This file is responsible for signing , encoding , decoding and returning JWTS
import time
import jwt
from fastapi_jwt_auth import AuthJWT

from sql_app.schemas import Settings



def decodeJWT(token: str, settings: Settings) -> dict:
    authjwt = AuthJWT(secret_key=settings.authjwt_secret_key)
    try:
        authjwt.decode_jwt(token)
        return authjwt.get_raw_jwt()
    except:
        return {}
    

def decodeJWT(token: str,settings: Settings) -> dict:
    try:
        decoded_token = jwt.decode(token,settings )
        return decoded_token if decoded_token["expires"] >= time.time() else None
    except:
        return {}
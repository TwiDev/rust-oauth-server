use rocket::*;
use rocket::http::Status;
use rocket::outcome::Outcome;
use rocket::request::FromRequest;
use rocket::serde::json::Json;

use crate::responses::DefaultGenericResponse;

pub struct AuthorizationToken(String);

#[derive(Debug)]
pub enum AuthorizationError {
    Missing,
    Invalid,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthorizationToken {
    type Error = AuthorizationError;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let token = request.headers().get_one("authorization");
        match token {
            Some(token) => {
                // check validity
                Outcome::Success(AuthorizationToken(token.to_string()))
            }
            None => Outcome::Failure((Status::Unauthorized, AuthorizationError::Missing)),
        }
    }
}

#[get("/oauth/signup")]
pub async fn signup_application() -> Result<Json<DefaultGenericResponse>,Status> {
    return Ok(Json(DefaultGenericResponse{message:"".to_string(),code:0}));
}

#[get("/oauth/token")]
pub async fn token_application() -> Result<Json<DefaultGenericResponse>,Status> {
    if true {
        Err(Status::Unauthorized)
    }else {
        Ok(Json(DefaultGenericResponse {
            code: 0,
            message: "".to_string()
        }))
    }
}

#[get("/oauth/secret")]
pub async fn secret_application(authorization: AuthorizationToken) -> Result<Json<DefaultGenericResponse>,Status> {
    return Ok(Json(DefaultGenericResponse{
        message:authorization.0,
        code:1
    }))
}

#[catch(401)]
pub fn unauthorized() -> Json<DefaultGenericResponse>{
    Json(DefaultGenericResponse{
        message: "401: Unauthorized".to_string(),
        code: 0
    })
}
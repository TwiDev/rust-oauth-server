use rocket::*;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::{Header, Status};
use rocket::outcome::Outcome;
use rocket::request::FromRequest;
use rocket::serde::json::Json;

use crate::responses::DefaultGenericResponse;

pub struct AuthorizationToken {
    pub _type: AuthorizationType,
    pub token: String
}

#[derive(Debug)]
pub enum AuthorizationError {
    Missing,
    Invalid,
}

#[derive(Debug)]
pub enum AuthorizationType {
    Bearer,
    Bot
}

#[async_trait]
impl<'r> FromRequest<'r> for AuthorizationToken {
    type Error = AuthorizationError;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let token = request.headers().get_one("authorization");
        match token {
            Some(token) => {
                // TODO: check validity
                let _type:AuthorizationType = AuthorizationType::Bearer;

                Outcome::Success(AuthorizationToken{_type, token: token.to_string()})
            }
            None => Outcome::Failure((Status::Unauthorized, AuthorizationError::Missing)),
        }
    }
}

pub struct CORS;

#[async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new("Access-Control-Allow-Methods", "POST, GET, PATCH, OPTIONS, DELETE"));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
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
        message:"Authorized!".to_string(),
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
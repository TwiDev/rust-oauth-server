use std::future::Future;
use std::str::FromStr;
use std::string::ToString;

use rocket::*;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::form::validate::Contains;
use rocket::http::{Header, Status};
use rocket::outcome::Outcome;
use rocket::request::FromRequest;
use rocket::serde::json::Json;
use serde::de::Unexpected::Str;
use crate::database;

use crate::responses::DefaultGenericResponse;

pub struct AuthorizationToken {
    pub _type: AuthorizationType,
    pub token: String
}

pub struct TokenProps {
    pub token:AuthorizationToken,
    pub authorization: Authorization,
    pub associated_id: i64
}

#[derive(Debug)]
pub enum AuthorizationError {
    Missing,
    Invalid,
}

#[derive(Debug, PartialEq)]
pub enum AuthorizationType {
    User,
    Bearer,
    Bot,
    Unknown
}

pub enum Authorization {
    User,
    Guild,
    Other
}

impl ToString for AuthorizationType {
    fn to_string(&self) -> String {
        match self {
            AuthorizationType::User => String::from(""),
            AuthorizationType::Bearer => String::from("Bearer"),
            AuthorizationType::Bot => String::from("Bot"),
            AuthorizationType::Unknown => String::from("Unknown")
        }
    }
}

impl AuthorizationType {

    fn from_token(token: String) -> AuthorizationType {
        if token.starts_with(AuthorizationType::Bearer.to_string()) {
            AuthorizationType::Bearer
        }

        if token.starts_with(AuthorizationType::Bot.to_string()) {
            AuthorizationType::Bot
        }

        AuthorizationType::User
    }

}

impl ToString for Authorization {
    fn to_string(&self) -> String {
        match self {
            Authorization::User => String::from("USER"),
            Authorization::Guild => String::from("GUILD"),
            Authorization::Other => String::from("OTHER")
        }
    }
}

impl FromStr for Authorization {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "USER" => Ok(Authorization::User),
            "GUILD" => Ok(Authorization::Guild),
            "OTHER" => Ok(Authorization::Other),
            _ => Err(())
        }
    }
}

#[async_trait]
impl<'r> FromRequest<'r> for TokenProps {
    type Error = AuthorizationError;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let token = request.headers().get_one("authorization");
        match token {
            Some(token) => {
                // Check token validity
                let raw_token = token.to_string();
                let _type:AuthorizationType = AuthorizationType::from_token(raw_token);

                let props: Option<TokenProps> = database::verify_token(AuthorizationToken{
                    _type,
                    token: token.to_string(),
                });

                if props.is_some() {
                    Outcome::Success(props.unwrap())
                }else{
                    Outcome::Failure((Status::Unauthorized, AuthorizationError::Invalid))
                }
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
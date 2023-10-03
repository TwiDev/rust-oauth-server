use std::str::FromStr;
use std::string::ToString;
use rocket::{async_trait, catch, get, post, Request, request, Response};

use rocket::fairing::{Fairing, Info, Kind};
use rocket::form::validate::Contains;
use rocket::http::{Header, Status};
use rocket::outcome::Outcome;
use rocket::request::FromRequest;
use rocket::serde::json::Json;
use serde::{Serialize, Deserialize};

use crate::app::{AccessTokenResponse, ClientApp, ClientAuthorizationRequest, ClientProperties, ClientTokenRequest};

use crate::database;
use crate::database::delete_authorization_code;
use crate::responses::{AppHandlerResponse, ClientAppResponse, DefaultGenericResponse, PrivateUserDataResponse, UserDataResponse};
use crate::status::ServerStatus;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct AuthorizationToken {
    pub _type: AuthorizationType,
    pub token: String
}


#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct TokenProps {
    pub token:AuthorizationToken,
    pub authorization: Authorization,
    pub associated_id: i64,
    pub scopes: i64
}

#[derive(Debug)]
pub enum AuthorizationError {
    Missing,
    Invalid,
}

#[derive(Copy, Clone, Debug, PartialEq,Eq, Serialize, Deserialize)]
pub enum AuthorizationType {
    User,
    Bearer,
    Bot,
    Unknown
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum Authorization {
    User,
    Guild,
    Other
}

impl AuthorizationType {
    pub(crate) fn as_str(&self) -> &str {
        match self {
            AuthorizationType::User => "",
            AuthorizationType::Bearer => "Bearer",
            AuthorizationType::Bot => "Bot",
            AuthorizationType::Unknown => "Unknown"
        }
    }
}

impl AuthorizationType {

    fn from_token(token: String) -> AuthorizationType {
        if token.contains(AuthorizationType::Bearer.as_str()) {
            return AuthorizationType::Bearer
        }

        if token.contains(AuthorizationType::Bot.as_str()) {
            return AuthorizationType::Bot
        }

        return AuthorizationType::User
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

                let props:Option<TokenProps> = database::verify_token(AuthorizationToken{
                    _type,
                    token: token.to_string(),
                }).await;

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

#[post("/oauth/token", format = "json", data = "<body>")]
pub async fn token_application(body: Json<ClientTokenRequest>) -> Result<Json<AccessTokenResponse>,Status> {
    let code: String = body.code.clone();

    if let Some(code) = database::verify_authorization(code).await {
        if let Some(app) = database::verify_client(body.client_id, body.client_secret.clone()).await {
            //TODO: Verify Bearer Token not app bot token
            let token_result: Result<TokenProps, ServerStatus> = database::verify_client_authorization(app, code.id, code.scopes).await;
            return match token_result {
                Ok(token) => {
                    delete_authorization_code(body.code.clone()).await;

                    Ok(Json(AccessTokenResponse::new_from_authorization(token, 86400)))
                },
                Err(status) => Err(Status::NotFound)
            }
        }
    }

    Err(Status::Unauthorized)
}

#[get("/oauth/app")]
pub async fn app_handler(auth: TokenProps) -> Result<Json<AppHandlerResponse>, Status> {
    if auth.token._type != AuthorizationType::User {
        return Err(Status::Unauthorized)
    }

    let mut apps: Vec<ClientProperties> = database::get_authorized_apps(auth.associated_id).await;

    return Ok(Json(AppHandlerResponse{
        apps
    }));
}

#[post("/oauth/authorize", format="json", data="<body>")]
pub async fn authorization_handler(auth: TokenProps, body: Json<ClientAuthorizationRequest>) -> Result<Json<DefaultGenericResponse>, Status> {
    if auth.token._type != AuthorizationType::User {
        return Err(Status::Unauthorized);
    }

    if let Some(app) = database::get_client(body.client_id).await {
        let user_id: i64 = auth.associated_id;

        return match database::authorize_client(user_id, app, body.scopes).await {
            Ok(code) => {
                Ok(Json(DefaultGenericResponse {
                    code: 0,
                    message: code
                }))
            },
            Err(..) => {
                Err(Status::BadRequest)
            }
        };

    }else{
        Err(Status::NotFound)
    }

}

#[get("/oauth/secret")]
pub async fn secret_application(authorization: TokenProps) -> Result<Json<DefaultGenericResponse>,Status> {
    return Ok(Json(DefaultGenericResponse{
        message:"Authorized!".to_string(),
        code:1
    }))
}

#[get("/api/users/<id>")]
pub async fn users_handler(authorization: TokenProps, id: i64) -> Result<Json<UserDataResponse>,Status> {
    let data:Result<UserDataResponse, Status> = database::get_user_by_id(authorization,id,false).await;

    return if data.is_ok() {
        Ok(Json(data.unwrap()))
    }else{
        Err(data.unwrap_err())
    }
}

#[get("/api/private/<id>")]
pub async fn private_users_handler(authorization: TokenProps, id: i64) -> Result<Json<PrivateUserDataResponse>,Status> {
    let data:Result<PrivateUserDataResponse, Status> = database::get_private_user_by_id(authorization,id).await;

    return if data.is_ok() {
        Ok(Json(data.unwrap()))
    }else{
        Err(data.unwrap_err())
    }
}

#[post("/api/client", data="<body>")]
pub async fn client_factory(mut body: String) -> Result<Json<ClientAppResponse>, Status> {
    println!("{}",body);

    unsafe {
        let app: ClientApp = database::create_client_app(ClientApp::new_empty(ClientProperties {
            name: body,
            scopes: 10
        })).await.unwrap();

        Ok(Json(ClientAppResponse {
            id: app.id,
            name: app.properties.name.clone(),
            token: app.token.clone(),
            secret: app.secret.clone(),
            scopes: app.properties.scopes
        }))
    }
}

#[catch(400)]
pub fn badrequest() -> Json<DefaultGenericResponse>{
    Json(DefaultGenericResponse{
        message: "400: Bad Request".to_string(),
        code: 0
    })
}

#[catch(401)]
pub fn unauthorized() -> Json<DefaultGenericResponse>{
    Json(DefaultGenericResponse{
        message: "401: Unauthorized".to_string(),
        code: 0
    })
}

#[catch(404)]
pub fn notfound() -> Json<DefaultGenericResponse>{
    Json(DefaultGenericResponse{
        message: "404: Not Found".to_string(),
        code: 0
    })
}
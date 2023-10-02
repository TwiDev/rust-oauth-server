use nanoid::nanoid;
use rocket::serde::Serialize;
use serde::Deserialize;
use crate::server::{Authorization, AuthorizationToken, AuthorizationType, TokenProps};

#[derive(Clone)]
pub struct ClientProperties {

    pub name: String,
    pub scopes: i64

}

#[derive(Clone)]
pub struct ClientApp {

    pub id: u64,
    pub secret: String,
    pub token: String,
    pub properties: ClientProperties

}

#[derive(Serialize, Deserialize)]
pub struct ClientTokenRequest {

    pub client_id: u64,
    pub client_secret: String,
    pub grant_type: String,
    pub code: String
}

#[derive(Serialize, Deserialize)]
pub struct AccessTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u32,
    pub refresh_token: String,
    pub scope: String
}

#[derive(Serialize, Deserialize)]
pub struct ClientAuthorizationRequest {

    pub client_id: u64,
    pub scopes: i64

}

impl AccessTokenResponse {

    pub fn new_from_authorization(auth: TokenProps, duration: u32) -> AccessTokenResponse {
        return AccessTokenResponse{
            access_token: auth.token.token,
            token_type: auth.token._type.as_str().to_string(),
            expires_in: duration,
            refresh_token: "null".to_string(),
            scope: auth.scopes.to_string(),
        }
    }

}

impl ClientApp {

    pub fn new_empty(properties: ClientProperties) -> ClientApp {
        let pop: &ClientProperties = &properties;
        let secret: String = generate_app_secret(pop);
        let token: String = generate_token(AuthorizationType::Bot);

        return ClientApp{
            id: 0,
            secret,
            token,
            properties,
        }
    }

    pub fn new(properties: ClientProperties, id: u64) -> ClientApp {
        let pop: &ClientProperties = &properties;
        let secret: String = generate_app_secret(pop);
        let token: String = generate_token(AuthorizationType::Bot);

        return ClientApp{
            id,
            secret,
            token,
            properties,
        }
    }

    pub fn populate(app: ClientApp, id: u64) -> ClientApp {
        return ClientApp{id, secret: app.secret.clone(), token: app.token.clone(), properties: ClientProperties{
            scopes: app.properties.scopes,
            name: app.properties.name.clone()
        }}
    }
}

pub fn generate_token(_type: AuthorizationType) -> String {
    return _type.as_str().to_string().to_owned() + &nanoid!().to_string()
}

pub fn generate_app_secret(properties: &ClientProperties) -> String {
    return nanoid!()
}
use serde::{Serialize};

#[derive(Serialize)]
pub struct DefaultGenericResponse {
    pub message: String,
    pub code: u32
}

#[derive(Serialize, Debug)]
pub struct UserDataResponse {
    pub id: i64,
    pub global_name: String,
    pub power: i64,
    pub flags: i64
}

#[derive(Serialize, Debug)]
pub struct PrivateUserDataResponse {
    pub id: i64,
    pub email: String,
    pub global_name: String,
    pub power: i64,
    pub flags: i64
}

#[derive(Serialize)]
pub struct ClientAppResponse {
    pub id: u64,
    pub name: String,
    pub secret: String,
    pub token: String,
    pub scopes: i64
}
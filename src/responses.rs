use serde::{Serialize};

#[derive(Serialize)]
pub struct DefaultGenericResponse {
    pub message: String,
    pub code: u32
}

#[derive(Serialize, Debug)]
pub struct UserDataResponse {
    pub id: i64,
    pub email: String,
    pub global_name: String,
    pub power: i64,
    pub flags: i64
}
use serde::{Serialize};

#[derive(Serialize)]
pub struct DefaultGenericResponse {
    pub status: String,
    pub message: String
}
use serde::{Serialize};

#[derive(Serialize)]
pub struct DefaultGenericResponse {
    pub message: String,
    pub code: u32
}
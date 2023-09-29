use std::fmt;

#[derive(Debug, Clone, Copy)]
pub struct ServerStatus {
    pub code: u16,
}

impl Default for ServerStatus {
    fn default() -> Self {
        ServerStatus::Ok
    }
}

macro_rules! dst {
    ($($code:expr, $code_str:expr, $name:ident => $reason:expr),+) => {
        $(
            pub const $name: ServerStatus = ServerStatus {code: $code};
        )+

        pub const fn reason(&self) -> Option<&'static str> {
            match self.code {
                $($code => Some($reason),)+
                _ => None
            }
        }

        pub const fn reason_lossy(&self) -> &'static str {
             if let Some(lossless) = self.reason() {
                return lossless;
             }

            return "Unknown Error"
        }
    };
}

impl ServerStatus {
    dst! {
        100, "100", Continue => "Continue",
        200, "200", Ok => "Ok",
        300, "300", NoConnection => "Connection not established",
        400, "400", BadRequest => "Bad Request",
        401, "401", Unauthorized => "Unauthorized",
        404, "404", NotFound => "Not Found",
        405, "405", TokenNotExist => "Token does not exist",
        406, "406", AlreadyExist => "Already exist"
    }
}

impl fmt::Display for ServerStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.code >= 300 {
            write!(f, "A Server Error occurred! Code: {} Reason: {}", self.code, self.reason_lossy())
        }else{
            write!(f, "{} {}", self.code, self.reason_lossy())
        }
    }
}

impl PartialEq for ServerStatus {
    fn eq(&self, other: &Self) -> bool {
        self.code.eq(&other.code)
    }
}


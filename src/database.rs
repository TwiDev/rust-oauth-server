use std::cell::OnceCell;
use std::ptr::null;
use std::str::FromStr;

use mysql;
use mysql::{Error, params, Pool, PooledConn};
use mysql::prelude::Queryable;
use rocket::http::Status;
use rocket::serde::{Deserialize, Serialize};
use crate::app::{ClientApp, ClientProperties};
use crate::responses::{PrivateUserDataResponse, UserDataResponse};
use crate::server::{Authorization, AuthorizationToken, AuthorizationType, TokenProps};

const URL: &str = "mysql://root:root@localhost:3306/oauth";
static mut DB_POOL: OnceCell<Pool> = OnceCell::new();
static DATABASE_CLIENT: DatabaseClient = DatabaseClient {};

#[derive(Clone, Copy)]
pub struct DatabaseClient;

impl DatabaseClient {
    pub async unsafe fn database_pool(self) -> &'static Pool {
        DB_POOL.get().unwrap()
    }

    pub async unsafe fn database_conn(self) -> PooledConn {
        let pool: &Pool  = self.database_pool().await;
        pool.get_conn().unwrap()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct UserData {
    pub id: i32,
    pub name: String,
    pub power: i32,
}

pub async fn verify_token(auth: AuthorizationToken) -> Option<TokenProps> {
    unsafe {
        let mut _conn: PooledConn = DATABASE_CLIENT.database_conn().await;

        match auth._type {
            AuthorizationType::User => {
                let _query: String = format!("SELECT id FROM users WHERE token = '{}'", auth.token);

                _conn.query_map(_query, |(id):(i64)| {
                    TokenProps {
                        token: AuthorizationToken{
                            _type: auth._type,
                            token: auth.token.clone()
                        },
                        authorization:Authorization::User,
                        associated_id: id,
                        scopes:10
                    }
                }).unwrap().pop()
            }
            AuthorizationType::Bearer => {
                let _query: String = format!("SELECT id,scopes,authorization_tye FROM tokens WHERE accessToken = '{}'", auth.token);

                println!("{}", _query);
                _conn.query_map::<(i64, i64, String), _, _, TokenProps>(_query, |(id, scopes, authorization_tye)| {
                    TokenProps {
                        token: AuthorizationToken{
                            _type: auth._type,
                            token: auth.token.clone()
                        },
                        authorization: Authorization::User,
                        associated_id: id,
                        scopes,
                    }
                }).unwrap().pop()
            }
            AuthorizationType::Bot => {
                let _query: String = format!("SELECT id,scopes FROM clients WHERE token = '{}'", auth.token);

                _conn.query_map(_query, |(id, scopes)| {
                    TokenProps {
                        token: AuthorizationToken{
                            _type: auth._type,
                            token: auth.token.clone()
                        },
                        authorization: Authorization::User,
                        associated_id: id,
                        scopes
                    }
                }).unwrap().pop()
            }
            _ => {
                None
            }
        }
    }
}


pub async fn get_user_by_id(auth: TokenProps, id: i64, private: bool) -> Result<UserDataResponse, Status> {
    if auth.scopes < 2 {
        return Err(Status::Unauthorized);
    }

    if private && auth.associated_id != id {
        return Err(Status::Unauthorized);
    }

    unsafe {
        let mut _conn: PooledConn = DATABASE_CLIENT.database_conn().await;
        let _query: String = format!("SELECT id,email,name,power FROM users WHERE id = {}", id);

        let data: Option<UserDataResponse> = _conn.query_map(_query, |(id, email, name, power)| {
            UserDataResponse {
                id,
                global_name: name,
                power,
                flags: 0
            }
        }).unwrap().pop();

        return if data.is_some() {
            Ok(data.unwrap())
        } else {
            Err(Status::NotFound)
        }
    }
}

pub async fn get_private_user_by_id(auth: TokenProps, id: i64) -> Result<PrivateUserDataResponse, Status> {
    if auth.scopes < 5 {
        return Err(Status::Unauthorized);
    }

    if auth.associated_id != id {
        return Err(Status::Unauthorized);
    }

    unsafe {
        let mut _conn: PooledConn = DATABASE_CLIENT.database_conn().await;
        let _query: String = format!("SELECT id,email,name,power FROM users WHERE id = {}", id);

        let data: Option<PrivateUserDataResponse> = _conn.query_map(_query, |(id, email, name, power)| {
            PrivateUserDataResponse {
                id,
                email,
                global_name: name,
                power,
                flags: 0
            }
        }).unwrap().pop();

        return if data.is_some() {
            Ok(data.unwrap())
        } else {
            Err(Status::NotFound)
        }
    }
}

pub async unsafe fn create_client_app(properties: ClientApp) -> Result<ClientApp, Error> {
        let mut _conn: PooledConn = DATABASE_CLIENT.database_conn().await;
        let _query: String = format!("INSERT INTO clients (secret,name,token,scopes) VALUES (:secret,:name,:token,:scopes)");

        let p: &ClientApp = &properties;

        _conn.exec_drop(_query,
                        params! {
            "secret" => p.secret.clone(),
            "name" => p.properties.name.clone(),
            "token" => p.token.clone(),
            "scopes" => p.properties.scopes
            },
        ).and_then(|_| Ok((ClientApp::populate(properties, _conn.last_insert_id()))))
}

pub unsafe fn initialize() {
    DB_POOL.set(Pool::new(URL).unwrap()).unwrap();
}
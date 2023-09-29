use std::cell::OnceCell;
use std::ptr::null;
use std::str::FromStr;
use rand::Rng;
use nanoid::nanoid;
use mysql;
use mysql::{Error, params, Params, Pool, PooledConn};
use mysql::prelude::Queryable;
use rocket::futures::stream::SplitStream;
use rocket::http::Status;
use rocket::serde::{Deserialize, Serialize};
use crate::app::{ClientApp, ClientProperties};
use crate::responses::{PrivateUserDataResponse, UserDataResponse};
use crate::server::{Authorization, AuthorizationToken, AuthorizationType, TokenProps};
use crate::status::ServerStatus;

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

pub async fn verify_token_by_index(client_id: u64, user_id: i64) -> Option<TokenProps> {
    unsafe {
        let mut _conn: PooledConn = DATABASE_CLIENT.database_conn().await;
        let _query: String = format!("SELECT accessToken,id,scopes,authorization_tye FROM tokens WHERE client_id = {} AND id = {} LIMIT 1", client_id, user_id);

        println!("{}", _query);
        _conn.query_map::<(String, i64, i64, String), _, _, TokenProps>(_query, |(accessToken,id, scopes, authorization_tye)| {
            TokenProps {
                token: AuthorizationToken{
                    _type: AuthorizationType::Bearer,
                    token: accessToken
                },
                authorization: Authorization::User,
                associated_id: id,
                scopes,
            }
        }).unwrap().pop()
    }
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
        let _query: String = format!("SELECT id,name,power FROM users WHERE id = {}", id);

        let data: Option<UserDataResponse> = _conn.query_map(_query, |(id, name, power)| {
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

pub async fn delete_authorization_code(code: String) {
    unsafe {
        let mut _conn: PooledConn = DATABASE_CLIENT.database_conn().await;
        let _query: String = format!("DELETE FROM authorization_code WHERE id=':id'");
        _conn.exec_drop(_query, params! {"id" => code}).unwrap();
    }
}

pub async fn authorize_client(user_id: i64, app: ClientApp) -> Result<String, ServerStatus> {
    unsafe {
        let mut _conn: PooledConn = DATABASE_CLIENT.database_conn().await;
        let _query: String = format!("INSERT INTO tokens (accessToken,id,scopes,authorization_tye,client_id) VALUES (:token,:id,:scopes,:authorization_tye,:client_id)");
        let p: &ClientApp = &app;

        return match _conn.exec_drop::<String, Params>(_query,
                                                       params! {
            "token" => "Bearer".to_owned() + &nanoid!(),
            "id" => user_id,
            "scopes" =>  p.properties.scopes,
            "authorization_tye" => AuthorizationType::User.as_str().to_string(),
            "client_id" => app.id
            }) {
            Ok(..) => {
                let code: String = nanoid!();

                _conn.exec::<String, String, Params>("INSERT INTO authorization_code (id, associated_id) VALUES (:id,:associated_id)".to_string(), params! {
                    "id" => code.clone(),
                    "associated_id" => user_id
                }).expect("panic!");

                Ok(code)
            },
            Err(err) =>  {
                println!("{}", err);
                Err(ServerStatus::BadRequest)
            }
        };


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

pub async fn verify_client(id: u64, secret: String) -> Option<ClientApp> {
    unsafe {
        let mut _conn: PooledConn = DATABASE_CLIENT.database_conn().await;
        let _query: String = format!("SELECT * FROM clients WHERE id = {:?} AND secret = {:?}", id, secret);

        _conn.query_map(_query, |(id, secret, name, token, scopes)| {
            ClientApp {
                id,
                secret,
                token,
                properties: ClientProperties{
                    name,
                    scopes
                }
            }
        }).unwrap().pop()
    }
}

pub async fn get_client(id: u64) -> Option<ClientApp> {
    unsafe {
        let mut _conn: PooledConn = DATABASE_CLIENT.database_conn().await;
        let _query: String = format!("SELECT * FROM clients WHERE id = {:?}", id);

        _conn.query_map(_query, |(id, secret, name, token, scopes)| {
            ClientApp {
                id,
                secret,
                token,
                properties: ClientProperties{
                    name,
                    scopes
                }
            }
        }).unwrap().pop()
    }
}

pub async fn verify_authorization(code: String) -> Option<i64> {
    unsafe {
        let mut _conn: PooledConn = DATABASE_CLIENT.database_conn().await;
        let _query: String = format!("SELECT associated_id FROM authorization_code WHERE id = {:?}", code);

        _conn.query_map(_query, |(associated_id)| {
            associated_id
        }).unwrap().pop()
    }
}

pub async fn verify_client_authorization(client_id: u64, user_id: i64) -> Result<TokenProps, ServerStatus> {
    if let Some(token) = verify_token_by_index(client_id, user_id).await {
        Ok(token)
    }else{
        Err(ServerStatus::TokenNotExist)
    }
}

pub unsafe fn initialize() {
    DB_POOL.set(Pool::new(URL).unwrap()).unwrap();
}
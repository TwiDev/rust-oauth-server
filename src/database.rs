use std::arch::asm;
use std::cell::OnceCell;
use std::str::FromStr;
use mysql;
use mysql::{Pool, PooledConn};
use mysql::prelude::Queryable;
use rocket::serde::{Deserialize, Serialize};

use crate::server::{Authorization, AuthorizationToken, AuthorizationType, TokenProps};

const URL: &str = "mysql://root:root@localhost:3306/core";
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
                let _query: String = format!("SELECT id FROM users WHERE token = {}", auth.token);

                _conn.query_map(_query, |(id)| {
                    TokenProps {
                        token: auth,
                        authorization:Authorization::User,
                        associated_id: id
                    }
                }).unwrap().pop()
            }
            AuthorizationType::Bearer => {
                let _query: String = format!("SELECT id, authorization_type FROM tokens WHERE accessToken = {}", auth.token);

                _conn.query_map(_query, |(id,authorization_type)| {
                    TokenProps {
                        token:auth,
                        authorization: Authorization::from_str(authorization_type).unwrap(),
                        associated_id: id
                    }
                }).unwrap().pop()
            }
            AuthorizationType::Bot => {
                let _query: String = format!("SELECT id FROM bots WHERE token = {}", auth.token);

                _conn.query_map(_query, |(id)| {
                    TokenProps {
                        token:auth,
                        authorization: Authorization::User,
                        associated_id: id
                    }
                }).unwrap().pop()
            }
        }
    }
}

pub async fn get_user_by_id(token: TokenProps, id: i64) {

}

pub unsafe fn initialize() {
    DB_POOL.set(Pool::new(URL).unwrap()).unwrap();
}
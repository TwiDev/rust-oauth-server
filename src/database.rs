use std::cell::OnceCell;
use mysql;
use mysql::{Pool, PooledConn};
use mysql::prelude::Queryable;
use rocket::serde::{Deserialize, Serialize};

use crate::server::AuthorizationToken;

const URL: &str = "mysql://root:root@localhost:3306/core";
static DB_POOL: OnceCell<Pool> = OnceCell::new();
static DATABASE_CLIENT: DatabaseClient = DatabaseClient {};

#[derive(Clone, Copy)]
pub struct DatabaseClient;

impl DatabaseClient {
    pub async fn database_pool(self) -> &'static Pool {
        DB_POOL.get().unwrap()
    }

    pub async fn database_conn(self) -> PooledConn {
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

pub async fn get_user_from_token(authorization: AuthorizationToken) -> Option<UserData> {
    let mut _conn: PooledConn = DATABASE_CLIENT.database_conn().await;

    let _query: String = format!("SELECT * FROM users WHERE token = {}", authorization.token);

    _conn.query_map(_query, |(id, name, power)| {
        UserData { id, name, power }
    }).unwrap().pop()
}

pub fn initialize() {
    DB_POOL.set(Pool::new(URL).unwrap()).unwrap();
}
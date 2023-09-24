pub struct ClientProperties {

    pub name: String,
    pub scopes: i64

}

pub struct ClientApp {

    pub id: i64,
    pub secret: String,
    pub token: String,
    pub properties: ClientProperties

}
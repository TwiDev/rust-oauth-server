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

impl ClientApp {

    pub fn new_empty(properties: ClientProperties) -> ClientApp {
        let pop: &ClientProperties = &properties;
        let secret: String = generate_app_secret(pop);
        let token: String = generate_app_token(pop);

        return ClientApp{
            id: -1,
            secret,
            token,
            properties,
        }
    }

    pub fn new(properties: ClientProperties, id: i64) -> ClientApp {
        let pop: &ClientProperties = &properties;
        let secret: String = generate_app_secret(pop);
        let token: String = generate_app_token(pop);

        return ClientApp{
            id,
            secret,
            token,
            properties,
        }
    }

    pub fn populate(app: ClientApp, id: i64) -> ClientApp {
        return ClientApp{id, secret: app.secret, token: app.token, properties: app.properties}
    }
}

pub fn generate_app_token(properties: &ClientProperties) -> String {
    return "".to_string()
}

pub fn generate_app_secret(properties: &ClientProperties) -> String {
    return "".to_string()
}
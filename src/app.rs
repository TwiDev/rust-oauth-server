use nanoid::nanoid;

#[derive(Clone)]
pub struct ClientProperties {

    pub name: String,
    pub scopes: i64

}

#[derive(Clone)]
pub struct ClientApp {

    pub id: u64,
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
            id: 0,
            secret,
            token,
            properties,
        }
    }

    pub fn new(properties: ClientProperties, id: u64) -> ClientApp {
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

    pub fn populate(app: ClientApp, id: u64) -> ClientApp {
        return ClientApp{id, secret: app.secret.clone(), token: app.token.clone(), properties: ClientProperties{
            scopes: app.properties.scopes,
            name: app.properties.name.clone()
        }}
    }
}

pub fn generate_app_token(properties: &ClientProperties) -> String {
    return "Bot".to_owned() + &nanoid!().to_string()
}

pub fn generate_app_secret(properties: &ClientProperties) -> String {
    return nanoid!()
}
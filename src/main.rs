use rocket::{catchers, launch, routes};

mod server;
mod responses;
mod database;

#[launch]
fn rocket() -> _ {
    database::initialize();

    rocket::build().mount("/", routes![server::signup_application,server::secret_application,server::token_application]).register("/", catchers![server::unauthorized])
}
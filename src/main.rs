use rocket::{catchers, launch, routes};
use crate::server::AuthorizationType;

mod server;
mod responses;
mod database;

#[launch]
fn rocket() -> _ {
    unsafe { database::initialize(); }

    rocket::build().mount("/", routes![server::signup_application,server::secret_application,server::token_application]).register("/", catchers![server::unauthorized])
}
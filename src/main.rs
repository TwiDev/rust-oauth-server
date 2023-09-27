use rocket::{catchers, launch, routes};

mod server;
mod responses;
mod database;
mod app;
mod status;

#[launch]
fn rocket() -> _ {
    unsafe { database::initialize(); }

    rocket::build().mount("/", routes![
        server::signup_application,
        server::secret_application,
        server::token_application,
        server::users_handler,
        server::private_users_handler,
        server::client_factory
    ]).register("/", catchers![server::unauthorized,server::notfound])
}
use rocket::{catchers, launch, routes};

mod server;
mod responses;

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![server::signup_application,server::secret_application,server::token_application]).register("/", catchers![server::unauthorized])
}
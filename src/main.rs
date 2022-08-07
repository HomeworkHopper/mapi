use dotenv;

fn main() {
    let email = dotenv::var("EMAIL").unwrap();
    let password = dotenv::var("PASSWORD").unwrap();

    println!("Email: {}, Password: {}", email, password);
}

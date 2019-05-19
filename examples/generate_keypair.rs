use ossuary;

fn main() {
    let (secret, public) = ossuary::generate_auth_keypair().unwrap();
    print!("let auth_secret_key = &[");
    for (idx,byte) in secret.iter().enumerate() {
        if idx % 8 == 0 {
            print!("\n    ");
        }
        print!("0x{:02x}, ", byte);
    }
    println!("\n];");
    print!("let auth_public_key = &[");
    for (idx,byte) in public.iter().enumerate() {
        if idx % 8 == 0 {
            print!("\n    ");
        }
        print!("0x{:02x}, ", byte);
    }
    println!("\n];");
}

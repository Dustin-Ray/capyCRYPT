use structopt::StructOpt;
use capycrypt::{Hashable, Message, SecParam};

#[derive(Debug, StructOpt)]
#[structopt(name = "capycrypt-cli", about = "A simple hashing CLI")]
enum Command {       //enums and structs in rust can be used almost interchangeably.
    #[structopt(name = "compute_sha3_hash")]   // the name of the program to run
    Sha3 {
        #[structopt(help = "The input string to hash")]
        input: String,

        #[structopt(help = "Number of bits for the SHA3 hash", short, long, default_value = "256")]
        bits: usize,
    },
}

fn main() {
    match Command::from_args() {
        Command::Sha3 { input, bits } => {
            let mut data = Message::new(input.into_bytes());
            let sec_param = SecParam::from_int(bits)
                .expect("Unsupported security parameter. Use 224, 256, 384, or 512");
            
            data.compute_hash_sha3(&sec_param).expect("An error occurred during hash computation.");
            
            match data.digest {
                Ok(digest) => println!("Hash: {}", hex::encode(digest.to_vec())),
                Err(_) => eprintln!("Error: Hash computation failed"),
            }
        }
    }
}
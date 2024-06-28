use capycrypt::{ecc::keypair::KeyPair, sha3::hashable::Hashable, Message, SecParam};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "capycrypt-cli",
    about = "Command-line interface for capycrypt library"
)]
enum Command {
    #[structopt(name = "sha3")]
    Sha3 {
        #[structopt(help = "The input string to hash")]
        input: String,

        #[structopt(
            help = "Number of bits for the SHA3 hash",
            short,
            long,
            default_value = "256"
        )]
        bits: usize,
    },

    #[structopt(name = "new_keypair")]
    NewKeypair {
        #[structopt(help = "Password")]
        pw: String,

        #[structopt(help = "Owner of the key pair")]
        owner: String,

        #[structopt(help = "Selected curve")]
        _curve: String,

        #[structopt(help = "Security length", short, long, default_value = "256")]
        bits: usize,

        #[structopt(help = "Output file name", short, long)]
        output: String,
    },
}

fn main() {
    match Command::from_args() {
        Command::Sha3 { input, bits } => {
            let mut data = Message::new(input.into_bytes());
            let sec_param = SecParam::try_from(bits)
                .expect("Unsupported security parameter. Use 224, 256, 384, or 512");

            data.compute_sha3_hash(&sec_param)
                .expect("An error occurred during hash computation.");

            match data.digest {
                Ok(digest) => println!("Hash: {}", hex::encode(digest)),
                Err(_) => eprintln!("Error: Hash computation failed"),
            }
        }

        Command::NewKeypair {
            pw,
            owner,
            _curve,
            bits,
            output,
        } => {
            let sec_param = SecParam::try_from(bits).expect("Unsupported security parameter.");
            let kp = KeyPair::new(pw.as_bytes(), owner, &sec_param)
                .expect("Unable to generate the requested key pair");

            let _ = kp.write_to_file(&output);
        }
    }
}

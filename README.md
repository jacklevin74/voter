# voter
Voter fetches records from XENBLOCKs ledger and runs verification in CPU 

Installation instructions:

Clone the repo:

$ git clone https://github.com/jacklevin74/voter
$ cd voter

Install Rust:

$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

check if cargo is installed:

$ cargo -v 

Build project:

$ cargo build --release

Run lightnode:

$ ./target/release/voter



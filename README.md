# QuikCrypt
A (hopefully) secure note-taking method that utilizes cryptography to encrypt notes, a little CLI tool also, all written in pure rust
# Setup Commands:
`git clone https://github.com/RustyKernelPunk/QuikCrypt.git`
`cargo build --release`(Assuming you are in the proper path)
Add this line to your terminal config, i.e. ~/.bashrc or ~/.zshrc, editing path as necessary:
`export PATH="$PATH:$HOME/path/to/target/release"`
now, from anywhere:
to encrypt, run:
`cat plaintext.txt | quikcrypt -cf note.enc`
to decrypt, run:
`quikcrypt -df note.enc`, you can pipe it into less `| less` or put it in a file `> note.txt`


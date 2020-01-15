use clap::{crate_authors, crate_version, load_yaml, App};
use std::process::Command;

fn main() {
    let yaml = load_yaml!("cli.yaml");
    let matches = App::from(yaml)
        .author(crate_authors!())
        .version(crate_version!())
        .get_matches();

    Command::new("ssh-keygen").spawn().unwrap().wait().unwrap();

    match matches.subcommand() {
        ("init", sub_matches) => init(sub_matches.unwrap()),
        _ => unreachable!(),
    }
}

fn init(args: &clap::ArgMatches) {
    
}

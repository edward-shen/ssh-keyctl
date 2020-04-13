use clap::derive::Clap;
use cli::{KeyInit, KeyRevoke, Opts, SubCommands};
use osshkeys::{cipher::Cipher, KeyPair};
use std::fs::read_to_string;
use std::fs::OpenOptions;
use std::os::unix::fs::PermissionsExt;
use std::{io::Write, process::Command};
mod cli;

#[derive(Debug)]
enum SshKeyCtlError {
    OSshKeySerialize(osshkeys::error::Error),
    IO(std::io::Error),
}

impl From<osshkeys::error::Error> for SshKeyCtlError {
    fn from(e: osshkeys::error::Error) -> Self {
        Self::OSshKeySerialize(e)
    }
}
impl From<std::io::Error> for SshKeyCtlError {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

fn main() -> Result<(), SshKeyCtlError> {
    let opts = Opts::parse();

    match opts.subcmd {
        SubCommands::Init(args) => init(&args)?,
        SubCommands::Revoke(args) => revoke(&args)?,
        SubCommands::Renew(args) => {
            revoke(&args.clone().into())?;
            init(&args.into())?;
        }
    }
    Ok(())
}

fn init(args: &KeyInit) -> Result<(), SshKeyCtlError> {
    let mut key_pair = KeyPair::generate(args.key_type.0, 0).unwrap();
    *key_pair.comment_mut() = args.comment.clone().unwrap();
    let mut ssh_folder = dirs::home_dir().unwrap();
    ssh_folder.push(".ssh");

    let target = args.target.split("@").collect::<Vec<_>>();
    let target = match target.as_slice() {
        [target] => target,
        [_, target] => target,
        _ => panic!(":("),
    };
    let mut priv_key_path = ssh_folder.clone();
    priv_key_path.push(target);
    let mut pub_key_path = priv_key_path.clone();
    pub_key_path.set_file_name(format!("{}.pub", target));

    [&priv_key_path, &pub_key_path].iter().for_each(|path| {
        if !args.force && path.as_path().exists() {
            panic!("aa");
        }
    });

    let mut priv_key_file = OpenOptions::new();
    if !args.force {
        priv_key_file.create_new(true);
    }
    let mut priv_key_file = priv_key_file.write(true).open(&priv_key_path)?;

    let mut perms = priv_key_file.metadata()?.permissions();
    perms.set_mode(0o600);
    priv_key_file.set_permissions(perms)?;
    priv_key_file.write(
        key_pair
            .serialize_openssh(
                args.password.as_ref().map(String::as_bytes),
                Cipher::Aes256_Ctr,
            )?
            .as_bytes(),
    )?;

    let mut pub_key_file = OpenOptions::new();
    if !args.force {
        pub_key_file.create_new(true);
    }
    let mut pub_key_file = pub_key_file.write(true).open(pub_key_path)?;

    pub_key_file.write(key_pair.serialize_publickey()?.as_bytes())?;
    pub_key_file.write("\n".as_bytes())?;

    Command::new("ssh-copy-id")
        .arg("-i")
        .arg(priv_key_path)
        .arg("-p")
        .arg(args.port.to_string())
        .arg(&args.target)
        .spawn()
        .unwrap()
        .wait()
        .unwrap();

    // todo: edit .ssh/config file
    Ok(())
}

fn revoke(args: &KeyRevoke) -> Result<(), SshKeyCtlError> {
    let target = args.target.split("@").collect::<Vec<_>>();
    let target = *match target.as_slice() {
        [target] => target,
        [_, target] => target,
        _ => panic!(":("),
    };

    let mut key_file_path = dirs::home_dir().unwrap();
    key_file_path.push(".ssh");
    let key_file_name = match &args.identity_file_path {
        None => &args.target,
        Some(path) => path,
    };
    key_file_path.push(format!("{}.pub", key_file_name));
    let key_data = read_to_string(key_file_path).unwrap();
    let key_data = key_data.trim().replace("/", "\\/");
    Command::new("ssh")
        .args(&[
            target,
            "-C",
            &format!("sed -i '/{}/d' .ssh/authorized_keys", key_data),
        ])
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    Ok(())
}

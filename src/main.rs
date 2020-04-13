use clap::derive::Clap;
use cli::{KeyInit, KeyRevoke, Opts, SubCommands};
use osshkeys::{cipher::Cipher, KeyPair};
use std::fs::{read_to_string, remove_file, OpenOptions};
use std::{io::Write, path::Path, process::Command};
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
    match Opts::parse().subcmd {
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
    let mut key_pair = KeyPair::generate(args.key_type.0, 0)?;
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
    safely_write(
        priv_key_path.as_path(),
        key_pair
            .serialize_openssh(
                args.passphrase.as_ref().map(String::as_bytes),
                Cipher::Aes256_Ctr,
            )?
            .as_bytes(),
        true,
        args.force,
    )?;

    let mut pub_key_path = priv_key_path.clone();
    pub_key_path.set_file_name(format!("{}.pub", target));
    let pub_key_data = key_pair.serialize_publickey()?;
    let mut pub_key_data = pub_key_data.as_bytes().to_vec();
    pub_key_data.push('\n' as u8);
    safely_write(pub_key_path.as_path(), &pub_key_data, false, args.force)?;

    // todo: edit .ssh/config file
    Ok(())
}

/// Safely writes to a path, requiring a force flag to overwrite it. If the
/// private flag is true and the target operating system is Unix, then also sets
/// the file to read/write only to the owner of the file. On other operating
/// systems, does nothing. since they likely can't support the permissions that
/// SSH prefers.
fn safely_write(
    path: &Path,
    buffer: &[u8],
    is_private: bool,
    force: bool,
) -> Result<(), SshKeyCtlError> {
    if !force && path.exists() {
        panic!("file already exists");
    }

    let mut priv_key_file = OpenOptions::new();
    if !force {
        priv_key_file.create_new(true);
    }
    let mut priv_key_file = priv_key_file.write(true).open(path)?;

    #[cfg(unix)]
    {
        if is_private {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = priv_key_file.metadata()?.permissions();
            perms.set_mode(0o600);
            priv_key_file.set_permissions(perms)?;
        }
    }

    priv_key_file.write(buffer)?;

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
    let key_data = read_to_string(&key_file_path)?;
    let key_data = key_data.trim().replace("/", "\\/");
    Command::new("ssh")
        .args(&[
            target,
            "-C",
            // todo: make gnu sed independent
            &format!("sed -i '/{}/d' .ssh/authorized_keys", key_data),
        ])
        .spawn()?
        .wait()?;

    if args.delete_identity_file {
        remove_file(&key_file_path)?;
        key_file_path.set_extension("");
        remove_file(&key_file_path)?;
    }
    Ok(())
}

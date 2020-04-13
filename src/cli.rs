use clap::Clap;
use osshkeys::keys::KeyType as OsshKeyType;

/// A helper to manage unique SSH keys.
///
/// ssh-keyctl is a tool that helps manage unique SSH keys for every host. It
/// offers a simple way to initialize, revoke, and renew SSH keys. ssh-keyctl
/// is completely stateless, so modifications to your .ssh folder should not
/// affect how ssh-keyctl functions. It works on a fail-safe basis, and thus
/// requires users to explicitly indicate when they wish to perform destructive
/// tasks, such as overwritting files or deleting them.
#[derive(Clap, Clone)]
#[clap(author, version)]
pub struct Opts {
    #[clap(subcommand)]
    pub subcmd: SubCommands,
}

#[derive(Clap, Clone)]
pub enum SubCommands {
    Init(KeyInit),
    Revoke(KeyRevoke),
    Renew(KeyRenew),
}

/// Generate and add a new key to the user's authorized_keys on the remote host.
///
/// Given a target, it generates a new keypair with the filename as the name
/// of the remote host. ed25519 is used by default as the key type, as most
/// implementations should support it by now, is smaller, and offers the same or
/// more crypographic integrity than RSA. By default, a long flag is required to
/// overwrite an existing key that exists with the same name as the remote host.
#[derive(Clap, Clone)]
pub struct KeyInit {
    /// The target to generate a keypair to. This follows the form [username@]host.
    pub target: String,

    /// Which type of key to use. RSA is well supported, while ed25519 is the most recent.
    #[clap(short = "t", long = "type", default_value = "ed25519")]
    pub key_type: KeyType,

    /// The comment for the SSH key. Generally, this should be
    /// `username@hostname` of the computer that generated the key.
    #[clap(short, long)]
    pub comment: Option<String>,

    /// What port the SSH server is listening to.
    #[clap(short, default_value = "22")]
    pub port: u16,

    /// Set an optional password on your SSH key.
    #[clap(short = "P", long)]
    pub passphrase: Option<String>,

    /// Overwrite an existing private and public keypair. This is dangerous
    /// and can leave you without access to the remote host. Use only if you
    /// know what you're doing!
    #[clap(long = "overwrite-ssh-keys")]
    pub force: bool,
}

impl From<KeyRenew> for KeyInit {
    fn from(key_renew: KeyRenew) -> Self {
        Self {
            target: key_renew.target,
            key_type: key_renew.key_type,
            comment: key_renew.comment,
            port: key_renew.port,
            passphrase: key_renew.password,
            force: key_renew.force,
        }
    }
}

/// Delete a public key from the user's authorized_keys on the remote host.
///
/// Sends a SSH command using the provided identity file to remove the public
/// key portion of the provided identity file from the authorized_keys for the
/// specified user on the remote host.
#[derive(Clap, Clone)]
pub struct KeyRevoke {
    /// The target to generate a keypair to. This follows the form [username@]host.
    pub target: String,

    /// The name of the public key file to revoke, without the .pub file
    /// extension. If not is provided, the hostname is used as default.
    pub identity_file_path: Option<String>,

    /// What port the SSH server is listening to.
    #[clap(short, default_value = "22")]
    pub port: u16,

    /// Delete the identity file after revocation. Set to false by default as a
    /// pre-emptive safety measure.
    #[clap(long)]
    pub delete_identity_file: bool,
}

impl From<KeyRenew> for KeyRevoke {
    fn from(key_renew: KeyRenew) -> Self {
        Self {
            target: key_renew.target,
            identity_file_path: key_renew.identity_file_path,
            port: key_renew.port,
            delete_identity_file: key_renew.delete_identity_file,
        }
    }
}

/// Shortcut for both revoke and then renew a SSH key.
#[derive(Clap, Clone)]
pub struct KeyRenew {
    /// The target to generate a keypair to. This follows the form [username@]host.
    pub target: String,

    /// Which type of key to use. RSA is well supported, while ed25519 is the most recent.
    #[clap(short = "t", long = "type", default_value = "ed25519")]
    pub key_type: KeyType,

    /// The comment for the SSH key. Generally, this should be
    /// `username@hostname` of the computer that generated the key.
    #[clap(short, long)]
    pub comment: Option<String>,

    /// What port the SSH server is listening to.
    #[clap(short, long, default_value = "22")]
    pub port: u16,

    /// Set an optional password on your SSH key.
    #[clap(short = "P", long)]
    pub password: Option<String>,

    /// Overwrite an existing private and public keypair. This is dangerous
    /// and can leave you without access to the remote host. Use only if you
    /// know what you're doing!
    #[clap(long = "overwrite-ssh-keys")]
    pub force: bool,

    /// The name of the public key file to revoke, without the .pub file
    /// extension. If not is provided, the hostname is used as default.
    pub identity_file_path: Option<String>,

    /// Delete the identity file after revocation. Set to false by default as a
    /// pre-emptive safety measure.
    #[clap(long)]
    pub delete_identity_file: bool,
}

#[derive(Debug, Clone)]
pub enum ParseError {
    UnknownKeyType(String),
}

#[derive(Debug, Clone)]
pub struct KeyType(pub OsshKeyType);

impl std::str::FromStr for KeyType {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "rsa" => Ok(KeyType(OsshKeyType::RSA)),
            "dsa" => Ok(KeyType(OsshKeyType::DSA)),
            "ed25519" => Ok(KeyType(OsshKeyType::ED25519)),
            "ecdsa" => Ok(KeyType(OsshKeyType::ECDSA)),
            _ => Err(ParseError::UnknownKeyType(s.to_string())),
        }
    }
}

impl Default for KeyType {
    fn default() -> Self {
        Self(OsshKeyType::ED25519)
    }
}

impl std::string::ToString for ParseError {
    fn to_string(&self) -> String {
        match self {
            Self::UnknownKeyType(_) => {
                String::from(format!("Must be one of rsa, dsa, ecdsa, or ed25519"))
            }
        }
    }
}

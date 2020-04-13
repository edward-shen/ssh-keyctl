use clap::Clap;
use osshkeys::keys::KeyType as OsshKeyType;

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

#[derive(Clap, Clone)]
pub struct KeyInit {
    pub target: String,
    #[clap(short = "t", long = "type", default_value = "ed25519")]
    pub key_type: KeyType,
    #[clap(short, long)]
    /// The comment for the SSH key. Generally, this should be
    /// `username@hostname` of the computer that generated the key.
    pub comment: Option<String>,
    #[clap(short, default_value = "22")]
    pub port: u16,
    #[clap(short = "P", long)]
    pub passphrase: Option<String>,
    #[clap(short, long)]
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

#[derive(Clap, Clone)]
pub struct KeyRevoke {
    pub target: String,
    pub identity_file_path: Option<String>,
    #[clap(short, long, default_value = "22")]
    pub port: u16,
    #[clap(short, long)]
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

#[derive(Clap, Clone)]
pub struct KeyRenew {
    pub target: String,
    #[clap(short = "t", long = "type", default_value = "ed25519")]
    pub key_type: KeyType,
    #[clap(short, long)]
    pub comment: Option<String>,
    #[clap(short, long, default_value = "22")]
    pub port: u16,
    #[clap(short = "P", long)]
    pub password: Option<String>,
    #[clap(short, long)]
    pub force: bool,
    pub identity_file_path: Option<String>,
    #[clap(short, long)]
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

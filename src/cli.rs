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
    #[clap(short = "c", long = "comment")]
    /// The comment for the SSH key. Generally, this should be
    /// `username@hostname` of the computer that generated the key.
    pub comment: Option<String>,
    #[clap(short = "p", long = "port", default_value = "22")]
    pub port: u16,
    #[clap(short = "P", long = "passphrase")]
    pub password: Option<String>,
    #[clap(short = "f", long = "--force")]
    pub force: bool,
}

impl From<KeyRenew> for KeyInit {
    fn from(key_renew: KeyRenew) -> Self {
        Self {
            target: key_renew.target,
            key_type: key_renew.key_type,
            comment: key_renew.comment,
            port: key_renew.port,
            password: key_renew.password,
            force: key_renew.force,
        }
    }
}

#[derive(Clap, Clone)]
pub struct KeyRevoke {
    pub target: String,
    pub identity_file_path: Option<String>,
    #[clap(short = "p", long = "port", default_value = "22")]
    pub port: u16,
}

impl From<KeyRenew> for KeyRevoke {
    fn from(key_renew: KeyRenew) -> Self {
        Self {
            target: key_renew.target,
            identity_file_path: key_renew.identity_file_path,
            port: key_renew.port,
        }
    }
}

#[derive(Clap, Clone)]
pub struct KeyRenew {
    pub target: String,
    #[clap(short = "t", long = "type", default_value = "ed25519")]
    pub key_type: KeyType,
    #[clap(short = "c", long = "comment")]
    pub comment: Option<String>,
    #[clap(short = "p", long = "port", default_value = "22")]
    pub port: u16,
    #[clap(short = "P", long = "passphrase")]
    pub password: Option<String>,
    #[clap(short = "f", long = "--force")]
    pub force: bool,
    pub identity_file_path: Option<String>,
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

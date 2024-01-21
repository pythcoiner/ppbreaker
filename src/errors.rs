use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum CustomError {
    FileDoesNotExist(String),
    CannotOpenFile(String),
    CannotReadLine(String),
    NoAddress,
    WrongAddress,
    WrongMnemonic,
    NoMnemonic,
    WrongDerivationPath,
    NoDerivationPath,
    WrongIndex,
    XPrivError,
    DeriveError,
    FailStartWorker,
    CannotWriteFile(String),
    NoWorkers,
    CannotParseWorkerMsg,
    CannotParseUSize,
    CannotTakeStdout,
    CannotRemoveFile(String),
}

impl fmt::Display for CustomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CustomError::NoAddress => write!(
                f,
                "No address to check against specified and address.txt not found!"
            ),
            CustomError::FileDoesNotExist(file) => write!(f, "File {file} does not exist!"),
            CustomError::CannotOpenFile(file) => write!(f, "Cannot open file {file}!"),
            CustomError::CannotReadLine(file) => write!(f, "Cannot read line in {file}!"),
            CustomError::WrongAddress => write!(f, "Wrong address!"),
            CustomError::WrongMnemonic => write!(f, "Wrong Mnemonic!"),
            CustomError::NoMnemonic => write!(f, "Missing --mnemonic or --mnemonic-file arg!"),
            CustomError::WrongDerivationPath => write!(f, "Wrong derivation path!"),
            CustomError::NoDerivationPath => {
                write!(f, "--derivation-path or --address-type missing!")
            }
            CustomError::WrongIndex => write!(f, "Wrong index!"),
            CustomError::XPrivError => {
                write!(f, "Cannot generate private key from mnemonic/passphrase!")
            }
            CustomError::DeriveError => write!(f, "Cannot derive from Xpriv!"),
            CustomError::FailStartWorker => write!(f, "Fail to start subprocess!"),
            CustomError::CannotWriteFile(file) => {
                write!(f, "Cannot write file {}", file.to_string())
            }
            CustomError::NoWorkers => write!(f, "No workers!"),
            CustomError::CannotParseWorkerMsg => write!(f, "Cannot parse message from worker"),
            CustomError::CannotParseUSize => write!(f, "Cannot parse usize from string"),
            CustomError::CannotTakeStdout => write!(f, "Cannot take stdout from worker"),
            CustomError::CannotRemoveFile(file) => write!(f, "Cannot remove file {}", file),
            _ => write!(f, "Unimplemented error!"),
        }
    }
}

impl Error for CustomError {}

impl From<CustomError> for String {
    fn from(error: CustomError) -> Self {
        error.to_string()
    }
}

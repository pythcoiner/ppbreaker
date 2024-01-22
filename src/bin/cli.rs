extern crate bip39;
extern crate bitcoin;

extern crate ppfinder;

use bip39::Mnemonic;
use bitcoin::address::NetworkUnchecked;
use bitcoin::bip32::DerivationPath;
use bitcoin::Address;
use ppfinder::{CustomError, MatchResult, PassphraseFinder};
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::str::FromStr;

use clap::Parser;

#[derive(Debug, Clone)]
enum AddressType {
    P2pkh,
    P2sh,
    Segwit,
    Taproot,
}

impl FromStr for AddressType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "p2pkh" => Ok(AddressType::P2pkh),
            "p2sh" => Ok(AddressType::P2sh),
            "p2wpkh" => Ok(AddressType::Segwit),
            "bech32" => Ok(AddressType::Segwit),
            "segwit" => Ok(AddressType::Segwit),
            "segwitv0" => Ok(AddressType::Segwit),
            "segwitv1" => Ok(AddressType::Taproot),
            "bech32m" => Ok(AddressType::Taproot),
            "taproot" => Ok(AddressType::Taproot),
            _ => Err(format!("Invalid Address Type: {}", s)),
        }
    }
}

/// ppfinder is a simple CLI tool for Bitcoin users who have lost their wallet's passphrase but still
/// have their mnemonic words and at least a known address. It helps to recover the passphrase by trying different
/// combinations based on the provided mnemonic words. The tool supports customizing the derivation path,
/// address type, and index. Users can input mnemonic words directly or via a file, and specify the number of processes.
///
#[derive(Parser, Debug)]
struct Cli {
    /// Address to check against, if not defined, will check content of address.txt.
    #[arg(short, long)]
    address: Option<String>,

    /// Derivation path to use, if none of --derivation-path or --address-type defined, 'm/84h/0h/0h/0/*' will be used
    #[arg(short = 'd', long)]
    derivation_path: Option<String>,

    /// Address type to use, if none of --derivation-path or --address-type defined, 'm/84h/0h/0h/0/*' will be used
    /// as derivation path
    #[arg(short = 't', long)]
    address_type: Option<AddressType>,

    /// Mnemonic words to use, can be 12, 18, 24 words.
    #[arg(short, long)]
    mnemonic: Option<String>,

    /// File to retrieve the mnemonic words to use.
    #[arg(short = 'f', long)]
    mnemonic_file: Option<String>,

    /// File where the passphrases are stored.
    #[arg(short = 'p', long, default_value = "passphrases.txt")]
    passphrase_dictionary: String,

    /// Derivation index to check, it can be pass in several forms: '0' or '[0,1,3]' or '0..1' or '0..=1'
    #[arg(short, long, default_value = "0")]
    index: String,

    /// Number of processes to launch.
    #[arg(short = 'k', long, default_value = "1")]
    processes: usize,

    /// Worker id, used when called by main instance as a subprocess worker
    #[arg(short = 'w', long)]
    worker: Option<usize>,
    // #[command(subcommand)]
    // command: Commands,
}

fn get_file_handle(path: &str) -> Result<BufReader<File>, CustomError> {
    // TODO: support absolute paths
    let file_path = env::current_exe()
        .expect("Fetch execution path should not fail!")
        .as_path()
        .parent()
        .expect("should not fail!")
        .join(path);

    if !file_path.exists() {
        Err(CustomError::FileDoesNotExist(path.to_string()))
    } else {
        // Open the file in read-only mode
        let file =
            File::open(&file_path).map_err(|_| CustomError::CannotOpenFile(path.to_string()))?;
        Ok(BufReader::new(file))
    }
}

fn parse_index(index: &str) -> Result<Vec<u32>, CustomError> {
    // Try to parse as u32
    if let Ok(idx) = u32::from_str(index) {
        return Ok(vec![idx; 1]);
    }

    // Try to parse List
    if let Ok(indexes) = serde_json::from_str::<Vec<u32>>(index) {
        return Ok(indexes);
    }

    // try to parse inclusive range
    if let Some(range_parts) = index.split_once("..=") {
        if let (Ok(start), Ok(end)) = (u32::from_str(range_parts.0), u32::from_str(range_parts.1)) {
            return Ok((start..=end).collect());
        }
    }

    // try to parse range
    if let Some(range_parts) = index.split_once("..") {
        if let (Ok(start), Ok(end)) = (u32::from_str(range_parts.0), u32::from_str(range_parts.1)) {
            return Ok((start..end).collect());
        }
    }

    Err(CustomError::WrongIndex)
}

fn parse_address(address: Option<String>) -> Result<Address<NetworkUnchecked>, CustomError> {
    if let Some(addr) = &address {
        // if address passed, parse it
        Ok(Address::from_str(addr).map_err(|_| CustomError::WrongAddress)?)
    } else {
        // else check if address.txt exist
        let mut file = get_file_handle("address.txt").map_err(|_| CustomError::NoAddress)?;
        let mut first_line = String::new();
        // if first line not empty
        if file
            .read_line(&mut first_line)
            .map_err(|_| CustomError::NoAddress)?
            > 0
        {
            // parse address
            Address::from_str(first_line.trim()).map_err(|_| CustomError::WrongAddress)
        } else {
            // else return no address passed
            Err(CustomError::NoAddress)
        }
    }
}

fn parse_mnemonic(
    mnemonic: Option<String>,
    mnemonic_file: Option<String>,
) -> Result<Mnemonic, CustomError> {
    if let Some(mnemonic) = &mnemonic {
        // if mnemonic passed, parse it
        Mnemonic::from_str(mnemonic).map_err(|_| CustomError::WrongMnemonic)
    } else if mnemonic_file.is_some() {
        // else if --mnemonic-file passed, try to parse it
        let mut file =
            get_file_handle(&mnemonic_file.unwrap()).map_err(|_| CustomError::WrongMnemonic)?;
        let mut first_line = String::new();
        // if first line not empty
        if file
            .read_line(&mut first_line)
            .map_err(|_| CustomError::WrongMnemonic)?
            > 0
        {
            // parse mnemonic
            Mnemonic::from_str(first_line.trim()).map_err(|_| CustomError::WrongMnemonic)
        } else {
            // else return wrong mnemonic
            Err(CustomError::WrongMnemonic)
        }
    } else {
        Err(CustomError::NoMnemonic)
    }
}

fn parse_derivation_path(
    address_type: Option<AddressType>,
    derivation_path: Option<String>,
) -> Result<DerivationPath, CustomError> {
    let path = if address_type.is_some() {
        // if address_type passed, parse it
        Ok(match address_type.unwrap() {
            AddressType::P2pkh => "m/44h/0h/0h/0",
            AddressType::P2sh => "m/49h/0h/0h/0",
            AddressType::Segwit => "m/84h/0h/0h/0",
            AddressType::Taproot => "m/86h/0h/0h/0",
        }
        .to_string())
    } else if derivation_path.is_some() {
        Ok(derivation_path.unwrap())
    } else {
        Err(CustomError::NoDerivationPath)
    }?;

    DerivationPath::from_str(&path).map_err(|_| CustomError::WrongDerivationPath)
}

fn parse_passphrases(
    passphrase_dictionary: String,
    mute: bool,
) -> Result<Vec<String>, CustomError> {
    let mut passphrases: Vec<String> = Vec::new();
    let file = get_file_handle(&passphrase_dictionary)?;
    if !mute {
        println!("Loading passphrases:");
        print!("\x1B[1A\x1B[K");
        println!("0 passphrases loaded...");
    }

    for line in file.lines().flatten() {
        passphrases.push(line);
        if passphrases.len() % 10_000 == 0  && !mute{
                print!("\x1B[1A\x1B[K");
                println!("{} passphrases loaded...", passphrases.len());
        }
    }
    if !mute {
        print!("\x1B[1A\x1B[K");
        println!("Loaded {} passphrases!", passphrases.len());
    }

    Ok(passphrases)
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();
    // dbg!(&cli);

    let addr = parse_address(cli.address)?.payload().to_owned();
    let address = bitcoin::Address::new(bitcoin::Network::Bitcoin, addr);

    let mnemonic = parse_mnemonic(cli.mnemonic, cli.mnemonic_file)?;

    let derivation_path = parse_derivation_path(cli.address_type, cli.derivation_path)?;

    let index = parse_index(&cli.index)?;

    let passphrases = parse_passphrases(cli.passphrase_dictionary, cli.worker.is_some())?;

    let worker_id = cli.worker;

    let mut ppb = PassphraseFinder::new(
        address,
        mnemonic,
        derivation_path,
        passphrases,
        index,
        cli.processes,
        worker_id,
    );

    if let MatchResult::Match(pp) = ppb.start()? {
        if worker_id.is_none() {
            println!("Passphrase found: {pp}");
        }
        // TODO: write result into a file 'pp.found'
        Ok(())
    } else {
        if worker_id.is_none() {
            println!("Passphrase not found!");
        }
        Ok(())
    }
}

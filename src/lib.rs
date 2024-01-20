extern crate bip39;
extern crate bitcoin;
mod errors;

use bip39::Mnemonic;
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpub};
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::{bip32, Address, Network};
use std::str::FromStr;
pub use errors::CustomError;
use crate::MatchResult::{DoNotMatch, Match};

pub enum MatchResult {
    Match(String),
    DoNotMatch,
}

pub struct PassphraseFinder {
    secp: Secp256k1<All>,
    address: Address,
    mnemonic: Mnemonic,
    derivation_path: DerivationPath,
    passphrases: Vec<String>,
    indexes: Vec<u32>,
    proc: u8,
}

impl PassphraseFinder {
    pub fn new(
        address: Address,
        mnemonic: Mnemonic,
        derivation_path: DerivationPath,
        passphrases: Vec<String>,
        indexes: Vec<u32>,
        proc: u8,
    ) -> Self {
        let secp = Secp256k1::new();
        PassphraseFinder {
            secp,
            address,
            mnemonic,
            derivation_path,
            passphrases,
            indexes,
            proc,
        }
    }

    fn mnemonic_to_xpub(&self, mnemonic: &Mnemonic, passphrase: &str) -> Result<Xpub, CustomError> {
        let xpriv =
            bip32::Xpriv::new_master(Network::Bitcoin, &mnemonic.to_seed(passphrase))
                .map_err(|_| CustomError::XPrivError)?
                .derive_priv(&self.secp, &self.derivation_path)
                .map_err(|_| CustomError::DeriveError)?;

        Ok(Xpub::from_priv(&self.secp, &xpriv))
    }

    fn get_address(&self, xpub: &Xpub, index: u32) -> Result<Address, CustomError> {
        let idx = ChildNumber::from_normal_idx(index).unwrap();
        let public_key = xpub.derive_pub(&self.secp, &[idx]).unwrap().public_key;
        Ok(Address::p2wpkh(&public_key.try_into().unwrap(), Network::Bitcoin).unwrap())
    }

    fn check_passphrase(&self, passphrase: &String) -> Result<bool, CustomError> {
        let xpub = self.mnemonic_to_xpub(&self.mnemonic, passphrase)?;
        for i in &self.indexes{
            let address = &self.get_address(&xpub, i.to_owned())?;
            if address == &self.address {
                return Ok(true);
            }
        };
        Ok(false)

    }

    pub fn start(&self) -> Result<MatchResult, CustomError> {
        let total = self.passphrases.len();
        println!("0/{} passphrases checked...", total);
        for (idx, p) in self.passphrases.iter().enumerate() {
            if self.check_passphrase(p)? {
                return Ok(Match(p.clone()));
            }

            if idx % 10 == 0 {
                // remove last line
                print!("\x1B[1A\x1B[K");
                println!("{}/{} passphrases checked...", idx, total);
            }
        }
        println!("{}/{} passphrases checked...", total, total);
        Ok(DoNotMatch)
    }
}

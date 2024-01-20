extern crate bitcoin;
extern crate bip39;

use std::str::FromStr;
use bitcoin::{Address, bip32, Network};
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpub};
use bitcoin::secp256k1::ffi::types::AlignedType;
use bitcoin::secp256k1::{AllPreallocated, Secp256k1};

fn mnemonic_to_xpub(secp: &Secp256k1<AllPreallocated>, mnemonic_phrase: &str, passphrase: &str) -> Xpub {
    let mnemonic = bip39::Mnemonic::from_str(mnemonic_phrase).unwrap();

    let root = bip32::Xpriv::new_master(bitcoin::Network::Bitcoin,
                                        &mnemonic.to_seed(passphrase)).unwrap();

    let path = DerivationPath::from_str("m/84h/0h/0h/0").unwrap();
    let child = root.derive_priv(&secp, &path).unwrap();

    Xpub::from_priv(&secp, &child)
}

fn get_address(secp: &Secp256k1<AllPreallocated>, &xpub: &Xpub, index: u32) -> String {

    let idx = ChildNumber::from_normal_idx(index).unwrap();
    let public_key_0 = xpub.derive_pub(&secp, &[idx]).unwrap().public_key;
    Address::p2wpkh(&public_key_0.try_into().unwrap(), Network::Bitcoin).unwrap().to_string()
}

fn check_passphrase(mnemonic: &str, passphrase: &str, expected_address: &str, secp: &Secp256k1<AllPreallocated>) -> bool {

    let range = 0..=1;

    let xpub = mnemonic_to_xpub(&secp, mnemonic, passphrase);

    for i in range {
        if get_address(&secp, &xpub, 0) == expected_address {
            return true;
        }
    }

    false
}

fn main() {
    let mnemonic = "planet woman brave monster novel million disagree tone brush zoo edge laundry"; // example mnemonic
    let passphrase = "fuck"; // your passphrase

    let mut buf: Vec<AlignedType> = Vec::new();
    buf.resize(Secp256k1::preallocate_size(), AlignedType::zeroed());
    let secp = Secp256k1::preallocated_new(buf.as_mut_slice()).unwrap();

    let xpub = mnemonic_to_xpub(&secp, mnemonic, passphrase);

    let address = get_address(&secp, &xpub, 0);
    println!("Receiving address 0: {}", address);

    let address = get_address(&secp, &xpub, 1);
    println!("Receiving address 1: {}", address);




}

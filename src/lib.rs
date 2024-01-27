extern crate bip39;
extern crate bitcoin;
mod errors;

use crate::WorkerState::{Ended, Match};
use bip39::Mnemonic;
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpub};
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::{bip32, Address, Network};
use std::{sync::mpsc, thread, time::SystemTime};

pub use errors::CustomError;

pub enum WorkerState {
    Match(FoundData),
    Ended,
    Running,
    Idle,
}

#[derive(Clone)]
enum WorkerMsg {
    Progress {
        id: usize,
        actual_pp: usize,
        total_pp: usize,
    },
    Found {
        id: usize,
        found_data: FoundData,
    },
    Ended(usize),
}

struct GlobalProgress {
    actual_pp: usize,
    total_pp: usize,
}

struct Eta {
    days: u32,
    hours: u32,
    minutes: u32,
    seconds: u32,
}

struct WorkerStatus {
    total_pp: usize,
    actual_pp: usize,
    state: WorkerState,
}

impl WorkerStatus {
    fn update(&mut self, msg: WorkerMsg) {
        if let WorkerMsg::Progress {
            id: _,
            actual_pp,
            total_pp,
        } = msg
        {
            self.actual_pp = actual_pp;
            self.total_pp = total_pp;

            if actual_pp >= total_pp {
                self.state = Ended;
            }
        }
    }
}

#[derive(Clone)]
pub struct FoundData {
    pub mnemonic: Mnemonic,
    pub passphrase: String,
    pub derivation_path: DerivationPath,
    pub address: Address,
}

/// Struct representing a Worker that will try to bruteforce passphrase in order to find a target address given a set of
/// fixed predefined mnemonic/derivation_path and lists of passphrases/derivation indexes. Send WorkerMsg frequently on
/// <tx> mpsc channel to keep the manager up to date with the worker status.
pub struct Worker {
    secp: Secp256k1<All>,
    address: Address,
    mnemonic: Mnemonic,
    derivation_path: DerivationPath,
    passphrases: Vec<String>,
    indexes: Vec<u32>,
    tx: Option<mpsc::Sender<WorkerMsg>>,
    id: usize,
    progress_step: usize,
}

impl Worker {
    pub fn new(
        address: Address,
        mnemonic: Mnemonic,
        derivation_path: DerivationPath,
        passphrases: Vec<String>,
        indexes: Vec<u32>,
        id: usize,
        progress_step: usize,
    ) -> Self {
        let secp = Secp256k1::new();
        Worker {
            secp,
            address,
            mnemonic,
            derivation_path,
            passphrases,
            indexes,
            tx: None,
            id,
            progress_step,
        }
    }

    /// Process root Xpub given <mnemonic> + <passphrase> + <root derivation path>.
    fn mnemonic_to_xpub(&self, passphrase: &str) -> Result<Xpub, CustomError> {
        let xpriv = bip32::Xpriv::new_master(Network::Bitcoin, &self.mnemonic.to_seed(passphrase))
            .map_err(|_| CustomError::XPrivError)?
            .derive_priv(&self.secp, &self.derivation_path)
            .map_err(|_| CustomError::DeriveError)?;

        Ok(Xpub::from_priv(&self.secp, &xpriv))
    }

    /// Derive Xpub at <index> and return the relevant address.
    fn get_address(&self, xpub: &Xpub, index: u32) -> Result<Address, CustomError> {
        let idx = ChildNumber::from_normal_idx(index).unwrap();
        let public_key = xpub.derive_pub(&self.secp, &[idx]).unwrap().public_key;
        Ok(Address::p2wpkh(&public_key.into(), Network::Bitcoin).unwrap())
    }

    /// Process all addresses from root Xpub by deriving at all <indexes> and return true if one match.
    fn check_passphrase(&self, passphrase: &str) -> Result<Option<u32>, CustomError> {
        let xpub = self.mnemonic_to_xpub(passphrase)?;
        for i in &self.indexes {
            let address = &self.get_address(&xpub, i.to_owned())?;
            if address == &self.address {
                return Ok(Some(*i));
            }
        }
        Ok(None)
    }

    /// Start this process as a worker
    pub fn start(&self) -> Result<(), CustomError> {
        if let Some(tx) = &self.tx {
            // for all passphrases
            for (idx, p) in self.passphrases.iter().enumerate() {
                // check is pp matching
                if let Some(index) = self.check_passphrase(p)? {
                    let child = ChildNumber::from_normal_idx(index).unwrap();
                    let data = FoundData {
                        mnemonic: self.mnemonic.clone(),
                        passphrase: p.clone(),
                        derivation_path: self.derivation_path.clone().child(child),
                        address: self.address.clone(),
                    };
                    let msg = WorkerMsg::Found {
                        id: 0,
                        found_data: data,
                    };

                    tx.send(msg).map_err(|_| CustomError::CannotSendMsg)?;
                    return Ok(());
                }

                // update manager w/ self progress
                if idx % self.progress_step == 0 {
                    tx.send(WorkerMsg::Progress {
                        id: self.id,
                        actual_pp: idx,
                        total_pp: self.passphrases.len(),
                    })
                    .map_err(|_| CustomError::CannotSendMsg)?;
                }
            }
            tx.send(WorkerMsg::Ended(self.id))
                .map_err(|_| CustomError::CannotSendMsg)?;
            Ok(())
        } else {
            Err(CustomError::NoChannel)
        }
    }
}

pub struct PassphraseFinder {
    workers: Vec<Option<Worker>>,
    workers_status: Vec<WorkerStatus>,
    rx: Option<mpsc::Receiver<WorkerMsg>>,
    found_data: Option<FoundData>,
    start_time: Option<SystemTime>,
}

impl PassphraseFinder {
    pub fn new(
        address: Address,
        mnemonic: Mnemonic,
        derivation_path: DerivationPath,
        passphrases: Vec<String>,
        indexes: Vec<u32>,
        proc: usize,
        progress_step: usize,
    ) -> Self {
        let mut workers: Vec<Option<Worker>> = Vec::new();
        let mut workers_status: Vec<WorkerStatus> = Vec::new();

        // split passphrase dictionary into <proc> chunks
        println!("Splitting jobs in {} workers...", proc);
        let chunk_size = (passphrases.len() + (proc - 1)) / proc;
        for (i, chunk) in passphrases.chunks(chunk_size).enumerate() {
            workers_status.push(WorkerStatus {
                total_pp: chunk.len(),
                actual_pp: 0,
                state: WorkerState::Idle,
            });

            workers.push(Some(Worker::new(
                address.clone(),
                mnemonic.clone(),
                derivation_path.clone(),
                chunk.to_vec(),
                indexes.clone(),
                i,
                progress_step,
            )));
        }

        PassphraseFinder {
            workers,
            workers_status,
            rx: None,
            found_data: None,
            start_time: None,
        }
    }

    /// Start bruteforcing
    pub fn start(&mut self) -> Result<WorkerState, CustomError> {
        self.launch()?;
        let result = self.monitor_workers()?;
        Ok(result)
    }

    /// Create several worker and start them
    fn launch(&mut self) -> Result<(), CustomError> {
        println!("Starting workers...");

        // preparing channel
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);

        self.start_time = Some(SystemTime::now());

        // Start all threads
        for w in &mut self.workers {
            // copy and give tx to the worker
            let tx = tx.clone();
            let mut worker = w.take().expect("missing worker");
            worker.tx = Some(tx);

            // start worker
            thread::spawn(move || worker.start());
        }

        // Close the spare sending part of the channel, other tx sides are not closed here
        drop(tx);

        Ok(())
    }

    /// Monitor workers until they all stopped
    fn monitor_workers(&mut self) -> Result<WorkerState, CustomError> {
        if let Some(rx) = self.rx.take() {
            // this is blocking until all tx end are not closed
            // every tx will be closed when its emitting process will stop
            for msg in rx {
                self.update_worker_status(msg);
                if let Some(msg) = &self.found_data {
                    return Ok(Match(msg.clone()));
                }
            }
            Ok(Ended)
        } else {
            Err(CustomError::NoWorkers)
        }
    }

    fn update_worker_status(&mut self, msg: WorkerMsg) {
        match &msg {
            WorkerMsg::Progress {
                id,
                actual_pp: _,
                total_pp: _,
            } => {
                self.workers_status[*id].update(msg);

                let s = self.get_global_status();
                let eta = self.estimate_eta(s.actual_pp as f64 / s.total_pp as f64);

                if let Some(eta) = eta {
                    print!("\x1B[1A\x1B[K"); // Remove last line
                    println!(
                        "{}/{}({:.2}%) passphrases checked... (ETA in {}days, {}hours, {}minutes, {}seconds...", s.actual_pp,
                        s.total_pp,
                        (s.actual_pp as f64 / s.total_pp as f64) * 100.0,
                        eta.days,
                        eta.hours,
                        eta.minutes,
                        eta.seconds
                    );
                } else {
                    println!(
                        "{}/{}({:.2}%) passphrases checked...",
                        s.actual_pp,
                        s.total_pp,
                        (s.actual_pp as f64 / s.total_pp as f64) * 100.0
                    );
                }
            }

            WorkerMsg::Found { id, found_data } => {
                self.workers_status[*id].update(msg.clone());
                self.found_data = Some(found_data.clone());
            }
            _ => {}
        }
    }

    fn get_global_status(&mut self) -> GlobalProgress {
        let mut actual = 0usize;
        let mut total = 0usize;
        for w in self.workers_status.iter() {
            actual += w.actual_pp;
            total += w.total_pp;
        }
        GlobalProgress {
            actual_pp: actual,
            total_pp: total,
        }
    }

    fn estimate_eta(&self, elapsed: f64) -> Option<Eta> {
        if let Some(start) = self.start_time {
            let duration = SystemTime::now()
                .duration_since(start)
                .unwrap()
                .as_secs_f64();
            let eta = ((1.0 / elapsed) * duration) - duration;
            let mut eta = eta as u32;

            let days = eta / 86_400;
            eta -= days * 86_400;
            let hours = eta / 3600;
            eta -= hours * 3600;
            let minutes = eta / 60;
            let seconds = eta - (minutes * 60);
            Some(Eta {
                days,
                hours,
                minutes,
                seconds,
            })
        } else {
            None
        }
    }
}

extern crate bip39;
extern crate bitcoin;
mod errors;

use crate::MatchResult::{DoNotMatch, Match};
use bip39::Mnemonic;
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpub};
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::{bip32, Address, Network};
pub use errors::CustomError;
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::mpsc;
use std::{env, fs, io, thread};
use std::time::SystemTime;

pub enum MatchResult {
    Match(String),
    DoNotMatch,
    Running,
    Iddle,
}

enum WorkerMsg {
    Progress {
        id: usize,
        actual_pp: usize,
        total_pp: usize,
    },
    Found {
        id: usize,
        passphrase: String,
    },
    Raw(String),
    Ended,
}

struct GlobalStatus {
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
    state: MatchResult,
    id: usize,
}

impl WorkerStatus {

    fn update(&mut self, msg: WorkerMsg) {
        match msg {
            WorkerMsg::Progress {
                id,
                actual_pp,
                total_pp,
            } => {
                self.actual_pp = actual_pp;
                self.total_pp = total_pp;
            }
            _ => {}
        }
    }
}

pub struct PassphraseFinder {
    workers: Option<Vec<Child>>,
    workers_status: Option<Vec<WorkerStatus>>,
    secp: Secp256k1<All>,
    address: Address,
    mnemonic: Mnemonic,
    derivation_path: DerivationPath,
    passphrases: Vec<String>,
    indexes: Vec<u32>,
    proc: usize,
    id: Option<usize>,
    rx: Option<mpsc::Receiver<String>>,
    found: bool,
    pp: Option<String>,
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
        id: Option<usize>,
    ) -> Self {
        let secp = Secp256k1::new();
        let workers: Option<Vec<Child>> = if proc == 1 {
            None
        } else {
            let w: Vec<Child> = Vec::new();
            Some(w)
        };

        let workers_status: Option<Vec<WorkerStatus>> = if proc == 1 {
            None
        } else {
            let mut ws: Vec<WorkerStatus> = Vec::new();
            for i in 0..proc {
                let status = WorkerStatus {
                    total_pp: 0,
                    actual_pp: 0,
                    state: MatchResult::Iddle,
                    id: i,
                };
                ws.push(status);
            }
            Some(ws)
        };

        let ppf = PassphraseFinder {
            workers,
            workers_status,
            secp,
            address,
            mnemonic,
            derivation_path,
            passphrases,
            indexes,
            proc,
            id,
            rx: None,
            found: false,
            pp: None,
            start_time: None,
        };

        ppf
    }

    fn mnemonic_to_xpub(&self, mnemonic: &Mnemonic, passphrase: &str) -> Result<Xpub, CustomError> {
        let xpriv = bip32::Xpriv::new_master(Network::Bitcoin, &mnemonic.to_seed(passphrase))
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
        for i in &self.indexes {
            let address = &self.get_address(&xpub, i.to_owned())?;
            if address == &self.address {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn start(&mut self) -> Result<MatchResult, CustomError> {
        if self.workers.is_none() {
            self.standalone_start()
        } else {
            self.split_and_start()?;
            Ok(self.monitor_workers()?)
        }
    }

    /// Start this process as a worker
    fn standalone_start(&self) -> Result<MatchResult, CustomError> {
        let total = self.passphrases.len();
        if let Some(id) = self.id {
            println!("[{}]0/{}", id.to_string(), total.to_string());
        } else {
            println!("0/{} passphrases checked...", total.to_string());
        };

        for (idx, p) in self.passphrases.iter().enumerate() {
            if self.check_passphrase(p)? {
                if let Some(id) = self.id {
                    println!("[{}]found:{}", id, p);
                }
                return Ok(Match(p.clone()));
            }

            if idx % 1000 == 0 {
                if let Some(id) = self.id {
                    println!(
                        "[{}]{}/{}",
                        id.to_string(),
                        idx.to_string(),
                        total.to_string()
                    );
                } else {
                    // print!("\x1B[1A\x1B[K");
                    println!(
                        "{}/{}({:.2}%) passphrases checked...",
                        idx,
                        total,
                        (idx as f64 / total as f64) * 100.0
                    );
                };
            }
        }
        if let Some(id) = self.id {
            println!(
                "[{}]{}/{}",
                id.to_string(),
                total.to_string(),
                total.to_string()
            );
        } else {
            println!("{}/{}(100%) passphrases checked...", total, total,);
        };

        Ok(DoNotMatch)
    }

    /// Create several worker and start them, the actual process will only manage this workers
    fn split_and_start(&mut self) -> Result<(), CustomError> {
        if let Some(workers) = &mut self.workers {
            let args: Vec<String> = env::args().collect();
            let binary = format!("./{}", &args[0]);
            let mut files: Vec<String> = Vec::new();

            println!("Splitting jobs in {} workers...", self.proc.to_string());

            // split passphrase dictionary into <self.proc> chunks
            let chunk_size = (self.passphrases.len() + (self.proc - 1)) / self.proc;
            for (i, chunk) in self.passphrases.chunks(chunk_size).enumerate() {
                // write each chunk in a new file
                let path = format!("worker_{}.pp", i.to_string());
                files.push(path.clone());
                let mut file =
                    File::create(&path).map_err(|_| CustomError::CannotWriteFile(path.clone()))?;

                for s in chunk {
                    writeln!(file, "{}", s)
                        .map_err(|_| CustomError::CannotWriteFile(path.clone()))?;
                }

                print!("[{}] ", i);
                io::stdout().flush().unwrap();
            }
            println!(" ");
            print!("\x1B[1A\x1B[K");
            print!("\x1B[1A\x1B[K");
            println!("Starting workers...");

            // preparing channel
            let (tx, rx) = mpsc::channel();
            self.rx = Some(rx);

            self.start_time = Some(SystemTime::now());

            // Strart all subprocesses
            for (i, f) in files.iter().enumerate() {
                let mut child = Command::new(&binary)
                    .stdout(Stdio::piped())
                    .arg("-a")
                    .arg(self.address.to_string())
                    .arg("-m")
                    .arg(self.mnemonic.to_string())
                    .arg("-i")
                    .arg(serde_json::to_string(&self.indexes).unwrap())
                    .arg("-d")
                    .arg(self.derivation_path.to_string())
                    .arg("-p")
                    .arg(f)
                    .arg("-w")
                    .arg(i.to_string())
                    .spawn()
                    .map_err(|_| CustomError::FailStartWorker)?;

                let tx = tx.clone();
                let stdout = child
                    .stdout
                    .take()
                    .expect("Child did not have a handle to stdout");

                // Thread to 'map' stdout to mpsc::channel
                thread::spawn(move || {
                    let reader = BufReader::new(stdout);
                    for line in reader.lines() {
                        let line = line.expect("Could not read line from stdout");
                        tx.send(line).expect("Could not send line to main thread");
                    }
                });

                workers.push(child);

                print!("[{}] ", i);
                io::stdout().flush().unwrap();
            }
            println!(" ");

            drop(tx); // Close the spare sending part of the channel, other tx sides are not closed here

            Ok(())
        } else {
            {
                return Ok(());
            }
        }
    }

    /// Monitor workers until they all stopped
    fn monitor_workers(&mut self) -> Result<MatchResult, CustomError> {
        if let Some(rx) = self.rx.take() {
            print!("\x1B[1A\x1B[K");

            // this is blocking until all tx end are not closed
            // every tx will be closed when its emitting process will stop
            for received in rx {
                let stop_listening = self.handle_worker_msg(received)?;
                if stop_listening || self.found {
                    break;
                }
            }

            if !&self.found {
                let s = &self.get_global_status();


                print!("\x1B[1A\x1B[K");
                println!(
                    "{}/{}({:.2}%) passphrases checked...",
                    s.total_pp,
                    s.total_pp,
                    (s.total_pp as f64 / s.total_pp as f64) * 100.0
                );
                self.cleanup()?;
                Ok(DoNotMatch)
            } else {
                self.kill_processes();
                if let Some(pp) = &self.pp {
                    self.cleanup()?;
                    Ok(Match(pp.clone()))
                } else {
                    self.cleanup()?;
                    Ok(DoNotMatch)
                }
            }

            // TODO: cleanup worker_<id>.pp files
        } else {
            Err(CustomError::NoWorkers)
        }
    }

    fn parse_msg(&self, input: &str) -> Result<WorkerMsg, CustomError> {
        let re1 = Regex::new(r"^\[(\d+)\](\d+)/(\d+)$").expect("static regex cannot fail");
        let re2 = Regex::new(r"^\[(\d+)\]found:(.+)$").expect("static regex cannot fail");
        let re3 = Regex::new(r"^\[\d+\].*$").expect("static regex cannot fail");

        if let Some(data) = re1.captures(input) {
            if &data[2] != &data[3] {
                Ok(WorkerMsg::Progress {
                    id: usize::from_str(&data[1]).map_err(|_| CustomError::CannotParseUSize)?,
                    actual_pp: usize::from_str(&data[2])
                        .map_err(|_| CustomError::CannotParseUSize)?,
                    total_pp: usize::from_str(&data[3])
                        .map_err(|_| CustomError::CannotParseUSize)?,
                })
            } else {
                Ok(WorkerMsg::Ended)
            }
        } else if let Some(data) = re2.captures(input) {
            Ok(WorkerMsg::Found {
                id: usize::from_str(&data[1]).map_err(|_| CustomError::CannotParseUSize)?,
                passphrase: data[2].to_string(),
            })
        } else if let Some(_data) = re3.captures(input) {
            println!("Raw.....................................");
            Ok(WorkerMsg::Raw(input.to_string()))
        } else {
            println!("Cannot parse worker msg input={}", input);
            Err(CustomError::CannotParseWorkerMsg)
        }
    }

    fn handle_worker_msg(&mut self, msg: String) -> Result<bool, CustomError> {
        let msg = self.parse_msg(&msg)?;
        self.update_worker_status(msg);

        // return true to stop listening subprocesses
        if self.check_workers_status().is_some() {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn update_worker_status(&mut self, msg: WorkerMsg) {
        match msg {
            WorkerMsg::Progress {
                id,
                actual_pp,
                total_pp,
            } => {
                if let Some(workers_status) = &mut self.workers_status {
                    workers_status[id].update(msg);
                }
                let s = self.get_global_status();
                let eta = self.estimate_eta(s.actual_pp as f64 / s.total_pp as f64);
                print!("\x1B[1A\x1B[K");
                if let Some(eta) = eta {
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

            WorkerMsg::Found { id, passphrase } => {
                // println!("Passphrase found '{}'", passphrase);
                self.found = true;
                self.pp = Some(passphrase);

                // TODO: write found pp into file
            }
            _ => {}
        }
    }

    fn get_global_status(&mut self) -> GlobalStatus {
        if let Some(status) = &self.workers_status {
            let mut actual = 0usize;
            let mut total = 0usize;
            for w in status.iter() {
                actual += w.actual_pp;
                total += w.total_pp;
            }
            GlobalStatus {
                actual_pp: actual,
                total_pp: total,
            }
        } else {
            GlobalStatus {
                actual_pp: 0,
                total_pp: 0,
            }
        }
    }

    fn check_workers_status(&mut self) -> Option<WorkerMsg> {
        if let Some(status) = &self.workers_status {
            for s in status.iter() {
                match &s.state {
                    Match(pp) => {
                        return Some(WorkerMsg::Found {
                            id: s.id,
                            passphrase: pp.clone(),
                        });
                    }
                    _ => {}
                }
            }
        };
        // TODO: else if all workers stopped return
        // Some(WorkerMsg::Ended)
        // else return
        None
    }

    fn kill_processes(&mut self) {
        if let Some(workers) = &mut self.workers {
            println!("Stopping all workers");
            for worker in &mut *workers {

                let _ = &worker.kill(); // Sends SIGKILL

            }
            println!("Waiting to all workers stopped...");
            for worker in workers {
                _ = worker.wait();
            }
            println!("All workers have stopped.");
        }
    }

    fn cleanup(&self) -> Result<(), CustomError>{
        if let Some(workers) = &self.workers {
            for i in 0..workers.len() {
                let path = format!("worker_{}.pp", i.to_string());
                fs::remove_file(&path).map_err(|_| CustomError::CannotRemoveFile(path))?;
            }
        }
        Ok(())
    }

    fn estimate_eta(&self, elapsed: f64) -> Option<Eta> {
        if let Some(start) = self.start_time {
            let duration =SystemTime::now()
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
            Some (
                Eta {
                    days,
                    hours,
                    minutes,
                    seconds
                }
            )
        } else {
            None
        }
    }
}

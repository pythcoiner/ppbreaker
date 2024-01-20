```
ppbreaker is a simple CLI tool for Bitcoin users who have lost their wallet's passphrase but still have their mnemonic
words and known address. It helps to recover the passphrase by trying different combinations based on the provided 
mnemonic words. The tool supports customizing the derivation path, address type, and index. Users can input mnemonic 
words directly or via a file, and specify the number of processes.

Usage: ppbreaker [OPTIONS]

Options:
-a, --address <ADDRESS>
    Address to check against, if not defined, will check content of adress.txt.
    
-d, --derivation-path <DERIVATION_PATH>
    Derivation path to use, if none of --derivation-path or --address-type defined, 'm/84h/0h/0h/0/*' will be used
    
-t, --address-type <ADDRESS_TYPE>
    Address type to use, if none of --derivation-path or --address-type defined, 'm/84h/0h/0h/0/*' will be used as derivation path
    
-m, --mnemonic <MNEMONIC>
    Mnemonic words to use, can be 12, 18, 24 words
    
-f, --mnemonic-file <MNEMONIC_FILE>
    File to retrieve the mnemonic words to use
    
-p, --passphrase-dictionary <PASSPHRASE_DICTIONARY>
    File where the passphrases are stored [default: passphrases.txt]
    
-i, --index <INDEX>
    Derivation index to check, it can be pass in several forms: '0' or '[0,1,3]' or '0..1' or '0..=1' [default: 0]
    
-k, --processes <PROCESSES>
    Number of processes to launch [default: 1]
    
-h, --help
```
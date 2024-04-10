use std::{fs, io::Write, os::unix::fs::PermissionsExt};

use anyhow::{Ok, Result};
use clap::{Args, Parser, Subcommand};
use ctap_hid_fido2::{
    fidokey::get_info::InfoOption, public_key::PublicKeyType, Cfg, FidoKeyHid, FidoKeyHidFactory,
};
use ssh_key::{
    private::{self, KeypairData},
    public, LineEnding, PrivateKey, PublicKey,
};

fn is_supported(device: &FidoKeyHid) -> Result<bool> {
    if device.enable_info_option(&InfoOption::CredMgmt)?.is_some() {
        return Ok(true);
    }

    Ok(device
        .enable_info_option(&InfoOption::CredentialMgmtPreview)?
        .is_some())
}

const SSH_SK_USER_PRESENCE_REQD: u8 = 0x01;
const SSH_SK_USER_VERIFICATION_REQD: u8 = 0x04;
const SSH_SK_FORCE_OPERATION: u8 = 0x10;
const SSH_SK_RESIDENT_KEY: u8 = 0x20;

#[derive(Parser, Debug)]
#[clap(long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Export(ExportArgs),
}

#[derive(Args, Debug)]
struct ExportArgs {
    #[arg(short = 'C', long)]
    comment: Option<String>,

    #[arg(short = 'O', long)]
    option: Vec<String>,

    #[arg(short = 'f')]
    output_keyfile: Option<String>,
}

fn keygen(args: &ExportArgs) -> Result<()> {
    let mut cfg = Cfg::init();
    cfg.enable_log = false;
    cfg.use_pre_credential_management = true;

    let device = FidoKeyHidFactory::create(&cfg)?;

    if !(is_supported(&device)?) {
        println!("This authenticator is not Supported Credential management.");
        return Ok(());
    }

    // read pin
    let pin = rpassword::prompt_password("PIN: ")?;
    println!();

    let credentials_count = device.credential_management_get_creds_metadata(Some(pin.as_str()))?;
    println!(
        "existing discoverable credentials: {}/{}",
        credentials_count.existing_resident_credentials_count,
        credentials_count.max_possible_remaining_resident_credentials_count
    );

    if credentials_count.existing_resident_credentials_count == 0 {
        println!("\nNo discoverable credentials.");
        return Ok(());
    }

    let rps = device.credential_management_enumerate_rps(Some(pin.as_str()))?;

    for rp in rps {
        let id = rp.public_key_credential_rp_entity.id;
        if !id.starts_with("ssh:") {
            continue;
        }

        println!("found ssh credential: {}", id);

        let creds = device
            .credential_management_enumerate_credentials(Some(pin.as_str()), &rp.rpid_hash)?;

        let cred = match creds.first() {
            Some(cred) => cred,
            None => {
                println!("No credentials.");
                return Ok(());
            }
        };

        let key_handle = cred.public_key_credential_descriptor.id.clone();
        let public_key = &cred.public_key;

        let mut flag = SSH_SK_USER_PRESENCE_REQD | SSH_SK_FORCE_OPERATION | SSH_SK_RESIDENT_KEY;
        for opt in args.option.iter() {
            match opt.as_str() {
                "no-touch-required" => {
                    flag &= !SSH_SK_USER_PRESENCE_REQD;
                }
                "verify-required" => {
                    flag |= SSH_SK_USER_VERIFICATION_REQD;
                }
                _ => {
                    println!("Unknown option: {}", opt);
                    return Ok(());
                }
            }
        }

        let (keydata, public_key): (KeypairData, PublicKey) = match public_key.key_type {
            PublicKeyType::Ecdsa256 => {
                let pk = public::EcdsaPublicKey::from_sec1_bytes(public_key.der.as_slice())?;
                let pk = match pk {
                    public::EcdsaPublicKey::NistP256(pk) => pk,
                    _ => {
                        println!("Unsupported key type.");
                        continue;
                    }
                };
                let pk = public::SkEcdsaSha2NistP256::new(pk, id.clone());
                let sk = private::SkEcdsaSha2NistP256::new(pk.clone(), flag, key_handle)?;

                (sk.into(), pk.into())
            }
            PublicKeyType::Ed25519 => {
                let pk = public::Ed25519PublicKey::try_from(public_key.der.as_slice())?;
                let pk = public::SkEd25519::new(pk, id.clone());
                let sk = private::SkEd25519::new(pk.clone(), flag, key_handle)?;

                (sk.into(), pk.into())
            }
            PublicKeyType::Unknown => {
                println!("Unknown key type.");
                continue;
            }
        };

        let private_key = PrivateKey::new(keydata, args.comment.clone().unwrap_or(id.clone()))?;

        let key_path = args.output_keyfile.clone().unwrap_or(format!(
            "id_ed25519_sk_rk_{}",
            id.trim_start_matches("ssh:")
        ));
        let public_key_path = format!("{}.pub", key_path);
        println!("write private key to {}", key_path);
        println!("write public key to {}", public_key_path);

        let pem = private_key.to_openssh(LineEnding::LF)?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(key_path)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(pem.as_bytes())?;

        let pk_buf = public_key.to_openssh()?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(public_key_path)?;

        file.set_permissions(fs::Permissions::from_mode(0o644))?;
        if flag & SSH_SK_USER_PRESENCE_REQD == 0 {
            file.write_all(b"no-touch-required ")?;
        }

        file.write_all(pk_buf.as_bytes())?;
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Cli::parse();

    if let Some(subcommand) = args.command {
        match subcommand {
            Commands::Export(args) => keygen(&args)?,
        }
    };

    Ok(())
}

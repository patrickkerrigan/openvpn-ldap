#[macro_use]
extern crate openvpn_plugin;

use std::collections::HashMap;
use std::ffi::CString;
use std::io::{Error, ErrorKind, Write};
use std::thread;
use std::fs::File;
use std::str::FromStr;
use openvpn_plugin::{EventResult, EventType};
use secrecy::{SecretString, ExposeSecret};
use crate::config::LdapConfig;
use crate::ldap::NetworkLdapService;
use crate::auth::Authenticator;

mod config;
mod ldap;
mod auth;

fn get_env_field<'a>(env: &'a HashMap<CString, CString>, field: &str) -> Result<&'a str, Error> {
    let key = CString::new(field)?;
    env.get(&key)
        .ok_or(Error::new(ErrorKind::Other, format!("No field '{}'", field)))?
        .to_str()
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "UTF8 error"))
}

fn get_argument(args: &Vec<CString>, num: usize) -> Result<&str, Error> {
    args.get(num)
        .ok_or(Error::new(ErrorKind::Other, format!("No argument '{}'", num)))?
        .to_str()
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "UTF8 error"))
}

fn async_auth(
    username: String,
    password: SecretString,
    mut control_file: File,
    authenticator: Authenticator
) {
    match authenticator.authenticate::<NetworkLdapService>(&username, password.expose_secret()) {
        Ok(_) => {
            println!("Authentication succeeded for {}", &username);
            let _ = control_file.write_all(b"1");
        },

        Err(e) => {
            println!("Authentication failed for {} - {}", &username, e);
            let _ = control_file.write_all(b"0");
        }
    }
}

fn openvpn_open(
    args: Vec<CString>,
    _env: HashMap<CString, CString>,
) -> Result<(Vec<EventType>, Authenticator), Error> {
    println!("Starting LDAP auth plugin");

    let config = LdapConfig::from_file(get_argument(&args, 1)?)?;
    let authenticator = Authenticator::new(config);
    let events = vec![EventType::AuthUserPassVerify];

    Ok((events, authenticator))
}

fn openvpn_close(_authenticator: Authenticator) {
    println!("Stopping LDAP auth plugin");
}

fn openvpn_event(
    event: EventType,
    _args: Vec<CString>,
    env: HashMap<CString, CString>,
    authenticator: &mut Authenticator,
) -> Result<EventResult, Error> {

    match event {
        EventType::AuthUserPassVerify => {
            let username = String::from(get_env_field(&env, "username")?);
            let password = SecretString::from_str(get_env_field(&env, "password")?)
                .expect("Secret string creation failed");

            let control_file_path = get_env_field(&env, "auth_control_file")?;
            let file = File::create(control_file_path)?;

            let authenticator = &*authenticator;
            let auth_clone = authenticator.clone();

            // OpenVPN is single threaded and will block by default until auth is complete. Spin up
            // a new thread to talk to the LDAP server to avoid blocking traffic during auth
            let _ = thread::Builder::new().name("LDAP auth thread".into()).spawn(move || {
                async_auth(username, password, file, auth_clone)
            });

            Ok(EventResult::Deferred)
        },

        _ => Ok(EventResult::Failure)
    }
}

openvpn_plugin!(openvpn_open, openvpn_close, openvpn_event, Authenticator);

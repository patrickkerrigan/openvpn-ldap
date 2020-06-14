use std::ffi::c_void;
use std::boxed;
use libc::timeval;
use openldap::{LDAPResponse, RustLDAP, codes, LDAPOptionValue};
use openldap::errors::LDAPError;
use openldap::codes::results::*;

// The OpenLDAP Rust bindings don't support setting the network timeout for some reason,
// so implement that here
struct Timeout(timeval);
static LDAP_OPT_NETWORK_TIMEOUT: i32 = 0x5005;

impl LDAPOptionValue for Timeout {
    fn as_cvoid_ptr(&self) -> *const c_void {
        let mem = boxed::Box::new(self.0);
        boxed::Box::into_raw(mem) as *const c_void
    }
}

pub trait LdapService {
    fn new(uri: &str) -> Self;
    fn bind(&self, dn: &str, password: &str) -> bool;
    fn search(&self, base_dn: &str, scope: i32, filter: &str) -> Result<LDAPResponse, LDAPError>;
}

pub struct NetworkLdapService {
    ldap: RustLDAP
}

impl LdapService for NetworkLdapService {
    fn new(uri: &str) -> Self {
        let timeout = Timeout(timeval {
            tv_sec: 5,
            tv_usec: 0
        });

        let ldap = RustLDAP::new(uri).expect("Unable to initialise LDAP");
        ldap.set_option(codes::options::LDAP_OPT_PROTOCOL_VERSION, &codes::versions::LDAP_VERSION3);
        ldap.set_option(codes::options::LDAP_OPT_REFERRALS, &0);
        ldap.set_option(LDAP_OPT_NETWORK_TIMEOUT, &timeout);

        NetworkLdapService { ldap }
    }

    fn bind(&self, dn: &str, password: &str) -> bool {
        let bind = self.ldap.simple_bind(dn, password);
        bind.unwrap_or(-1) == LDAP_SUCCESS
    }

    fn search(&self, base_dn: &str, scope: i32, filter: &str) -> Result<LDAPResponse, LDAPError> {
        let mut timeout = timeval {
            tv_sec: 5,
            tv_usec: 0
        };

        self.ldap.ldap_search(
            base_dn,
            scope,
            Some(filter),
            None,
            false,
            None,
            None,
            &mut timeout,
            -1,
        )
    }
}

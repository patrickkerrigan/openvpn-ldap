use openldap::codes::scopes::*;
use crate::config::LdapConfig;
use crate::ldap::LdapService;

pub type AuthResult<T> = Result<T, &'static str>;

#[derive(Clone)]
pub struct Authenticator {
    ldap_config: LdapConfig
}

impl Authenticator {
    pub fn new(ldap_config: LdapConfig) -> Self {
        Authenticator { ldap_config }
    }

    pub fn authenticate<T>(&self, username: &str, password: &str) -> AuthResult<()>
        where T : LdapService
    {
        let ldap = self.bind_as_service::<T>()?;
        let user_dn = self.resolve_user_dn(&ldap, username)?;
        let _ = self.verify_password::<T>(&user_dn, password)?;
        self.check_member_of_required_group(&ldap, &user_dn)
    }

    fn bind_as_service<T>(&self) -> AuthResult<T>
        where T : LdapService
    {
        let ldap = T::new(self.ldap_config.get_uri());

        let bind = ldap.bind(
            self.ldap_config.get_bind_dn(),
            self.ldap_config.get_bind_password()
        );

        if !bind {
            return Err("Unable to bind as service");
        }

        Ok(ldap)
    }

    fn resolve_user_dn<T>(&self, ldap: &T, username: &str) -> AuthResult<String>
        where T : LdapService
    {
        let user_search_filter = format!(
            "({}={})",
            self.ldap_config.get_username_property(),
            Authenticator::escape_search(username)
        );

        let users = ldap.search(
            self.ldap_config.get_user_base_dn(),
            LDAP_SCOPE_SUBTREE,
            &user_search_filter
        ).map_err(|_| "Error looking up user")?;
        let user = users.last().ok_or("User not found")?;
        user["dn"].first().ok_or("User has no dn(!)").map(String::from)
    }

    fn verify_password<T>(&self, user_dn: &str, password: &str) -> AuthResult<()>
        where T : LdapService
    {
        let auth_ldap = T::new(self.ldap_config.get_uri());
        let auth_bind = auth_ldap.bind(user_dn, password);

        if !auth_bind {
            return Err("Invalid password");
        }

        Ok(())
    }

    fn check_member_of_required_group<T>(&self, ldap: &T, user_dn: &str) -> AuthResult<()>
        where T : LdapService
    {
        match (self.ldap_config.get_group_base_dn(), self.ldap_config.get_group_cn()) {
            (Some(group_base_dn), Some(group_cn)) => {
                let group_search_filter = format!("(cn={})", group_cn);
                let membership_search_filter = format!("(member={})", user_dn);

                let groups = ldap.search(
                    group_base_dn,
                    LDAP_SCOPE_SUBTREE,
                    &group_search_filter
                ).map_err(|_| "Error looking up group")?;
                let group = groups.last().ok_or("Group not found")?;
                let group_dn = group["dn"].first().ok_or("Group has no dn(!)").map(String::from)?;

                let membership = ldap.search(
                    &group_dn,
                    LDAP_SCOPE_BASEOBJECT,
                    &membership_search_filter
                ).map_err(|_| "Error checking group membership")?;

                match membership.is_empty() {
                    true => Err("User not a member of required group"),
                    false => Ok(())
                }
            },

            _ => Ok(())
        }

    }

    fn escape_search(input: &str) -> String {
        input
            .replace("\\", "\\5c")
            .replace('(', "\\28")
            .replace(')', "\\29")
            .replace('*', "\\2a")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openldap::LDAPResponse;
    use openldap::errors::LDAPError;
    use std::collections::HashMap;
    use secrecy::SecretString;
    use std::str::FromStr;

    struct MockLdapService {}

    impl LdapService for MockLdapService {
        fn new(_uri: &str) -> Self {
            MockLdapService {}
        }

        fn bind(&self, dn: &str, password: &str) -> bool {
            match (dn, password) {
                ("valid_service_dn", "valid_service_pw") => true,
                ("valid_user_dn", "valid_user_pw") => true,
                _ => false
            }
        }

        fn search(&self, base_dn: &str, scope: i32, filter: &str) -> Result<LDAPResponse, LDAPError> {
            match (base_dn, scope, filter) {
                ("users", 0x0002, "(uid=valid_username)") => {
                    let mut user: HashMap<String, Vec<String>> = HashMap::new();
                    user.insert("dn".into(), vec!["valid_user_dn".into()]);
                    let result: LDAPResponse = vec![user];
                    Ok(result)
                },

                ("users", 0x0002, "(uid=invalid_username)") => {
                    let result: LDAPResponse = vec![];
                    Ok(result)
                },

                ("users", 0x0002, "(uid=error_username)") => {
                    Err(LDAPError::NativeError("".into()))
                },

                ("groups", 0x0002, "(cn=valid_group)") => {
                    let mut group: HashMap<String, Vec<String>> = HashMap::new();
                    group.insert("dn".into(), vec!["valid_group_dn".into()]);
                    let result: LDAPResponse = vec![group];
                    Ok(result)
                },

                ("groups", 0x0002, "(cn=invalid_group)") => {
                    let result: LDAPResponse = vec![];
                    Ok(result)
                },

                ("groups", 0x0002, "(cn=error_group)") => {
                    Err(LDAPError::NativeError("".into()))
                },

                ("groups", 0x0002, "(cn=empty_group)") => {
                    let mut group: HashMap<String, Vec<String>> = HashMap::new();
                    group.insert("dn".into(), vec!["empty_group_dn".into()]);
                    let result: LDAPResponse = vec![group];
                    Ok(result)
                },

                ("groups", 0x0002, "(cn=invalid_membership_group)") => {
                    let mut group: HashMap<String, Vec<String>> = HashMap::new();
                    group.insert("dn".into(), vec!["invalid_membership_group_dn".into()]);
                    let result: LDAPResponse = vec![group];
                    Ok(result)
                },

                ("valid_group_dn", 0x0000, "(member=valid_user_dn)") => {
                    let mut group: HashMap<String, Vec<String>> = HashMap::new();
                    group.insert("dn".into(), vec!["valid_group_dn".into()]);
                    let result: LDAPResponse = vec![group];
                    Ok(result)
                },

                ("empty_group_dn", 0x0000, "(member=valid_user_dn)") => {
                    Ok(vec![])
                },

                ("invalid_membership_group_dn", 0x0000, "(member=valid_user_dn)") => {
                    Err(LDAPError::NativeError("".into()))
                },

                _ => Err(LDAPError::NativeError("".into()))
            }
        }
    }

    #[test]
    fn test_bind_failure_returns_false() {
        let config = LdapConfig::new(
            "".into(),
            "invalid_service_dn".into(),
            SecretString::from_str("invalid_service_pw").unwrap(),
            "users".into(),
            "uid".into(),
            Some("groups".into()),
            Some("valid_group".into())
        );

        let authenticator = Authenticator::new(config);

        assert_eq!(authenticator.authenticate::<MockLdapService>("valid_username", "valid_user_pw").is_ok(), false);
    }

    #[test]
    fn test_invalid_user_returns_false() {
        let config = LdapConfig::new(
            "".into(),
            "valid_service_dn".into(),
            SecretString::from_str("valid_service_pw").unwrap(),
            "users".into(),
            "uid".into(),
            Some("groups".into()),
            Some("valid_group".into())
        );

        let authenticator = Authenticator::new(config);

        assert_eq!(authenticator.authenticate::<MockLdapService>("invalid_username", "valid_user_pw").is_ok(), false);
    }

    #[test]
    fn test_user_lookup_error_returns_false() {
        let config = LdapConfig::new(
            "".into(),
            "valid_service_dn".into(),
            SecretString::from_str("valid_service_pw").unwrap(),
            "users".into(),
            "uid".into(),
            Some("groups".into()),
            Some("valid_group".into())
        );

        let authenticator = Authenticator::new(config);

        assert_eq!(authenticator.authenticate::<MockLdapService>("error_username", "valid_user_pw").is_ok(), false);
    }

    #[test]
    fn test_invalid_password_returns_false() {
        let config = LdapConfig::new(
            "".into(),
            "valid_service_dn".into(),
            SecretString::from_str("valid_service_pw").unwrap(),
            "users".into(),
            "uid".into(),
            Some("groups".into()),
            Some("valid_group".into())
        );

        let authenticator = Authenticator::new(config);

        assert_eq!(authenticator.authenticate::<MockLdapService>("valid_username", "invalid_user_pw").is_ok(), false);
    }

    #[test]
    fn test_invalid_group_returns_false() {
        let config = LdapConfig::new(
            "".into(),
            "valid_service_dn".into(),
            SecretString::from_str("valid_service_pw").unwrap(),
            "users".into(),
            "uid".into(),
            Some("groups".into()),
            Some("invalid_group".into())
        );

        let authenticator = Authenticator::new(config);

        assert_eq!(authenticator.authenticate::<MockLdapService>("valid_username", "valid_user_pw").is_ok(), false);
    }

    #[test]
    fn test_group_lookup_error_returns_false() {
        let config = LdapConfig::new(
            "".into(),
            "valid_service_dn".into(),
            SecretString::from_str("valid_service_pw").unwrap(),
            "users".into(),
            "uid".into(),
            Some("groups".into()),
            Some("error_group".into())
        );

        let authenticator = Authenticator::new(config);

        assert_eq!(authenticator.authenticate::<MockLdapService>("valid_username", "valid_user_pw").is_ok(), false);
    }

    #[test]
    fn test_not_in_group_returns_false() {
        let config = LdapConfig::new(
            "".into(),
            "valid_service_dn".into(),
            SecretString::from_str("valid_service_pw").unwrap(),
            "users".into(),
            "uid".into(),
            Some("groups".into()),
            Some("empty_group".into())
        );

        let authenticator = Authenticator::new(config);

        assert_eq!(authenticator.authenticate::<MockLdapService>("valid_username", "valid_user_pw").is_ok(), false);
    }

    #[test]
    fn test_membership_lookup_error_returns_false() {
        let config = LdapConfig::new(
            "".into(),
            "valid_service_dn".into(),
            SecretString::from_str("valid_service_pw").unwrap(),
            "users".into(),
            "uid".into(),
            Some("groups".into()),
            Some("invalid_membership_group".into())
        );

        let authenticator = Authenticator::new(config);

        assert_eq!(authenticator.authenticate::<MockLdapService>("valid_username", "valid_user_pw").is_ok(), false);
    }

    #[test]
    fn test_auth_success_with_group_returns_true() {
        let config = LdapConfig::new(
            "".into(),
            "valid_service_dn".into(),
            SecretString::from_str("valid_service_pw").unwrap(),
            "users".into(),
            "uid".into(),
            Some("groups".into()),
            Some("valid_group".into())
        );

        let authenticator = Authenticator::new(config);

        assert_eq!(authenticator.authenticate::<MockLdapService>("valid_username", "valid_user_pw").is_ok(), true);
    }

    #[test]
    fn test_auth_success_without_group_config_returns_true() {
        let config = LdapConfig::new(
            "".into(),
            "valid_service_dn".into(),
            SecretString::from_str("valid_service_pw").unwrap(),
            "users".into(),
            "uid".into(),
            Some("groups".into()),
            None
        );

        let authenticator = Authenticator::new(config);

        assert_eq!(authenticator.authenticate::<MockLdapService>("valid_username", "valid_user_pw").is_ok(), true);
    }

    #[test]
    fn test_auth_success_without_group_base_config_returns_true() {
        let config = LdapConfig::new(
            "".into(),
            "valid_service_dn".into(),
            SecretString::from_str("valid_service_pw").unwrap(),
            "users".into(),
            "uid".into(),
            None,
            Some("empty_group".into())
        );

        let authenticator = Authenticator::new(config);

        assert_eq!(authenticator.authenticate::<MockLdapService>("valid_username", "valid_user_pw").is_ok(), true);
    }

    #[test]
    fn test_escape() {
        let input = "()\\*test";
        let output = Authenticator::escape_search(input);

        assert_eq!(output, "\\28\\29\\5c\\2atest");
    }
}

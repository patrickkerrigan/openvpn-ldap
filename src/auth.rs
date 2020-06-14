use openldap::codes::scopes::*;
use crate::config::LdapConfig;
use crate::ldap::LdapService;

#[derive(Clone)]
pub struct Authenticator {
    ldap_config: LdapConfig
}

impl Authenticator {
    pub fn new(ldap_config: LdapConfig) -> Self {
        Authenticator { ldap_config }
    }

    pub fn authenticate<T>(&self, username: &str, password: &str) -> bool
        where T : LdapService
    {
        let ldap = T::new(self.ldap_config.get_uri());

        let bind = ldap.bind(
            self.ldap_config.get_bind_dn(),
            self.ldap_config.get_bind_password()
        );

        if !bind {
            println!("Unable to bind as service");
            return false;
        }

        let user_search_filter = format!(
            "({}={})",
            self.ldap_config.get_username_property(),
            Authenticator::escape_search(username)
        );

        let user_list = ldap.search(
            self.ldap_config.get_user_base_dn(),
            LDAP_SCOPE_SUBTREE,
            &user_search_filter
        );

        if user_list.is_err() {
            println!("User not found");
            return false;
        }

        let user_list = user_list.unwrap();
        let user = user_list.last();


        if user.is_none() {
            println!("User not found");
            return false;
        }

        let user = user.unwrap();


        let auth_ldap = T::new(self.ldap_config.get_uri());
        let auth_bind = auth_ldap.bind(user["dn"].first().unwrap(), password);

        if !auth_bind {
            println!("Invalid password");
            return false;
        }

        let group_search_filter = format!("(cn={})", self.ldap_config.get_group_cn());

        let group_list = ldap.search(
            self.ldap_config.get_group_base_dn(),
            LDAP_SCOPE_SUBTREE,
            &group_search_filter
        );

        if group_list.is_err() {
            println!("Group not found");
            return false;
        }

        let group_list = group_list.unwrap();
        let group = group_list.last();


        if group.is_none() {
            println!("Group not found");
            return false;
        }

        let group = group.unwrap();

        let member_list = ldap.search(
            group["dn"].first().unwrap(),
            LDAP_SCOPE_BASEOBJECT,
            &format!("(member={})", user["dn"].first().unwrap())
        );

        if member_list.is_err() || member_list.unwrap().is_empty() {
            println!("User not a member of required group");
            return false;
        }

        true
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

                ("groups", 0x0002, "(cn=valid_group)") => {
                    let mut group: HashMap<String, Vec<String>> = HashMap::new();
                    group.insert("dn".into(), vec!["valid_group_dn".into()]);
                    let result: LDAPResponse = vec![group];
                    Ok(result)
                },

                ("groups", 0x0002, "(cn=empty_group)") => {
                    let mut group: HashMap<String, Vec<String>> = HashMap::new();
                    group.insert("dn".into(), vec!["empty_group_dn".into()]);
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
            "groups".into(),
            "valid_group".into()
        );

        let authenticator = Authenticator::new(config);

        assert_eq!(authenticator.authenticate::<MockLdapService>("valid_username", "valid_user_pw"), false);
    }

    #[test]
    fn test_invalid_user_returns_false() {
        let config = LdapConfig::new(
            "".into(),
            "valid_service_dn".into(),
            SecretString::from_str("valid_service_pw").unwrap(),
            "users".into(),
            "uid".into(),
            "groups".into(),
            "valid_group".into()
        );

        let authenticator = Authenticator::new(config);

        assert_eq!(authenticator.authenticate::<MockLdapService>("invalid_username", "valid_user_pw"), false);
    }

    #[test]
    fn test_invalid_password_returns_false() {
        let config = LdapConfig::new(
            "".into(),
            "valid_service_dn".into(),
            SecretString::from_str("valid_service_pw").unwrap(),
            "users".into(),
            "uid".into(),
            "groups".into(),
            "valid_group".into()
        );

        let authenticator = Authenticator::new(config);

        assert_eq!(authenticator.authenticate::<MockLdapService>("valid_username", "invalid_user_pw"), false);
    }

    #[test]
    fn test_invalid_group_returns_false() {
        let config = LdapConfig::new(
            "".into(),
            "valid_service_dn".into(),
            SecretString::from_str("valid_service_pw").unwrap(),
            "users".into(),
            "uid".into(),
            "groups".into(),
            "invalid_group".into()
        );

        let authenticator = Authenticator::new(config);

        assert_eq!(authenticator.authenticate::<MockLdapService>("valid_username", "valid_user_pw"), false);
    }

    #[test]
    fn test_not_in_group_returns_false() {
        let config = LdapConfig::new(
            "".into(),
            "valid_service_dn".into(),
            SecretString::from_str("valid_service_pw").unwrap(),
            "users".into(),
            "uid".into(),
            "groups".into(),
            "empty_group".into()
        );

        let authenticator = Authenticator::new(config);

        assert_eq!(authenticator.authenticate::<MockLdapService>("valid_username", "valid_user_pw"), false);
    }

    #[test]
    fn test_auth_success_returns_true() {
        let config = LdapConfig::new(
            "".into(),
            "valid_service_dn".into(),
            SecretString::from_str("valid_service_pw").unwrap(),
            "users".into(),
            "uid".into(),
            "groups".into(),
            "valid_group".into()
        );

        let authenticator = Authenticator::new(config);

        assert_eq!(authenticator.authenticate::<MockLdapService>("valid_username", "valid_user_pw"), true);
    }

    #[test]
    fn test_escape() {
        let input = "()\\*test";
        let output = Authenticator::escape_search(input);

        assert_eq!(output, "\\28\\29\\5c\\2atest");
    }
}

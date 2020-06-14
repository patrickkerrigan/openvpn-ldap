use std::fs::read_to_string;
use std::io::{Error, ErrorKind};
use std::collections::HashMap;
use std::str::FromStr;
use secrecy::{SecretString, ExposeSecret};

#[derive(Clone, Debug)]
pub struct LdapConfig {
    uri: String,
    bind_dn: String,
    bind_password: SecretString,
    user_base_dn: String,
    username_property: String,
    group_base_dn: String,
    group_cn: String
}

impl LdapConfig {
    pub fn new(
        uri: String,
        bind_dn: String,
        bind_password: SecretString,
        user_base_dn: String,
        username_property: String,
        group_base_dn: String,
        group_cn: String
    ) -> Self {
        LdapConfig {
            uri,
            bind_dn,
            bind_password,
            user_base_dn,
            username_property,
            group_base_dn,
            group_cn
        }
    }

    pub fn from_file(filename: &str) -> Result<Self, Error> {
        let raw_config = read_to_string(filename)?;
        let config_map = parse_config_file(&raw_config);

        Ok(LdapConfig::new(
            get_config_value(&config_map, "uri")?.into(),
            get_config_value(&config_map, "bind-dn")?.into(),
            SecretString::from_str(get_config_value(&config_map, "bind-password")?)
                .expect("Secret string failed"),
            get_config_value(&config_map, "user-base-dn")?.into(),
            get_config_value(&config_map, "username-property")?.into(),
            get_config_value(&config_map, "group-base-dn")?.into(),
            get_config_value(&config_map, "group-cn")?.into()
        ))
    }

    pub fn get_uri(&self) -> &str {
        &self.uri
    }

    pub fn get_bind_dn(&self) -> &str {
        &self.bind_dn
    }

    pub fn get_bind_password(&self) -> &str {
        self.bind_password.expose_secret()
    }

    pub fn get_user_base_dn(&self) -> &str {
        &self.user_base_dn
    }

    pub fn get_username_property(&self) -> &str {
        &self.username_property
    }

    pub fn get_group_base_dn(&self) -> &str {
        &self.group_base_dn
    }

    pub fn get_group_cn(&self) -> &str {
        &self.group_cn
    }
}

fn parse_config_file(raw_file: &str) -> HashMap<String, String> {
    let config_lines = raw_file.trim().lines();
    config_lines.filter_map(|line| {
            let mut parts = line.trim().splitn(2, ' ');
            Some((parts.next()?.into(), parts.next()?.into()))
        })
        .collect()
}

fn get_config_value<'a>(config_map: &'a HashMap<String, String>, key: &str) -> Result<&'a String, Error> {
    config_map.get(key)
        .ok_or(Error::new(ErrorKind::Other, format!("Missing config option '{}'", key)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parsing() {
        let raw_data = r###"
        test-option-1 test-value-1

        test-option-2 test-value-2
        test-option-3 test-value-3 with spaces
        "###;

        let mut expected: HashMap<String, String> = HashMap::new();
        expected.insert(String::from("test-option-1"), String::from("test-value-1"));
        expected.insert(String::from("test-option-2"), String::from("test-value-2"));
        expected.insert(String::from("test-option-3"), String::from("test-value-3 with spaces"));

        let output = parse_config_file(raw_data);

        assert_eq!(expected, output);
    }
}

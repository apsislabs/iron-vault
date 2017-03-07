use std::collections::HashMap;
use uuid::Uuid;
use serde_json;

#[derive(Serialize, Deserialize, Debug)]
/// Record is an entry in the password database. The `kind` attribute will specify what types of
/// entries exist in the `entries` map.
///
/// Every Record has a randomly generated uuid as its id (stored in, surprisingly, the `uuid` field),
/// and a user presentable `name` field. Since `uuid` can disambiguate any collisions `name` is not
/// required to be unique. Our recommendation is to treat `name` as if it were a path (using a `/`
/// character as a separator of "folders" (similar to the way S3 object keys are treated).
///
/// Each Record has an `entries` table where the relevant fields and any metadata are stored. Each
/// PasswordKind defines a different set of fields that are expected to be present in the `entries`
/// table. For example a `RecordKind::Login` expects a `username` and `password` values to be set.
/// However, as a user is not _required_ to fill out any of these fields, all code should be able to
/// handle some of these expected fields to be missing from the entries table.
#[derive(Clone)]
pub struct Record {
    pub uuid: String,
    pub name: String,
    pub kind: RecordKind,
    // TODO: UUIDSTRING
    pub entries: HashMap<String, String>,
}

impl Record {
    /// Create a new Record using `RecordKind::Login`.
    ///
    /// # Examples
    /// ```rust
    /// use vault_core::record::Record;
    /// let record = Record::new_login("My Bank Account".to_string(), "myemail@example.com".to_string(), "password1".to_string());
    /// assert_eq!(record.entries.get(&"username".to_string()), Some(&"myemail@example.com".to_string()));
    /// assert_eq!(record.entries.get(&"password".to_string()), Some(&"password1".to_string()));
    /// ```
    pub fn new_login(name:String, username:String, password:String) -> Record {
        let mut entries_map = HashMap::new();
        entries_map.insert("username".to_string(), username);
        entries_map.insert("password".to_string(), password);

        Record {
            uuid: create_uuid(),
            name: name,
            kind: RecordKind::Login,
            entries: entries_map
        }
    }

    pub fn username(&self) -> Option<&String> {
        return self.metadata(&"username".to_string());
    }

    pub fn update_username(&mut self, username: String) -> Option<String> {
        return self.update_metadata("username".to_string(), username);
    }

    pub fn password(&self) -> Option<&String> {
        return self.metadata(&"password".to_string());
    }

    pub fn update_password(&mut self, password: String) -> Option<String> {
        return self.update_metadata("password".to_string(), password);
    }

    pub fn update_metadata(&mut self, meta_key: String, meta_value: String) -> Option<String> {
        return self.entries.insert(meta_key, meta_value);
    }

    pub fn metadata(&self, meta_key: &String) -> Option<&String> {
        return self.entries.get(meta_key);
    }

    /// Serialize this Record to json
    pub fn to_json(&self) -> serde_json::Result<String> {
        return serde_json::to_string(self);
    }

    /// Deserialize this record from previously serialized JSON
    pub fn from_json(json: String) -> serde_json::Result<Record> {
        return serde_json::from_str(&json);
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum RecordKind {
    Login
}

fn create_uuid() -> String {
    return Uuid::new_v4().to_string();
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::Value;

    describe! new_login {
        it "should instantiate with the correct settings" {
            let record = Record::new_login("My Bank Account".to_string(), "myemail@example.com".to_string(), "password1".to_string());
            assert_eq!(record.name, "My Bank Account");
            assert_eq!(record.entries.get(&"username".to_string()), Some(&"myemail@example.com".to_string()));
            assert_eq!(record.entries.get(&"password".to_string()), Some(&"password1".to_string()));
        }

        it "should generate unique uuids" {
            let record_a = Record::new_login("My Bank Account".to_string(), "myemail@example.com".to_string(), "password1".to_string());
            let record_b = Record::new_login("My Bank Account".to_string(), "myemail@example.com".to_string(), "password1".to_string());

            assert!(record_a.uuid != record_b.uuid);
            assert!(record_a.name == record_b.name);
        }
    }

    describe! serialization {
        it "should serialize and deserialize into equivalent record" {
            let record_a = Record::new_login("My Bank Account".to_string(), "myemail@example.com".to_string(), "password1".to_string());
            let json = record_a.to_json().unwrap();
            let record_b = Record::from_json(json).unwrap();

            assert_eq!(record_a.uuid, record_b.uuid);
            assert_eq!(record_a.name, record_b.name);
            assert_eq!(record_a.kind, record_b.kind);
        }

        it "should serialize to known json" {
            let record_a = Record::new_login("My Bank Account".to_string(), "myemail@example.com".to_string(), "password1".to_string());
            let json = record_a.to_json().unwrap();
            let json: Value = serde_json::from_str(&json).unwrap();

            assert_eq!("My Bank Account", json["name"]);
            assert_eq!("Login", json["kind"]);
            assert_eq!("myemail@example.com", json["entries"]["username"]);
            assert_eq!("password1", json["entries"]["password"]);
        }

        it "should deserialize to known json" {
            let json = "{\"uuid\":\"60f1e42d-5eec-47cd-9377-fda6af2be692\",\"name\":\"My Bank Account\",\"kind\":\"Login\",\"entries\":{\"username\":\"myemail@example.com\",\"password\":\"password1\"}}".to_string();

            let record = Record::from_json(json).unwrap();

            assert_eq!("60f1e42d-5eec-47cd-9377-fda6af2be692", record.uuid);
            assert_eq!("My Bank Account", record.name);
            assert_eq!(RecordKind::Login, record.kind);
        }
    }
}

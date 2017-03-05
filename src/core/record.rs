use std::collections::HashMap;
use serde_json;

#[derive(Serialize, Deserialize, Debug)]
pub struct Record {
    uuid: String,
    name: String,
    kind: RecordKind,
    entries: HashMap<String, String>,
}

impl Record {
    pub fn new_password(name:String, username:String, password:String) -> Record {
        let mut entries_map = HashMap::new();
        entries_map.insert("username".to_string(), username);
        entries_map.insert("password".to_string(), password);

        Record {
            uuid: "1234".to_string(),
            name: name,
            kind: RecordKind::Password,
            entries: entries_map
        }
    }

    pub fn to_json(&self) -> String {
        return serde_json::to_string(self).expect("It worked");
    }

    pub fn from_json(json: String) -> Record {
        return serde_json::from_str(&json).unwrap();
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum RecordKind {
    Password
}

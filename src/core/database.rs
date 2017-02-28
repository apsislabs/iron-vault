use std::io::prelude::*;
use std::fs::File;
use std::path::PathBuf;
use std::fs::create_dir_all;
use std::env;

static ENVIRONMENT_KEY: &'static str = "IRONVAULT_DATABASE";
static DEFAULT_DATABASE_PATH: &'static str = "/.ironvault/database";

pub fn read_database(buf: &mut String) {
    let db_path = resolve_database_path();
    let mut f = File::open(db_path).expect("Failed to open the database file");
    f.read_to_string(buf).expect("Failed to read the database file into the provided string buffer");
}

pub fn write_database(buf: &[u8]) {
    let db_path = resolve_database_path();
    let mut f = File::create(db_path).expect("Failed to open the database file");
    f.write_all(buf).expect("Failed to write the provided string buffer into the database file");
}

fn determine_database_path() -> String {
    // Database Path Resolution
    // 1 - Not Implemented - Explicit Override
    // 2 - Environment Variable
    // 3 - Hardcoded Location

    // TODO: Explicit Override

    // Fetch Environment Variable
    let environment_result = env::var(ENVIRONMENT_KEY);
    if environment_result.is_ok() {
        return environment_result.unwrap();
    }

    // Hardcoded Location
    return format!("{}{}", env::home_dir().expect("Failed to find the home directory").display(), DEFAULT_DATABASE_PATH);
}

fn resolve_database_path() -> PathBuf {
    let path = determine_database_path();

    let path = PathBuf::from(&path);

    match path.parent() {
        Some(parent) => create_dir_all(parent).expect("Failed to create the directory for the database"),
        _ => panic!("The path didn't have a parent attribute.")
    }

    return path;
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fs::remove_dir_all;
    use std::path::Path;

    #[test]
    fn determine_database_path_with_environment_variable() {
        test_cleanup(&|| {
            env::set_var(ENVIRONMENT_KEY, "~/test_tmp/ironvault");
            assert_eq!(determine_database_path(), "~/test_tmp/ironvault");
        });
    }

    #[test]
    fn determine_database_path_with_default_directory() {
        test_cleanup(&|| {
            assert!(determine_database_path().ends_with("/.ironvault/database"));
        });
    }

    #[test]
    fn resolve_database_path_creates_a_directory() {
        test_cleanup(&|| {
            env::set_var(ENVIRONMENT_KEY, "test_dir/something/ironvault");

            assert!( !Path::new("test_dir").is_dir() );
            assert!( !Path::new("test_dir/something").is_dir() );
            assert!( !Path::new("test_dir/something/ironvault").is_dir() );

            let db_path = resolve_database_path();
            println!("{}", db_path.display());

            assert!( Path::new("test_dir").is_dir() );
            assert!( Path::new("test_dir/something").is_dir() );
            assert!( !Path::new("test_dir/something/ironvault").is_dir() );
        });
    }

    fn test_cleanup(tests_fn: &Fn()) {
        perform_cleanup();
        tests_fn();
        perform_cleanup();
    }

    fn perform_cleanup() {
        remove_test_dir();
        env::remove_var(ENVIRONMENT_KEY);
    }

    fn remove_test_dir() {
        remove_dir_all("test_dir").unwrap_or(())
    }
}

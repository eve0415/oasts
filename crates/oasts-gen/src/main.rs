mod schema;
mod typescript;

use std::fs;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let schema = schema::config_schema();

    let schema_dir = Path::new("schemas");
    if !schema_dir.exists()
        && let Err(err) = fs::create_dir(schema_dir)
    {
        eprintln!("failed to create schemas directory: {err}");
        return ExitCode::FAILURE;
    }

    let json = match serde_json::to_string_pretty(&schema) {
        Ok(json) => json,
        Err(err) => {
            eprintln!("failed to serialize schema: {err}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(err) = fs::write("schemas/config-v1.json", format!("{json}\n")) {
        eprintln!("failed to write schemas/config-v1.json: {err}");
        return ExitCode::FAILURE;
    }

    let ts = match typescript::emit_config_ts(&schema) {
        Ok(ts) => ts,
        Err(err) => {
            eprintln!("failed to generate TypeScript: {err}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(err) = fs::write("packages/oasts/config.ts", &ts) {
        eprintln!("failed to write packages/oasts/config.ts: {err}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

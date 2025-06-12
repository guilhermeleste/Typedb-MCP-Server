use hvac::Client;
use std::env;
use std::fs;
use std::io::Write;

fn main() -> anyhow::Result<()> {
    let vault_addr = env::var("VAULT_ADDR")?;
    let role_id = env::var("MCP_SERVER_ROLE_ID")?;
    let secret_id = env::var("MCP_SERVER_SECRET_ID")?;

    let client = Client::new(&vault_addr)?;
    let auth_response = client.auth_approle(&role_id, &secret_id)?;
    client.set_token(&auth_response.auth.client_token);

    let cert_response = client.write("pki/issue/mcp-server", r#"{ "common_name": "localhost" }"#.into())?;
    let cert_data = cert_response["data"].as_object().unwrap();
    fs::write("/tmp/mcp_server.crt", cert_data["certificate"].as_str().unwrap())?;
    fs::write("/tmp/mcp_server.key", cert_data["private_key"].as_str().unwrap())?;

    let oidc_config_resp = client.read("ecosystem/data/config/mcp-server")?;
    let oidc_config = oidc_config_resp["data"]["data"].as_object().unwrap();
    let jwks_uri = oidc_config["jwks_uri"].as_str().unwrap();
    let issuer = oidc_config["issuer"].as_str().unwrap();

    let ca_resp = client.read("pki/ca/pem")?;
    // Ensure the 'data' field and 'certificate' sub-field exist before accessing them
    let ca_cert_data = ca_resp.get("data").and_then(|data| data.get("certificate")).and_then(|cert| cert.as_str()).ok_or_else(|| anyhow::anyhow!("Certificate data not found in CA response"))?;
    fs::write("/tmp/typedb_ca.pem", ca_cert_data)?;

    let mut env_file = fs::File::create("/tmp/vault_exports.env")?;
    writeln!(env_file, "export MCP_SERVER__TLS_ENABLED=true")?;
    writeln!(env_file, "export MCP_SERVER__TLS_CERT_PATH=/tmp/mcp_server.crt")?;
    writeln!(env_file, "export MCP_SERVER__TLS_KEY_PATH=/tmp/mcp_server.key")?;
    writeln!(env_file, "export MCP_AUTH__OAUTH_ENABLED=true")?;
    writeln!(env_file, "export MCP_AUTH__OAUTH_JWKS_URI='{}'", jwks_uri)?;
    writeln!(env_file, "export MCP_AUTH__OAUTH_ISSUER='{}'", issuer)?;
    writeln!(env_file, "export MCP_TYPEDB__TLS_ENABLED=true")?;
    writeln!(env_file, "export MCP_TYPEDB__TLS_CA_PATH=/tmp/typedb_ca.pem")?;

    Ok(())
}

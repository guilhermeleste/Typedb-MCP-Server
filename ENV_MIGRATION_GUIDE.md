# Migration Guide: .env Files Post-Vault Integration

## 🚀 Overview

This guide helps existing developers migrate from the legacy `.env` approach to the new **Vault-first architecture**.

## 📊 What Changed

### Before Vault Integration

```bash
# Legacy .env file contained EVERYTHING
TYPEDB_PASSWORD=mysecretpassword
JWT_SECRET=my_jwt_secret_key  
OAUTH_CLIENT_SECRET=oauth_secret
VAULT_TOKEN=vault_token
TYPEDB_ADDRESS=localhost:1729
RUST_LOG=info
MCP_CONFIG_PATH=configs/config.dev.toml
```

### After Vault Integration

```bash
# Modern .env file - NO SECRETS
RUST_LOG=debug
MCP_TYPEDB__ADDRESS=localhost:1729
MCP_AUTH__OAUTH_ENABLED=false
MCP_CONFIG_PATH=configs/config.dev.toml
```

**All secrets now managed by Vault! 🔐**

## 🔄 Migration Steps

### Step 1: Backup Current Configuration

```bash
# Backup your current .env if it exists
cp .env .env.backup
```

### Step 2: Update to New .env Format

```bash
# Copy new template
cp configs/.env.example .env

# Edit with only non-sensitive configurations
nano .env
```

### Step 3: Move Secrets to Vault

**Option A: Use Development Vault Setup**

```bash
# Set up Vault development environment
./scripts/init-vault-test.sh

# Your secrets are now in Vault KV store
vault kv get kv/typedb-mcp-server/config
```

**Option B: Use Local Secret Files (Alternative)**

```bash
# Set up local secret files for development
cp test-secrets/typedb_password.txt.example test-secrets/typedb_password.txt
echo "your_password_here" > test-secrets/typedb_password.txt
```

### Step 4: Remove Sensitive Variables

Remove these variables from your `.env` file:

- ❌ `TYPEDB_PASSWORD`
- ❌ `TYPEDB_PASSWORD_FILE` (now handled by docker-entrypoint.sh)
- ❌ `JWT_SECRET`
- ❌ `OAUTH_CLIENT_SECRET`
- ❌ `VAULT_TOKEN`
- ❌ Any `*_PASSWORD`, `*_SECRET`, `*_KEY` variables

### Step 5: Update Development Workflow

```bash
# Old workflow
export TYPEDB_PASSWORD="secret"
cargo run

# New workflow  
docker-compose up -d  # Vault handles secrets
cargo run
```

## 📋 Migration Checklist

- [ ] Backup existing `.env` file
- [ ] Copy new `configs/.env.example` to `.env`
- [ ] Remove all sensitive variables from `.env`
- [ ] Set up Vault development environment OR local secret files
- [ ] Test application startup with new configuration
- [ ] Verify secrets are loaded from Vault/files, not environment
- [ ] Update team documentation/scripts if needed

## 🛠️ Configuration Mapping

### Legacy → Modern

| Legacy Variable | New Location | Notes |
|---|---|---|
| `TYPEDB_PASSWORD` | Vault KV store | Via `vault kv put kv/typedb-mcp-server/config` |
| `TYPEDB_PASSWORD_FILE` | Auto-set by entrypoint | Points to `/vault/secrets/db_password.txt` |
| `JWT_SECRET` | Vault KV store | Cryptographically secure |
| `OAUTH_CLIENT_SECRET` | Vault KV store | OAuth configuration |
| `TYPEDB_ADDRESS` | `.env` as `MCP_TYPEDB__ADDRESS` | Non-sensitive, OK in .env |
| `RUST_LOG` | `.env` | Non-sensitive, stays in .env |
| `MCP_CONFIG_PATH` | `.env` | Non-sensitive, stays in .env |

## 🔍 Verification

### Check Secret Loading

```bash
# Verify Vault secrets are accessible
docker-compose exec typedb-mcp-server cat /vault/secrets/db_password.txt

# Or check Vault directly
vault kv get kv/typedb-mcp-server/config
```

### Test Configuration

```bash
# Test with debug logging
RUST_LOG=debug docker-compose up typedb-mcp-server

# Look for configuration loading messages
```

### Validate Security

```bash
# Ensure no secrets in environment
docker-compose exec typedb-mcp-server env | grep -E "(PASSWORD|SECRET|TOKEN)"
# Should NOT show actual secret values
```

## 🚨 Common Migration Issues

### Issue 1: "TYPEDB_PASSWORD_FILE not found"

**Solution**: Vault Agent not running properly

```bash
# Check Vault service
docker-compose logs vault

# Restart Vault services
docker-compose restart vault typedb-mcp-server
```

### Issue 2: "Configuration not loading"

**Solution**: Environment variable override issues

```bash
# Check for conflicting environment variables
env | grep MCP_

# Clear and restart
unset MCP_TYPEDB__PASSWORD
docker-compose restart typedb-mcp-server
```

### Issue 3: "AppRole authentication failed"

**Solution**: Vault credentials not properly mounted

```bash
# Check secret files
ls -la test-secrets/
cat test-secrets/role_id.txt
cat test-secrets/secret_id.txt

# Regenerate if needed
./scripts/init-vault-test.sh
```

## 📚 Additional Resources

- [Configuration Architecture](CONFIGURATION_ARCHITECTURE.md)
- [Vault Setup Guide](test-secrets/README.md)
- [Security Audit Results](SECURITY_AUDIT_RESULTS.md)
- [Docker Compose Documentation](docker-compose.yml)

## 🤝 Getting Help

If you encounter issues during migration:

1. Check the troubleshooting section in [CONFIGURATION_ARCHITECTURE.md](CONFIGURATION_ARCHITECTURE.md)
2. Review logs: `docker-compose logs typedb-mcp-server`
3. Test Vault connectivity: `vault status`
4. Verify secret rendering: `ls -la /vault/secrets/`

Migration should be smooth with these steps. The new architecture provides much better security and separation of concerns! 🔐

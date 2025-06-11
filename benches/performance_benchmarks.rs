//! Suíte de benchmarks de performance para o Typedb-MCP-Server.
//!
//! Este módulo contém benchmarks para medir a performance de:
//! - Componentes internos (validação de JWT, carregamento de config)
//! - Latência de chamadas de ferramentas MCP end-to-end
//! - Throughput de operações por segundo
//! - Performance de estabelecimento de conexão
//!
//! # Execução
//!
//! ```bash
//! # Execute todos os benchmarks
//! cargo bench
//!
//! # Salve uma baseline para comparação
//! cargo bench -- --save-baseline initial
//!
//! # Compare com baseline anterior
//! cargo bench -- --baseline initial
//! ```
//!
//! # Estrutura
//!
//! - `bench_internal_components`: Benchmarks de componentes internos isolados
//! - Relatórios HTML são gerados em `target/criterion/`

#![allow(missing_docs)]

use criterion::{criterion_group, criterion_main, Criterion};
use std::time::SystemTime;
use typedb_mcp_server_lib::{
    auth::Claims,
    config::Settings,
};

/// Grupo de benchmarks para componentes internos do servidor
fn bench_internal_components(c: &mut Criterion) {
    // Benchmark para validação de configuração
    c.bench_function("internal_config_loading", |b| {
        b.iter(|| {
            // Testa o carregamento de configuração
            let result = Settings::new();
            criterion::black_box(result)
        });
    });

    // Benchmark para criação de claims JWT
    c.bench_function("internal_jwt_claims_creation", |b| {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        
        b.iter(|| {
            let claims = Claims {
                sub: "benchmark_user".to_string(),
                exp: now + 3600,
                iat: Some(now),
                nbf: Some(now),
                iss: None,
                aud: None,
                scope: None,
            };
            criterion::black_box(claims)
        });
    });
}

/// Grupo de benchmarks para operações de string e serialização
fn bench_serialization_operations(c: &mut Criterion) {
    // Benchmark para parsing de JSON comum em MCP
    c.bench_function("json_parsing_mcp_request", |b| {
        let json_data = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "list_databases",
                "arguments": {}
            }
        }"#;
        
        b.iter(|| {
            let parsed: serde_json::Value = serde_json::from_str(json_data).unwrap();
            criterion::black_box(parsed)
        });
    });

    // Benchmark para serialização de respostas MCP
    c.bench_function("json_serialization_mcp_response", |b| {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": "Database list: [db1, db2, db3]"
                    }
                ]
            }
        });
        
        b.iter(|| {
            let serialized = serde_json::to_string(&response).unwrap();
            criterion::black_box(serialized)
        });
    });
}

/// Grupo de benchmarks para operações de criptografia
fn bench_crypto_operations(c: &mut Criterion) {
    // Benchmark básico para hashing (usado em várias operações)
    c.bench_function("crypto_basic_hashing", |b| {
        let data = "benchmark_data_for_hashing_performance_test";
        
        b.iter(|| {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            
            let mut hasher = DefaultHasher::new();
            data.hash(&mut hasher);
            let hash = hasher.finish();
            criterion::black_box(hash)
        });
    });
}

// Configuração dos grupos de benchmark para execução via criterion
criterion_group!(
    benches,
    bench_internal_components,
    bench_serialization_operations,
    bench_crypto_operations
);

criterion_main!(benches);

// benches/performance_benchmarks.rs

use criterion::{criterion_group, criterion_main, Bencher, Criterion};
use tokio::runtime::Runtime;

// Import the test utilities from the integration test suite for now.
// This allows the benchmarks to reuse the existing TestEnvironment setup.
#[path = "../tests/common/mod.rs"]
mod common;

use common::{test_env::TestEnvironment, test_utils::{create_test_db, unique_db_name}};

fn bench_tool_call_latency(c: &mut Criterion) {
    let rt = Runtime::new().expect("Falha ao criar runtime Tokio para benchmark.");

    let (test_env, db_name) = rt.block_on(async {
        let test_env = TestEnvironment::setup(
            "bench_latency",
            common::constants::DEFAULT_TEST_CONFIG_FILENAME,
        )
        .await
        .expect("Falha ao configurar ambiente de teste para benchmark.");

        let db_name = unique_db_name("bench_db");
        let mut client = test_env.mcp_client_with_auth(None).await.unwrap();
        create_test_db(&mut client, &db_name).await.unwrap();
        (test_env, db_name)
    });

    c.bench_function("latency_list_databases", |b: &mut Bencher| {
        rt.block_on(async {
            let mut client = test_env.mcp_client_with_auth(None).await.unwrap();
            b.iter(|| async {
                let _ = criterion::black_box(
                    client
                        .call_tool("list_databases", None)
                        .await
                        .unwrap(),
                );
            });
        });
    });

    c.bench_function("latency_query_read_simple", |b: &mut Bencher| {
        let query = "match $p isa person;";
        rt.block_on(async {
            let mut client = test_env.mcp_client_with_auth(None).await.unwrap();
            b.iter(|| async {
                let _ = criterion::black_box(
                    client
                        .call_tool(
                            "query_read",
                            Some(serde_json::json!({
                                "databaseName": db_name,
                                "query": query
                            })),
                        )
                        .await
                        .unwrap(),
                );
            });
        });
    });
}

criterion_group!(benches, bench_tool_call_latency);
criterion_main!(benches);

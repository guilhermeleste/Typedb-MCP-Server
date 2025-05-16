#!/bin/bash

# Limpeza (Opcional, mas Recomendado)
echo "Limpando alvos anteriores e dados de cobertura..."
cargo clean
rm -rf ./target/coverage
rm -f ./*.profraw

# Definição de Flags de Compilação para Cobertura
export RUSTFLAGS="-Cinstrument-coverage"
export LLVM_PROFILE_FILE="typedb_mcp_server-%p-%m.profraw"

# Execução dos Testes
echo "Executando testes com instrumentação de cobertura..."
cargo test

# Geração do Relatório de Cobertura HTML
echo "Gerando relatório de cobertura..."
grcov . --binary-path ./target/debug/ -s . -t html --branch --ignore-not-existing --ignore "tests/*" --ignore "target/*" --ignore "**/vendor/*" -o ./target/coverage/

# Limpeza das Variáveis de Ambiente
unset RUSTFLAGS
unset LLVM_PROFILE_FILE

# Mensagens Finais
echo "Relatório de cobertura gerado em ./target/coverage/index.html"
echo "Certifique-se de ter 'grcov' e 'llvm-tools-preview' instalados:"
echo "  rustup component add llvm-tools-preview"
echo "  cargo install grcov"

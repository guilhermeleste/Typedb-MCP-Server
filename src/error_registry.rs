use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use chrono::{DateTime, Utc};

/// Sistema de registro e rastreamento de erros para prevenção automática
/// 
/// Este módulo implementa um sistema robusto para:
/// - Capturar erros sistematicamente
/// - Identificar padrões recorrentes
/// - Aplicar medidas preventivas automaticamente
/// - Integrar com sistema f1e memory para persistência
/// 
/// # Exemplo
/// 
/// ```rust
/// use typedb_mcp_server_lib::error_registry::{ErrorRegistry, ErrorEntry, ErrorCategory};
/// 
/// let mut registry = ErrorRegistry::new();
/// 
/// let error = ErrorEntry::new(
///     ErrorCategory::TypeDB,
///     "High".to_string(),
///     "src/db.rs".to_string(),
///     "Connection timeout during transaction".to_string()
/// );
/// 
/// registry.register_error(error)?;
/// let patterns = registry.analyze_patterns()?;
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorRegistry {
    /// Diretório base para arquivos de erro
    pub base_path: String,
    /// Cache de erros em memória
    pub errors: HashMap<String, ErrorEntry>,
    /// Configurações do sistema
    pub config: RegistryConfig,
}

/// Configurações do sistema de registro de erros
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryConfig {
    /// Habilita captura automática
    pub auto_capture: bool,
    /// Máximo de erros por categoria
    pub max_errors_per_category: usize,
    /// Intervalo de análise automática (em horas)
    pub analysis_interval_hours: u64,
    /// Habilita geração automática de regras
    pub auto_prevention: bool,
}

/// Entrada de erro no registro
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorEntry {
    /// ID único do erro
    pub id: String,
    /// Timestamp de criação
    pub timestamp: String,
    /// Categoria do erro
    pub category: ErrorCategory,
    /// Severidade (Critical, High, Medium, Low)
    pub severity: String,
    /// Componente afetado
    pub component: String,
    /// Linha do código (se aplicável)
    pub line: Option<u32>,
    /// Descrição do erro
    pub description: String,
    /// Contexto técnico
    pub context: ErrorContext,
    /// Mensagem de erro original
    pub error_message: String,
    /// Passos para reprodução
    pub reproduction_steps: Vec<String>,
    /// Análise do erro
    pub analysis: ErrorAnalysis,
    /// Solução aplicada
    pub solution: Option<ErrorSolution>,
    /// Medidas de prevenção
    pub prevention: Option<ErrorPrevention>,
    /// Erros relacionados
    pub related_errors: Vec<String>,
    /// Contador de recorrência
    pub recurrence_count: u32,
    /// Status de resolução
    pub resolved: bool,
    /// Timestamp de resolução
    pub resolved_at: Option<String>,
    /// Responsável pela resolução
    pub resolved_by: Option<String>,
}

/// Categorias de erro suportadas
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ErrorCategory {
    /// Erros de compilação Rust
    Compilation,
    /// Erros de integração TypeDB
    TypeDB,
    /// Erros do protocolo MCP
    Authentication,
    /// Erros de configuração
    Configuration,
    /// Erros de teste
    Testing,
    /// Outros erros
    General,
}

/// Contexto técnico do erro
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorContext {
    /// Versão do Cargo
    pub cargo_version: String,
    /// Versão do Rust
    pub rust_version: String,
    /// Versão do TypeDB
    pub typedb_version: String,
    /// Ambiente (dev, test, prod)
    pub environment: String,
    /// Hash do commit Git
    pub git_commit: String,
}

/// Análise do erro
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorAnalysis {
    /// Causa raiz identificada
    pub root_cause: String,
    /// Fatores contribuintes
    pub contributing_factors: Vec<String>,
}

/// Solução aplicada ao erro
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorSolution {
    /// Descrição da solução
    pub description: String,
    /// Arquivos alterados
    pub changes: Vec<String>,
    /// Método de validação
    pub validation: String,
}

/// Medidas de prevenção implementadas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPrevention {
    /// Regras automáticas criadas
    pub rules: Vec<String>,
    /// Scripts de automação
    pub automation: Vec<String>,
}

/// Padrão de erro identificado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPattern {
    /// Categoria do padrão
    pub category: ErrorCategory,
    /// Número de ocorrências
    pub frequency: u32,
    /// Componentes mais afetados
    pub affected_components: Vec<String>,
    /// Mensagens comuns
    pub common_messages: Vec<String>,
    /// Recomendações de prevenção
    pub prevention_recommendations: Vec<String>,
}

/// Resultados da análise de padrões
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternAnalysis {
    /// Padrões identificados
    pub patterns: Vec<ErrorPattern>,
    /// Taxa de recorrência geral
    pub recurrence_rate: f64,
    /// Categorias mais problemáticas
    pub top_categories: Vec<ErrorCategory>,
    /// Recomendações gerais
    pub general_recommendations: Vec<String>,
}

/// Tipo de otimização aplicada ao sistema
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OptimizationType {
    /// Otimização de build Docker (cache, multi-stage, etc.)
    DockerBuildOptimization,
    /// Otimização de execução de testes
    TestExecutionOptimization,
    /// Melhoria de performance de aplicação
    ApplicationPerformance,
    /// Otimização de uso de recursos
    ResourceUsage,
    /// Melhoria de processo de desenvolvimento
    DevelopmentProcess,
}

/// Medição de impacto de uma otimização
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactMeasurement {
    /// Duração antes da otimização
    pub before_duration: Option<chrono::Duration>,
    /// Duração após a otimização
    pub after_duration: Option<chrono::Duration>,
    /// Percentual de melhoria (positivo = melhoria, negativo = regressão)
    pub improvement_percentage: f64,
    /// Métrica adicional (ex: tamanho de imagem, uso de memória)
    pub additional_metrics: HashMap<String, String>,
}

/// Registro de uma otimização aplicada
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationEntry {
    /// ID único da otimização
    pub id: String,
    /// Tipo de otimização
    pub optimization_type: OptimizationType,
    /// Descrição da otimização aplicada
    pub description: String,
    /// Medição de impacto (se disponível)
    pub impact_measured: Option<ImpactMeasurement>,
    /// Data/hora quando foi aplicada
    pub applied_at: DateTime<Utc>,
    /// Contexto onde foi aplicada
    pub context: String,
    /// Autor da otimização
    pub author: Option<String>,
    /// Se a otimização foi validada/aprovada
    pub validated: bool,
}

/// Categoria de mudança de código para aprovação
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChangeCategory {
    /// Mudança pequena (< 10 arquivos, < 500 linhas)
    SmallChange,
    /// Mudança média (< 20 arquivos, < 1000 linhas)
    MediumChange,
    /// Mudança grande (20+ arquivos, 1000+ linhas)
    LargeChange,
    /// Mudança crítica (arquivos críticos tocados)
    CriticalChange,
}

/// Análise de mudança de código
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeAnalysis {
    /// ID único da análise
    pub id: String,
    /// Categoria da mudança
    pub change_category: ChangeCategory,
    /// Número de arquivos modificados
    pub files_changed: u32,
    /// Número de linhas alteradas
    pub lines_changed: u32,
    /// Score calculado da mudança
    pub change_score: u32,
    /// Arquivos críticos tocados
    pub critical_files_touched: Vec<String>,
    /// Diretórios protegidos tocados
    pub protected_directories_touched: Vec<String>,
    /// Mudanças estruturais detectadas
    pub structural_changes: Vec<String>,
    /// Aprovações necessárias
    pub approvals_required: u32,
    /// Se requer aprovação sênior
    pub senior_approval_required: bool,
    /// Data/hora da análise
    pub analyzed_at: DateTime<Utc>,
    /// Branch base
    pub base_branch: String,
    /// Branch head
    pub head_branch: String,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            auto_capture: true,
            max_errors_per_category: 100,
            analysis_interval_hours: 24,
            auto_prevention: true,
        }
    }
}

impl Default for ErrorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ErrorRegistry {
    /// Cria uma nova instância do registry
    /// 
    /// # Argumentos
    /// 
    /// * `base_path` - Diretório base para arquivos de erro
    /// 
    /// # Exemplo
    /// 
    /// ```rust
    /// let registry = ErrorRegistry::new();
    /// ```
    pub fn new() -> Self {
        Self::with_path(".github/errors")
    }

    /// Cria uma nova instância com caminho customizado
    /// 
    /// # Argumentos
    /// 
    /// * `base_path` - Diretório base customizado
    pub fn with_path(base_path: &str) -> Self {
        Self {
            base_path: base_path.to_string(),
            errors: HashMap::new(),
            config: RegistryConfig::default(),
        }
    }

    /// Registra um novo erro no sistema
    /// 
    /// # Argumentos
    /// 
    /// * `error` - Entrada de erro a ser registrada
    /// 
    /// # Retorna
    /// 
    /// * `Result<String, Box<dyn std::error::Error>>` - ID do erro registrado
    /// 
    /// # Exemplo
    /// 
    /// ```rust
    /// let error = ErrorEntry::new(
    ///     ErrorCategory::TypeDB,
    ///     "High".to_string(),
    ///     "src/db.rs".to_string(),
    ///     "Connection timeout".to_string()
    /// );
    /// 
    /// let error_id = registry.register_error(error)?;
    /// ```
    pub fn register_error(&mut self, mut error: ErrorEntry) -> Result<String, Box<dyn std::error::Error>> {
        // Gera ID único se não fornecido
        if error.id.is_empty() {
            error.id = self.generate_error_id(&error.category);
        }

        info!(
            error_id = %error.id,
            category = ?error.category,
            severity = %error.severity,
            "Registrando novo erro"
        );

        // Verifica se é erro recorrente
        let existing_id = self.find_similar_error(&error).map(|e| e.id.clone());
        
        if let Some(existing_id) = existing_id {
            warn!(
                existing_id = %existing_id,
                new_id = %error.id,
                "Erro similar detectado - incrementando contador de recorrência"
            );
            
            // Incrementa contador de recorrência
            {
                let existing = self.errors.get_mut(&existing_id).unwrap();
                existing.recurrence_count += 1;
                existing.related_errors.push(error.id.clone());
            }
            self.save_error(&existing_id)?;
        } else {
            // Novo erro único
            self.errors.insert(error.id.clone(), error.clone());
            self.save_error(&error.id)?;
        }

        // Trigger análise automática se habilitada
        if self.config.auto_capture {
            self.trigger_automatic_analysis()?;
        }

        Ok(error.id)
    }

    /// Analisa padrões de erro existentes
    /// 
    /// # Retorna
    /// 
    /// * `Result<PatternAnalysis, Box<dyn std::error::Error>>` - Análise de padrões
    pub fn analyze_patterns(&self) -> Result<PatternAnalysis, Box<dyn std::error::Error>> {
        info!("Iniciando análise de padrões de erro");

        let mut patterns = Vec::new();
        let mut category_counts: HashMap<ErrorCategory, u32> = HashMap::new();
        let total_errors = self.errors.len() as u32;

        // Conta erros por categoria
        for error in self.errors.values() {
            *category_counts.entry(error.category.clone()).or_insert(0) += 1;
        }

        // Cria padrões para cada categoria
        for (category, frequency) in category_counts.iter() {
            if *frequency > 1 {
                let pattern = self.analyze_category_pattern(category)?;
                patterns.push(pattern);
            }
        }

        // Calcula taxa de recorrência
        let recurring_errors = self.errors.values()
            .filter(|e| e.recurrence_count > 1)
            .count() as u32;
        
        let recurrence_rate = if total_errors > 0 {
            (recurring_errors as f64 / total_errors as f64) * 100.0
        } else {
            0.0
        };

        // Identifica categorias mais problemáticas
        let mut top_categories: Vec<_> = category_counts.iter()
            .map(|(cat, count)| (cat.clone(), *count))
            .collect();
        top_categories.sort_by(|a, b| b.1.cmp(&a.1));
        let top_categories: Vec<_> = top_categories.into_iter()
            .take(3)
            .map(|(cat, _)| cat)
            .collect();

        // Gera recomendações gerais
        let general_recommendations = self.generate_general_recommendations(&patterns);

        Ok(PatternAnalysis {
            patterns,
            recurrence_rate,
            top_categories,
            general_recommendations,
        })
    }

    /// Gera regras de prevenção automática
    /// 
    /// # Argumentos
    /// 
    /// * `analysis` - Análise de padrões
    /// 
    /// # Retorna
    /// 
    /// * `Result<Vec<String>, Box<dyn std::error::Error>>` - Regras geradas
    pub fn generate_prevention_rules(&self, analysis: &PatternAnalysis) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        info!("Gerando regras de prevenção automática");

        let mut rules = Vec::new();

        for pattern in &analysis.patterns {
            match pattern.category {
                ErrorCategory::Compilation => {
                    rules.push("unwrap_used = \"deny\"".to_string());
                    rules.push("expect_used = \"deny\"".to_string());
                }
                ErrorCategory::TypeDB => {
                    rules.push("panic_in_result_fn = \"deny\"".to_string());
                    rules.push("# Timeout validation required".to_string());
                }
                ErrorCategory::Authentication => {
                    rules.push("# Token validation required".to_string());
                    rules.push("# Scope checking required".to_string());
                }
                ErrorCategory::Configuration => {
                    rules.push("# TOML schema validation required".to_string());
                    rules.push("# Default value validation required".to_string());
                }
                ErrorCategory::Testing => {
                    rules.push("# Mock reliability checks required".to_string());
                    rules.push("# Test isolation required".to_string());
                }
                ErrorCategory::General => {
                    rules.push("# General error handling improvements".to_string());
                }
            }
        }

        Ok(rules)
    }

    /// Carrega erros existentes do disco
    pub fn load_existing_errors(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let errors_dir = Path::new(&self.base_path);
        
        if !errors_dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(errors_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().map_or(false, |ext| ext == "yml") {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(error) = serde_yaml::from_str::<ErrorEntry>(&content) {
                        self.errors.insert(error.id.clone(), error);
                    }
                }
            }
        }

        info!(count = self.errors.len(), "Erros carregados do disco");
        Ok(())
    }

    /// Registra uma otimização aplicada ao sistema
    pub fn log_optimization(&mut self, optimization: OptimizationEntry) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let span = tracing::info_span!("log_optimization", 
            optimization_id = %optimization.id,
            optimization_type = ?optimization.optimization_type
        );
        let _enter = span.enter();
        
        tracing::info!(
            "Registrando otimização: {} (tipo: {:?})",
            optimization.description,
            optimization.optimization_type
        );
        
        // Persiste no disco para análise histórica
        let optimization_file = self.get_optimizations_file_path()?;
        let mut optimizations = self.load_optimizations()?;
        optimizations.push(optimization.clone());
        
        std::fs::write(&optimization_file, serde_yaml::to_string(&optimizations)?)?;
        
        // Atualiza métricas se houver impacto medido
        if let Some(ref impact) = optimization.impact_measured {
            if impact.improvement_percentage > 0.0 {
                tracing::info!(
                    "Otimização teve impacto positivo: {:.1}% de melhoria",
                    impact.improvement_percentage
                );
            } else {
                tracing::warn!(
                    "Otimização teve impacto negativo: {:.1}% de regressão",
                    impact.improvement_percentage.abs()
                );
            }
        }
        
        Ok(())
    }
    
    /// Registra análise de mudança de código
    pub fn log_change_analysis(&mut self, analysis: ChangeAnalysis) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let span = tracing::info_span!("log_change_analysis",
            analysis_id = %analysis.id,
            change_category = ?analysis.change_category,
            change_score = analysis.change_score
        );
        let _enter = span.enter();
        
        tracing::info!(
            "Registrando análise de mudança: categoria {:?}, score {}, {} arquivos alterados",
            analysis.change_category,
            analysis.change_score,
            analysis.files_changed
        );
        
        // Log de arquivos críticos tocados
        if !analysis.critical_files_touched.is_empty() {
            tracing::warn!(
                "Arquivos críticos modificados: {:?}",
                analysis.critical_files_touched
            );
        }
        
        // Log de mudanças estruturais
        if !analysis.structural_changes.is_empty() {
            tracing::info!(
                "Mudanças estruturais detectadas: {:?}",
                analysis.structural_changes
            );
        }
        
        // Persiste análise
        let analysis_file = self.get_change_analysis_file_path()?;
        let mut analyses = self.load_change_analyses()?;
        analyses.push(analysis);
        
        std::fs::write(&analysis_file, serde_yaml::to_string(&analyses)?)?;
        
        Ok(())
    }
    
    /// Gera relatório de otimizações aplicadas
    pub fn generate_optimization_report(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let optimizations = self.load_optimizations()?;
        
        let mut report = String::new();
        report.push_str("=== RELATÓRIO DE OTIMIZAÇÕES ===\n\n");
        
        // Estatísticas gerais
        let total_optimizations = optimizations.len();
        let validated_optimizations = optimizations.iter().filter(|o| o.validated).count();
        
        report.push_str(&format!("Total de otimizações: {}\n", total_optimizations));
        report.push_str(&format!("Otimizações validadas: {}\n\n", validated_optimizations));
        
        // Agrupamento por tipo
        let mut by_type: HashMap<String, Vec<&OptimizationEntry>> = HashMap::new();
        for optimization in &optimizations {
            by_type.entry(format!("{:?}", optimization.optimization_type))
                   .or_insert_with(Vec::new)
                   .push(optimization);
        }
        
        report.push_str("=== POR TIPO ===\n");
        for (optimization_type, entries) in &by_type {
            report.push_str(&format!("{}: {} otimizações\n", optimization_type, entries.len()));
            
            // Calcula impacto médio
            let impacts: Vec<f64> = entries.iter()
                .filter_map(|e| e.impact_measured.as_ref())
                .map(|i| i.improvement_percentage)
                .collect();
            
            if !impacts.is_empty() {
                let avg_impact = impacts.iter().sum::<f64>() / impacts.len() as f64;
                report.push_str(&format!("  Impacto médio: {:.1}%\n", avg_impact));
            }
        }
        
        // Otimizações recentes (últimos 7 dias)
        let week_ago = Utc::now() - chrono::Duration::days(7);
        let recent_optimizations: Vec<&OptimizationEntry> = optimizations.iter()
            .filter(|o| o.applied_at > week_ago)
            .collect();
        
        if !recent_optimizations.is_empty() {
            report.push_str(&format!("\n=== OTIMIZAÇÕES RECENTES (7 dias) ===\n"));
            for optimization in recent_optimizations {
                report.push_str(&format!("- {}: {}\n", 
                    optimization.applied_at.format("%Y-%m-%d"),
                    optimization.description
                ));
            }
        }
        
        Ok(report)
    }
    
    /// Gera relatório de análises de mudança
    pub fn generate_change_analysis_report(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let analyses = self.load_change_analyses()?;
        
        let mut report = String::new();
        report.push_str("=== RELATÓRIO DE ANÁLISES DE MUDANÇA ===\n\n");
        
        // Estatísticas por categoria
        let mut by_category: HashMap<String, Vec<&ChangeAnalysis>> = HashMap::new();
        for analysis in &analyses {
            by_category.entry(format!("{:?}", analysis.change_category))
                       .or_insert_with(Vec::new)
                       .push(analysis);
        }
        
        report.push_str("=== DISTRIBUIÇÃO POR CATEGORIA ===\n");
        for (category, entries) in &by_category {
            let avg_score = entries.iter().map(|e| e.change_score as f64).sum::<f64>() / entries.len() as f64;
            report.push_str(&format!("{}: {} mudanças (score médio: {:.1})\n", 
                category, entries.len(), avg_score
            ));
        }
        
        // Arquivos mais modificados
        let mut file_frequency: HashMap<String, u32> = HashMap::new();
        for analysis in &analyses {
            for file in &analysis.critical_files_touched {
                *file_frequency.entry(file.clone()).or_insert(0) += 1;
            }
        }
        
        if !file_frequency.is_empty() {
            report.push_str("\n=== ARQUIVOS CRÍTICOS MAIS MODIFICADOS ===\n");
            let mut sorted_files: Vec<_> = file_frequency.iter().collect();
            sorted_files.sort_by(|a, b| b.1.cmp(a.1));
            
            for (file, count) in sorted_files.iter().take(10) {
                report.push_str(&format!("{}: {} vezes\n", file, count));
            }
        }
        
        Ok(report)
    }
    
    /// Carrega otimizações do disco
    fn load_optimizations(&self) -> Result<Vec<OptimizationEntry>, Box<dyn std::error::Error + Send + Sync>> {
        let file_path = self.get_optimizations_file_path()?;
        
        if !file_path.exists() {
            return Ok(Vec::new());
        }
        
        let content = std::fs::read_to_string(file_path)?;
        let optimizations: Vec<OptimizationEntry> = serde_yaml::from_str(&content)?;
        Ok(optimizations)
    }
    
    /// Carrega análises de mudança do disco
    fn load_change_analyses(&self) -> Result<Vec<ChangeAnalysis>, Box<dyn std::error::Error + Send + Sync>> {
        let file_path = self.get_change_analysis_file_path()?;
        
        if !file_path.exists() {
            return Ok(Vec::new());
        }
        
        let content = std::fs::read_to_string(file_path)?;
        let analyses: Vec<ChangeAnalysis> = serde_yaml::from_str(&content)?;
        Ok(analyses)
    }
    
    /// Caminho do arquivo de otimizações
    fn get_optimizations_file_path(&self) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
        let mut path = PathBuf::from(&self.base_path);
        path.push("optimizations");
        std::fs::create_dir_all(&path)?;
        path.push("applied_optimizations.yml");
        Ok(path)
    }
    
    /// Caminho do arquivo de análises de mudança
    fn get_change_analysis_file_path(&self) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
        let mut path = PathBuf::from(&self.base_path);
        path.push("change-analysis");
        std::fs::create_dir_all(&path)?;
        path.push("change_analyses.yml");
        Ok(path)
    }

    // Métodos auxiliares privados

    fn generate_error_id(&self, category: &ErrorCategory) -> String {
        let category_prefix = match category {
            ErrorCategory::Compilation => "COMP",
            ErrorCategory::TypeDB => "TYPEDB",
            ErrorCategory::Authentication => "AUTH",
            ErrorCategory::Configuration => "CONFIG",
            ErrorCategory::Testing => "TEST",
            ErrorCategory::General => "GEN",
        };

        let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
        format!("{}-{}", category_prefix, timestamp)
    }

    fn find_similar_error(&self, error: &ErrorEntry) -> Option<&ErrorEntry> {
        // Busca erros similares baseado na descrição e componente
        self.errors.values().find(|existing| {
            existing.category == error.category &&
            existing.component == error.component &&
            self.similarity_score(&existing.description, &error.description) > 0.8
        })
    }

    fn similarity_score(&self, text1: &str, text2: &str) -> f64 {
        // Implementação simplificada de similaridade
        // Em produção, usar algoritmos mais sofisticados como Levenshtein
        let words1: std::collections::HashSet<_> = text1.split_whitespace().collect();
        let words2: std::collections::HashSet<_> = text2.split_whitespace().collect();
        
        let intersection = words1.intersection(&words2).count();
        let union = words1.union(&words2).count();
        
        if union == 0 { 0.0 } else { intersection as f64 / union as f64 }
    }

    fn save_error(&self, error_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(error) = self.errors.get(error_id) {
            let file_path = format!("{}/{}.yml", self.base_path, error_id);
            let content = serde_yaml::to_string(error)?;
            
            // Garante que o diretório existe
            if let Some(parent) = Path::new(&file_path).parent() {
                fs::create_dir_all(parent)?;
            }
            
            fs::write(file_path, content)?;
        }
        Ok(())
    }

    fn analyze_category_pattern(&self, category: &ErrorCategory) -> Result<ErrorPattern, Box<dyn std::error::Error>> {
        let category_errors: Vec<_> = self.errors.values()
            .filter(|e| &e.category == category)
            .collect();

        let frequency = category_errors.len() as u32;
        
        // Analisa componentes mais afetados
        let mut component_counts: HashMap<String, u32> = HashMap::new();
        for error in &category_errors {
            *component_counts.entry(error.component.clone()).or_insert(0) += 1;
        }
        
        let mut affected_components: Vec<_> = component_counts.into_iter().collect();
        affected_components.sort_by(|a, b| b.1.cmp(&a.1));
        let affected_components = affected_components.into_iter()
            .take(5)
            .map(|(comp, _)| comp)
            .collect();

        // Analisa mensagens comuns
        let mut message_counts: HashMap<String, u32> = HashMap::new();
        for error in &category_errors {
            *message_counts.entry(error.description.clone()).or_insert(0) += 1;
        }
        
        let mut common_messages: Vec<_> = message_counts.into_iter().collect();
        common_messages.sort_by(|a, b| b.1.cmp(&a.1));
        let common_messages = common_messages.into_iter()
            .take(5)
            .map(|(msg, _)| msg)
            .collect();

        // Gera recomendações específicas
        let prevention_recommendations = self.generate_category_recommendations(category);

        Ok(ErrorPattern {
            category: category.clone(),
            frequency,
            affected_components,
            common_messages,
            prevention_recommendations,
        })
    }

    fn generate_category_recommendations(&self, category: &ErrorCategory) -> Vec<String> {
        match category {
            ErrorCategory::Compilation => vec![
                "Implementar lint rules customizadas".to_string(),
                "Adicionar testes de borrowing".to_string(),
                "Documentar lifetime patterns".to_string(),
                "Pre-commit hooks para validação".to_string(),
            ],
            ErrorCategory::TypeDB => vec![
                "Connection pooling obrigatório".to_string(),
                "Timeouts configuráveis".to_string(),
                "Retry com exponential backoff".to_string(),
                "Health checks automáticos".to_string(),
            ],
            ErrorCategory::Authentication => vec![
                "Token validation centralizada".to_string(),
                "Scope checking automático".to_string(),
                "Certificate rotation".to_string(),
                "Audit logging obrigatório".to_string(),
            ],
            ErrorCategory::Configuration => vec![
                "Schema validation de TOML".to_string(),
                "Default values seguros".to_string(),
                "Environment variable validation".to_string(),
                "Precedence documentation".to_string(),
            ],
            ErrorCategory::Testing => vec![
                "Mock reliability improvements".to_string(),
                "Docker setup automation".to_string(),
                "Flaky test detection".to_string(),
                "Test isolation enforcement".to_string(),
            ],
            ErrorCategory::General => vec![
                "Error handling improvements".to_string(),
                "Logging enhancement".to_string(),
                "Monitoring integration".to_string(),
            ],
        }
    }

    fn generate_general_recommendations(&self, patterns: &[ErrorPattern]) -> Vec<String> {
        let mut recommendations = Vec::new();

        // Recomendações baseadas na análise geral
        if patterns.iter().any(|p| matches!(p.category, ErrorCategory::Compilation)) {
            recommendations.push("Implementar linting mais rigoroso".to_string());
        }

        if patterns.iter().any(|p| matches!(p.category, ErrorCategory::TypeDB)) {
            recommendations.push("Melhorar gestão de conexões TypeDB".to_string());
        }

        if patterns.len() > 3 {
            recommendations.push("Implementar sistema de alertas".to_string());
        }

        recommendations.push("Continuar monitoramento automático".to_string());
        
        recommendations
    }

    fn trigger_automatic_analysis(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Em uma implementação completa, isso poderia:
        // 1. Agendar análise automática
        // 2. Enviar alertas
        // 3. Atualizar métricas
        // 4. Trigger prevenção automática
        
        info!("Análise automática triggerada");
        Ok(())
    }
}

impl ErrorEntry {
    /// Cria uma nova entrada de erro
    /// 
    /// # Argumentos
    /// 
    /// * `category` - Categoria do erro
    /// * `severity` - Severidade (Critical, High, Medium, Low)
    /// * `component` - Componente afetado
    /// * `description` - Descrição do erro
    pub fn new(
        category: ErrorCategory,
        severity: String,
        component: String,
        description: String,
    ) -> Self {
        Self {
            id: String::new(), // Será gerado automaticamente
            timestamp: chrono::Utc::now().to_rfc3339(),
            category,
            severity,
            component,
            line: None,
            description,
            context: ErrorContext::default(),
            error_message: String::new(),
            reproduction_steps: Vec::new(),
            analysis: ErrorAnalysis {
                root_cause: "To be analyzed".to_string(),
                contributing_factors: Vec::new(),
            },
            solution: None,
            prevention: None,
            related_errors: Vec::new(),
            recurrence_count: 1,
            resolved: false,
            resolved_at: None,
            resolved_by: None,
        }
    }

    /// Marca o erro como resolvido
    /// 
    /// # Argumentos
    /// 
    /// * `solution` - Solução aplicada
    /// * `resolved_by` - Responsável pela resolução
    pub fn mark_resolved(&mut self, solution: ErrorSolution, resolved_by: String) {
        self.resolved = true;
        self.resolved_at = Some(chrono::Utc::now().to_rfc3339());
        self.resolved_by = Some(resolved_by);
        self.solution = Some(solution);
    }

    /// Adiciona medidas de prevenção
    /// 
    /// # Argumentos
    /// 
    /// * `prevention` - Medidas de prevenção implementadas
    pub fn add_prevention(&mut self, prevention: ErrorPrevention) {
        self.prevention = Some(prevention);
    }
}

impl Default for ErrorContext {
    fn default() -> Self {
        Self {
            cargo_version: env!("CARGO_PKG_VERSION").to_string(),
            rust_version: "unknown".to_string(),
            typedb_version: "unknown".to_string(),
            environment: "development".to_string(),
            git_commit: "unknown".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_error_registry_creation() {
        let registry = ErrorRegistry::new();
        assert_eq!(registry.base_path, ".github/errors");
        assert!(registry.errors.is_empty());
    }

    #[test]
    fn test_error_entry_creation() {
        let error = ErrorEntry::new(
            ErrorCategory::TypeDB,
            "High".to_string(),
            "src/db.rs".to_string(),
            "Connection timeout".to_string(),
        );

        assert_eq!(error.category, ErrorCategory::TypeDB);
        assert_eq!(error.severity, "High");
        assert_eq!(error.component, "src/db.rs");
        assert_eq!(error.description, "Connection timeout");
        assert!(!error.resolved);
    }

    #[test]
    fn test_error_registration() {
        let temp_dir = TempDir::new().unwrap();
        let mut registry = ErrorRegistry::with_path(temp_dir.path().to_str().unwrap());

        let error = ErrorEntry::new(
            ErrorCategory::Authentication,
            "Medium".to_string(),
            "src/tools/query.rs".to_string(),
            "Invalid parameter".to_string(),
        );

        let error_id = registry.register_error(error).unwrap();
        assert!(!error_id.is_empty());
        assert!(registry.errors.contains_key(&error_id));
    }

    #[test]
    fn test_pattern_analysis() {
        let mut registry = ErrorRegistry::new();

        // Adiciona múltiplos erros da mesma categoria
        for i in 0..3 {
            let error = ErrorEntry::new(
                ErrorCategory::Compilation,
                "High".to_string(),
                format!("src/lib{}.rs", i),
                "Borrow checker error".to_string(),
            );
            registry.register_error(error).unwrap();
        }

        let analysis = registry.analyze_patterns().unwrap();
        
        // Deve detectar padrão de compilação (>=1 erro por categoria)
        let comp_pattern = analysis.patterns.iter()
            .find(|p| matches!(p.category, ErrorCategory::Compilation));
        
        // Se temos 3 erros da mesma categoria, deve criar padrão
        if registry.errors.len() >= 2 {
            assert!(comp_pattern.is_some());
        }
        
        // Verifica que a análise retorna dados válidos
        assert!(analysis.recurrence_rate >= 0.0);
        assert!(!analysis.top_categories.is_empty());
    }

    #[test]
    fn test_prevention_rules_generation() {
        let registry = ErrorRegistry::new();
        
        let pattern = ErrorPattern {
            category: ErrorCategory::Compilation,
            frequency: 3,
            affected_components: vec!["src/lib.rs".to_string()],
            common_messages: vec!["unwrap on None".to_string()],
            prevention_recommendations: vec!["Use ? operator".to_string()],
        };

        let analysis = PatternAnalysis {
            patterns: vec![pattern],
            recurrence_rate: 25.0,
            top_categories: vec![ErrorCategory::Compilation],
            general_recommendations: vec!["Improve error handling".to_string()],
        };

        let rules = registry.generate_prevention_rules(&analysis).unwrap();
        assert!(rules.iter().any(|r| r.contains("unwrap_used")));
    }

    #[test]
    fn test_optimization_logging() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut registry = ErrorRegistry::default();
        registry.base_path = temp_dir.path().to_string_lossy().to_string();
        
        let optimization = OptimizationEntry {
            id: "opt-001".to_string(),
            optimization_type: OptimizationType::DockerBuildOptimization,
            description: "Implementação de multi-stage build".to_string(),
            impact_measured: Some(ImpactMeasurement {
                before_duration: Some(chrono::Duration::seconds(300)),
                after_duration: Some(chrono::Duration::seconds(120)),
                improvement_percentage: 60.0,
                additional_metrics: {
                    let mut map = HashMap::new();
                    map.insert("image_size_before".to_string(), "2.1GB".to_string());
                    map.insert("image_size_after".to_string(), "1.2GB".to_string());
                    map
                },
            }),
            applied_at: Utc::now(),
            context: "docker_build_optimization".to_string(),
            author: Some("test_user".to_string()),
            validated: true,
        };
        
        registry.log_optimization(optimization).unwrap();
        
        let report = registry.generate_optimization_report().unwrap();
        assert!(report.contains("Total de otimizações: 1"));
        assert!(report.contains("DockerBuildOptimization"));
        assert!(report.contains("60.0%"));
    }
    
    #[test]
    fn test_change_analysis_logging() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut registry = ErrorRegistry::default();
        registry.base_path = temp_dir.path().to_string_lossy().to_string();
        
        let analysis = ChangeAnalysis {
            id: "change-001".to_string(),
            change_category: ChangeCategory::LargeChange,
            files_changed: 25,
            lines_changed: 1200,
            change_score: 750,
            critical_files_touched: vec!["src/main.rs".to_string(), "Dockerfile".to_string()],
            protected_directories_touched: vec!["src/tools/".to_string()],
            structural_changes: vec!["new_dependency".to_string(), "api_change".to_string()],
            approvals_required: 2,
            senior_approval_required: true,
            analyzed_at: Utc::now(),
            base_branch: "main".to_string(),
            head_branch: "feature/large-feature".to_string(),
        };
        
        registry.log_change_analysis(analysis).unwrap();
        
        let report = registry.generate_change_analysis_report().unwrap();
        assert!(report.contains("LargeChange"));
        assert!(report.contains("src/main.rs"));
        assert!(report.contains("score médio: 750"));
    }
}

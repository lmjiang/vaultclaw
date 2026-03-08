//! Criterion benchmarks for core vault operations.
//!
//! Run with: `cargo bench`

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

use vaultclaw::config::generate_password;
use vaultclaw::crypto::kdf::KdfParams;
use vaultclaw::crypto::keys::password_secret;
use vaultclaw::vault::entry::*;
use vaultclaw::vault::format::VaultFile;

fn fast_kdf() -> KdfParams {
    KdfParams {
        memory_cost_kib: 1024,
        iterations: 1,
        parallelism: 1,
        salt_length: 32,
    }
}

fn test_password() -> secrecy::SecretString {
    password_secret("bench-password-123".to_string())
}

fn sample_login(i: usize) -> Entry {
    Entry::new(
        format!("Service {}", i),
        Credential::Login(LoginCredential {
            url: format!("https://service{}.example.com", i),
            username: format!("user{}", i),
            password: generate_password(24),
        }),
    )
}

fn bench_vault_create(c: &mut Criterion) {
    c.bench_function("vault_create", |b| {
        b.iter(|| {
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().join("bench.vclaw");
            let vault = VaultFile::create(&path, &test_password(), fast_kdf()).unwrap();
            black_box(vault);
        });
    });
}

fn bench_vault_open(c: &mut Criterion) {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("bench.vclaw");
    let mut vault = VaultFile::create(&path, &test_password(), fast_kdf()).unwrap();
    for i in 0..100 {
        vault.store_mut().add(sample_login(i));
    }
    vault.save().unwrap();

    c.bench_function("vault_open_100_entries", |b| {
        b.iter(|| {
            let vault = VaultFile::open(&path, &test_password()).unwrap();
            black_box(vault.store().len());
        });
    });
}

fn bench_entry_add(c: &mut Criterion) {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("bench.vclaw");
    VaultFile::create(&path, &test_password(), fast_kdf()).unwrap();

    c.bench_function("entry_add", |b| {
        let mut vault = VaultFile::open(&path, &test_password()).unwrap();
        let mut i = 0usize;
        b.iter(|| {
            vault.store_mut().add(sample_login(i));
            i += 1;
        });
    });
}

fn bench_entry_search(c: &mut Criterion) {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("bench.vclaw");
    let mut vault = VaultFile::create(&path, &test_password(), fast_kdf()).unwrap();
    for i in 0..1000 {
        vault.store_mut().add(sample_login(i));
    }
    vault.save().unwrap();

    let vault = VaultFile::open(&path, &test_password()).unwrap();
    let entries = vault.store().list();

    c.bench_function("fuzzy_search_1000_entries", |b| {
        b.iter(|| {
            let results = vaultclaw::vault::search::fuzzy_search(&entries, black_box("Service 500"));
            black_box(results.len());
        });
    });
}

fn bench_vault_save(c: &mut Criterion) {
    let mut group = c.benchmark_group("vault_save");

    for count in [10, 100, 500, 1000] {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("bench.vclaw");
        let mut vault = VaultFile::create(&path, &test_password(), fast_kdf()).unwrap();
        for i in 0..count {
            vault.store_mut().add(sample_login(i));
        }

        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, _| {
            b.iter(|| {
                vault.save().unwrap();
            });
        });
    }
    group.finish();
}

fn bench_password_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("password_gen");

    for len in [16, 32, 64, 128] {
        group.bench_with_input(BenchmarkId::from_parameter(len), &len, |b, &len| {
            b.iter(|| {
                black_box(generate_password(len));
            });
        });
    }
    group.finish();
}

fn bench_vault_crud_1000(c: &mut Criterion) {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("bench.vclaw");
    let mut vault = VaultFile::create(&path, &test_password(), fast_kdf()).unwrap();
    for i in 0..1000 {
        vault.store_mut().add(sample_login(i));
    }
    vault.save().unwrap();

    // Benchmark get by ID
    let vault = VaultFile::open(&path, &test_password()).unwrap();
    let entries = vault.store().list();
    let target_id = entries[500].id;

    c.bench_function("get_by_id_1000_entries", |b| {
        b.iter(|| {
            black_box(vault.store().get(black_box(&target_id)));
        });
    });
}

fn bench_redaction(c: &mut Criterion) {
    use vaultclaw::security::redact;

    let engine = redact::RedactionEngine::new(redact::default_patterns());
    let input = "Connect to db with password=SuperSecret123! and api_key=AKIAIOSFODNN7EXAMPLE then export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    c.bench_function("redact_text", |b| {
        b.iter(|| {
            black_box(engine.redact(black_box(input)));
        });
    });
}

fn bench_password_health(c: &mut Criterion) {
    use vaultclaw::security::health::analyze_vault_health;

    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("bench.vclaw");
    let mut vault = VaultFile::create(&path, &test_password(), fast_kdf()).unwrap();
    for i in 0..100 {
        vault.store_mut().add(sample_login(i));
    }
    vault.save().unwrap();

    let entries = vault.store().list();

    c.bench_function("health_analysis_100_entries", |b| {
        b.iter(|| {
            black_box(analyze_vault_health(black_box(&entries)));
        });
    });
}

criterion_group!(
    benches,
    bench_vault_create,
    bench_vault_open,
    bench_entry_add,
    bench_entry_search,
    bench_vault_save,
    bench_password_generation,
    bench_vault_crud_1000,
    bench_redaction,
    bench_password_health,
);
criterion_main!(benches);

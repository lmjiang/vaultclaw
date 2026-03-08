use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;

use super::entry::Entry;

/// Fuzzy search entries using the Skim algorithm.
/// Returns entries sorted by match score (best first).
pub fn fuzzy_search<'a>(entries: &'a [&'a Entry], query: &str) -> Vec<(&'a Entry, i64)> {
    let matcher = SkimMatcherV2::default();
    let mut results: Vec<(&Entry, i64)> = entries
        .iter()
        .filter_map(|entry| {
            let score = fuzzy_score(&matcher, entry, query);
            if score > 0 {
                Some((*entry, score))
            } else {
                None
            }
        })
        .collect();

    results.sort_by(|a, b| b.1.cmp(&a.1));
    results
}

fn fuzzy_score(matcher: &SkimMatcherV2, entry: &Entry, query: &str) -> i64 {
    let mut best = 0i64;

    if let Some(score) = matcher.fuzzy_match(&entry.title, query) {
        best = best.max(score);
    }

    for tag in &entry.tags {
        if let Some(score) = matcher.fuzzy_match(tag, query) {
            best = best.max(score);
        }
    }

    if let Some(cat) = &entry.category {
        if let Some(score) = matcher.fuzzy_match(cat, query) {
            best = best.max(score);
        }
    }

    match &entry.credential {
        super::entry::Credential::Login(login) => {
            if let Some(score) = matcher.fuzzy_match(&login.url, query) {
                best = best.max(score);
            }
            if let Some(score) = matcher.fuzzy_match(&login.username, query) {
                best = best.max(score);
            }
        }
        super::entry::Credential::ApiKey(api) => {
            if let Some(score) = matcher.fuzzy_match(&api.service, query) {
                best = best.max(score);
            }
        }
        _ => {}
    }

    best
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::entry::*;

    fn make_entries() -> Vec<Entry> {
        vec![
            Entry::new(
                "GitHub".to_string(),
                Credential::Login(LoginCredential {
                    url: "https://github.com".to_string(),
                    username: "octocat".to_string(),
                    password: "pass".to_string(),
                }),
            ),
            Entry::new(
                "GitLab".to_string(),
                Credential::Login(LoginCredential {
                    url: "https://gitlab.com".to_string(),
                    username: "labuser".to_string(),
                    password: "pass".to_string(),
                }),
            ),
            Entry::new(
                "Twitter".to_string(),
                Credential::Login(LoginCredential {
                    url: "https://twitter.com".to_string(),
                    username: "tweeter".to_string(),
                    password: "pass".to_string(),
                }),
            ),
            Entry::new(
                "AWS".to_string(),
                Credential::ApiKey(ApiKeyCredential {
                    service: "Amazon Web Services".to_string(),
                    key: "AKIA123".to_string(),
                    secret: "secret".to_string(),
                }),
            ),
        ]
    }

    #[test]
    fn test_fuzzy_search_exact() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();

        let results = fuzzy_search(&refs, "GitHub");
        assert!(!results.is_empty());
        assert_eq!(results[0].0.title, "GitHub");
    }

    #[test]
    fn test_fuzzy_search_partial() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();

        let results = fuzzy_search(&refs, "git");
        assert!(results.len() >= 2); // GitHub and GitLab
    }

    #[test]
    fn test_fuzzy_search_no_match() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();

        let results = fuzzy_search(&refs, "zzzzzzzzzzz");
        assert!(results.is_empty());
    }

    #[test]
    fn test_fuzzy_search_by_username() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();

        let results = fuzzy_search(&refs, "octocat");
        assert!(!results.is_empty());
        assert_eq!(results[0].0.title, "GitHub");
    }

    #[test]
    fn test_fuzzy_search_by_service() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();

        let results = fuzzy_search(&refs, "amazon");
        assert!(!results.is_empty());
        assert_eq!(results[0].0.title, "AWS");
    }

    #[test]
    fn test_fuzzy_search_sorted_by_score() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();

        let results = fuzzy_search(&refs, "git");
        // Results should be sorted by score descending
        for i in 1..results.len() {
            assert!(results[i - 1].1 >= results[i].1);
        }
    }

    #[test]
    fn test_fuzzy_search_empty_query() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();

        let results = fuzzy_search(&refs, "");
        // Empty query may or may not match depending on the matcher
        // The important thing is it doesn't crash
        let _ = results;
    }

    #[test]
    fn test_fuzzy_search_empty_entries() {
        let entries: Vec<&Entry> = vec![];
        let results = fuzzy_search(&entries, "test");
        assert!(results.is_empty());
    }

    #[test]
    fn test_fuzzy_search_by_tag() {
        let entries = [
            Entry::new(
                "NoMatch".to_string(),
                Credential::Login(LoginCredential {
                    url: "https://no.com".to_string(),
                    username: "x".to_string(),
                    password: "p".to_string(),
                }),
            ).with_tags(vec!["deployment".to_string(), "production".to_string()]),
        ];
        let refs: Vec<&Entry> = entries.iter().collect();
        let results = fuzzy_search(&refs, "production");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_fuzzy_search_by_category() {
        let entries = [
            Entry::new(
                "Something".to_string(),
                Credential::Login(LoginCredential {
                    url: "https://x.com".to_string(),
                    username: "u".to_string(),
                    password: "p".to_string(),
                }),
            ).with_category("development"),
        ];
        let refs: Vec<&Entry> = entries.iter().collect();
        let results = fuzzy_search(&refs, "development");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_fuzzy_search_secure_note_and_ssh_key() {
        let entries = [
            Entry::new(
                "MyNote".to_string(),
                Credential::SecureNote(SecureNoteCredential {
                    content: "secret".to_string(),
                }),
            ),
            Entry::new(
                "MySSH".to_string(),
                Credential::SshKey(SshKeyCredential {
                    private_key: "key".to_string(),
                    public_key: "pub".to_string(),
                    passphrase: "".to_string(),
                }),
            ),
        ];
        let refs: Vec<&Entry> = entries.iter().collect();
        // Search by title should still work
        let results = fuzzy_search(&refs, "MyNote");
        assert!(!results.is_empty());
        let results = fuzzy_search(&refs, "MySSH");
        assert!(!results.is_empty());
    }
}

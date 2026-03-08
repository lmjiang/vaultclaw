use std::collections::HashMap;

use super::entry::{Entry, EntryId};

/// In-memory vault store holding all credential entries.
#[derive(Debug, Clone, Default)]
pub struct VaultStore {
    entries: HashMap<EntryId, Entry>,
}

impl VaultStore {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn from_entries(entries: Vec<Entry>) -> Self {
        let map = entries.into_iter().map(|e| (e.id, e)).collect();
        Self { entries: map }
    }

    /// Add an entry to the store. Returns the entry ID.
    pub fn add(&mut self, entry: Entry) -> EntryId {
        let id = entry.id;
        self.entries.insert(id, entry);
        id
    }

    /// Get an entry by ID.
    pub fn get(&self, id: &EntryId) -> Option<&Entry> {
        self.entries.get(id)
    }

    /// Get a mutable reference to an entry.
    pub fn get_mut(&mut self, id: &EntryId) -> Option<&mut Entry> {
        self.entries.get_mut(id)
    }

    /// Remove an entry by ID. Returns the removed entry.
    pub fn remove(&mut self, id: &EntryId) -> Option<Entry> {
        self.entries.remove(id)
    }

    /// Update an entry. Returns true if the entry existed and was updated.
    pub fn update(&mut self, entry: Entry) -> bool {
        if let std::collections::hash_map::Entry::Occupied(mut e) = self.entries.entry(entry.id) {
            e.insert(entry);
            true
        } else {
            false
        }
    }

    /// List all entries.
    pub fn list(&self) -> Vec<&Entry> {
        let mut entries: Vec<&Entry> = self.entries.values().collect();
        entries.sort_by(|a, b| a.title.cmp(&b.title));
        entries
    }

    /// List entries filtered by category.
    pub fn list_by_category(&self, category: &str) -> Vec<&Entry> {
        let cat = category.to_lowercase();
        let mut entries: Vec<&Entry> = self
            .entries
            .values()
            .filter(|e| {
                e.category
                    .as_ref()
                    .map(|c| c.to_lowercase() == cat)
                    .unwrap_or(false)
            })
            .collect();
        entries.sort_by(|a, b| a.title.cmp(&b.title));
        entries
    }

    /// List entries filtered by tag.
    pub fn list_by_tag(&self, tag: &str) -> Vec<&Entry> {
        let t = tag.to_lowercase();
        let mut entries: Vec<&Entry> = self
            .entries
            .values()
            .filter(|e| e.tags.iter().any(|et| et.to_lowercase() == t))
            .collect();
        entries.sort_by(|a, b| a.title.cmp(&b.title));
        entries
    }

    /// List favorite entries.
    pub fn list_favorites(&self) -> Vec<&Entry> {
        let mut entries: Vec<&Entry> = self
            .entries
            .values()
            .filter(|e| e.favorite)
            .collect();
        entries.sort_by(|a, b| a.title.cmp(&b.title));
        entries
    }

    /// Search entries by query (case-insensitive, matches title, url, username, tags, category).
    pub fn search(&self, query: &str) -> Vec<&Entry> {
        let mut entries: Vec<&Entry> = self
            .entries
            .values()
            .filter(|e| e.matches(query))
            .collect();
        entries.sort_by(|a, b| a.title.cmp(&b.title));
        entries
    }

    /// Number of entries in the store.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get all entries as a Vec (for serialization).
    pub fn into_entries(self) -> Vec<Entry> {
        self.entries.into_values().collect()
    }

    /// Get all entries as a Vec (for serialization, without consuming).
    pub fn entries(&self) -> Vec<Entry> {
        self.entries.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::entry::*;

    fn login_entry(title: &str, url: &str, username: &str) -> Entry {
        Entry::new(
            title.to_string(),
            Credential::Login(LoginCredential {
                url: url.to_string(),
                username: username.to_string(),
                password: "password123".to_string(),
            }),
        )
    }

    #[test]
    fn test_add_and_get() {
        let mut store = VaultStore::new();
        let entry = login_entry("GitHub", "https://github.com", "user");
        let id = entry.id;
        store.add(entry.clone());

        let retrieved = store.get(&id).unwrap();
        assert_eq!(retrieved.title, "GitHub");
    }

    #[test]
    fn test_remove() {
        let mut store = VaultStore::new();
        let entry = login_entry("GitHub", "https://github.com", "user");
        let id = entry.id;
        store.add(entry);

        let removed = store.remove(&id).unwrap();
        assert_eq!(removed.title, "GitHub");
        assert!(store.get(&id).is_none());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_update() {
        let mut store = VaultStore::new();
        let mut entry = login_entry("GitHub", "https://github.com", "user");
        let id = entry.id;
        store.add(entry.clone());

        entry.title = "GitHub Updated".to_string();
        assert!(store.update(entry));

        assert_eq!(store.get(&id).unwrap().title, "GitHub Updated");
    }

    #[test]
    fn test_update_nonexistent() {
        let mut store = VaultStore::new();
        let entry = login_entry("X", "https://x.com", "user");
        assert!(!store.update(entry));
    }

    #[test]
    fn test_list_sorted() {
        let mut store = VaultStore::new();
        store.add(login_entry("Zebra", "https://z.com", "z"));
        store.add(login_entry("Alpha", "https://a.com", "a"));
        store.add(login_entry("Middle", "https://m.com", "m"));

        let list = store.list();
        assert_eq!(list[0].title, "Alpha");
        assert_eq!(list[1].title, "Middle");
        assert_eq!(list[2].title, "Zebra");
    }

    #[test]
    fn test_list_by_category() {
        let mut store = VaultStore::new();
        store.add(login_entry("GH", "https://gh.com", "u").with_category("dev"));
        store.add(login_entry("FB", "https://fb.com", "u").with_category("social"));
        store.add(login_entry("GL", "https://gl.com", "u").with_category("Dev"));

        let dev = store.list_by_category("dev");
        assert_eq!(dev.len(), 2);
    }

    #[test]
    fn test_list_by_tag() {
        let mut store = VaultStore::new();
        store.add(login_entry("A", "https://a.com", "u").with_tags(vec!["work".into()]));
        store.add(login_entry("B", "https://b.com", "u").with_tags(vec!["personal".into()]));
        store.add(login_entry("C", "https://c.com", "u").with_tags(vec!["Work".into(), "important".into()]));

        let work = store.list_by_tag("work");
        assert_eq!(work.len(), 2);
    }

    #[test]
    fn test_list_favorites() {
        let mut store = VaultStore::new();
        store.add(login_entry("A", "https://a.com", "u").with_favorite(true));
        store.add(login_entry("B", "https://b.com", "u"));
        store.add(login_entry("C", "https://c.com", "u").with_favorite(true));

        let favs = store.list_favorites();
        assert_eq!(favs.len(), 2);
    }

    #[test]
    fn test_search() {
        let mut store = VaultStore::new();
        store.add(login_entry("GitHub", "https://github.com", "octocat"));
        store.add(login_entry("GitLab", "https://gitlab.com", "labuser"));
        store.add(login_entry("Twitter", "https://twitter.com", "tweeter"));

        let results = store.search("git");
        assert_eq!(results.len(), 2);

        let results = store.search("octocat");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_from_entries() {
        let entries = vec![
            login_entry("A", "https://a.com", "u"),
            login_entry("B", "https://b.com", "u"),
        ];
        let store = VaultStore::from_entries(entries);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_into_entries() {
        let mut store = VaultStore::new();
        store.add(login_entry("A", "https://a.com", "u"));
        store.add(login_entry("B", "https://b.com", "u"));

        let entries = store.into_entries();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_empty_store() {
        let store = VaultStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert!(store.list().is_empty());
    }

    #[test]
    fn test_get_mut() {
        let mut store = VaultStore::new();
        let entry = login_entry("Test", "https://test.com", "u");
        let id = entry.id;
        store.add(entry);

        let e = store.get_mut(&id).unwrap();
        e.favorite = true;

        assert!(store.get(&id).unwrap().favorite);
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut store = VaultStore::new();
        assert!(store.remove(&uuid::Uuid::new_v4()).is_none());
    }
}

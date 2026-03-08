use std::io;
use clap::CommandFactory;
use clap_complete::{Shell, generate};

use super::Cli;

/// Generate shell completions and write to stdout.
pub fn generate_completions(shell: Shell) {
    let mut cmd = Cli::command();
    generate(shell, &mut cmd, "vaultclaw", &mut io::stdout());
}

/// Generate a man page and write to stdout.
pub fn generate_manpage() -> anyhow::Result<()> {
    let cmd = Cli::command();
    let man = clap_mangen::Man::new(cmd);
    let mut buf = Vec::new();
    man.render(&mut buf)?;
    io::Write::write_all(&mut io::stdout(), &buf)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_completions_bash() {
        // Verify that completion generation doesn't panic for each shell
        let mut cmd = Cli::command();
        let mut buf = Vec::new();
        generate(Shell::Bash, &mut cmd, "vaultclaw", &mut buf);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("vaultclaw"));
    }

    #[test]
    fn test_generate_completions_zsh() {
        let mut cmd = Cli::command();
        let mut buf = Vec::new();
        generate(Shell::Zsh, &mut cmd, "vaultclaw", &mut buf);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("vaultclaw"));
    }

    #[test]
    fn test_generate_completions_fish() {
        let mut cmd = Cli::command();
        let mut buf = Vec::new();
        generate(Shell::Fish, &mut cmd, "vaultclaw", &mut buf);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("vaultclaw"));
    }

    #[test]
    fn test_generate_completions_powershell() {
        let mut cmd = Cli::command();
        let mut buf = Vec::new();
        generate(Shell::PowerShell, &mut cmd, "vaultclaw", &mut buf);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("vaultclaw"));
    }

    #[test]
    fn test_generate_completions_elvish() {
        let mut cmd = Cli::command();
        let mut buf = Vec::new();
        generate(Shell::Elvish, &mut cmd, "vaultclaw", &mut buf);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("vaultclaw"));
    }

    #[test]
    fn test_generate_manpage() {
        let cmd = Cli::command();
        let man = clap_mangen::Man::new(cmd);
        let mut buf = Vec::new();
        man.render(&mut buf).unwrap();
        let output = String::from_utf8_lossy(&buf);
        // Man pages contain the command name in troff format
        assert!(output.contains("vaultclaw"));
    }

    #[test]
    fn test_completions_contain_subcommands() {
        // Verify that generated completions reference known subcommands
        let mut cmd = Cli::command();
        let mut buf = Vec::new();
        generate(Shell::Bash, &mut cmd, "vaultclaw", &mut buf);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("init"));
        assert!(output.contains("get"));
        assert!(output.contains("add"));
        assert!(output.contains("search"));
    }

    #[test]
    fn test_manpage_contains_description() {
        let cmd = Cli::command();
        let man = clap_mangen::Man::new(cmd);
        let mut buf = Vec::new();
        man.render(&mut buf).unwrap();
        let output = String::from_utf8_lossy(&buf);
        // Should contain the program description from clap
        assert!(output.contains("credential"));
    }
}

//! Result collection.
//!
//! The run does not stop at the first failure: one broken endpoint should not
//! hide the state of the other forty. Every check prints its verdict as it
//! happens and is tallied for a summary, and the process exits non-zero if
//! anything failed — which is what makes this usable from a script.

use std::fmt::Write as _;

pub struct Report {
    group: String,
    rows: Vec<Row>,
}

struct Row {
    group: String,
    name: String,
    outcome: Outcome,
}

enum Outcome {
    Pass,
    Fail(String),
    Skip(String),
}

impl Report {
    pub fn new() -> Self {
        Self {
            group: String::new(),
            rows: Vec::new(),
        }
    }

    /// Starts a section. Purely presentational — checks carry their group with
    /// them, so a group with nothing in it still shows up in the summary.
    pub fn group(&mut self, name: &str) {
        self.group = name.to_string();
        println!("\n== {name}");
    }

    /// Runs a check that produces something later checks need.
    ///
    /// `None` back means it failed and the caller should skip whatever
    /// depended on it, rather than reporting a cascade of failures that all
    /// have the same cause.
    pub fn probe<T>(&mut self, name: &str, f: impl FnOnce() -> Result<T, String>) -> Option<T> {
        match f() {
            Ok(value) => {
                println!("  ok    {name}");
                self.push(name, Outcome::Pass);
                Some(value)
            }
            Err(why) => {
                println!("  FAIL  {name}: {why}");
                self.push(name, Outcome::Fail(why));
                None
            }
        }
    }

    pub fn check(&mut self, name: &str, f: impl FnOnce() -> Result<(), String>) -> bool {
        self.probe(name, f).is_some()
    }

    /// Records a check that could not run, with the reason. A skip is not a
    /// pass: the summary counts it separately so a run that quietly covered
    /// half the surface cannot read as a clean one.
    pub fn skip(&mut self, name: &str, why: &str) {
        println!("  skip  {name}: {why}");
        self.push(name, Outcome::Skip(why.to_string()));
    }

    pub fn skip_group(&mut self, group: &str, why: &str) {
        self.group(group);
        self.skip("(whole group)", why);
    }

    fn push(&mut self, name: &str, outcome: Outcome) {
        self.rows.push(Row {
            group: self.group.clone(),
            name: name.to_string(),
            outcome,
        });
    }

    /// Prints the summary and returns the process exit code.
    pub fn finish(&self) -> i32 {
        let mut groups: Vec<&str> = Vec::new();
        for row in &self.rows {
            if !groups.contains(&row.group.as_str()) {
                groups.push(&row.group);
            }
        }

        println!("\n== summary");
        let mut failures = String::new();
        let mut skips = String::new();
        let (mut all_pass, mut all_fail, mut all_skip) = (0, 0, 0);
        for group in groups {
            let (mut pass, mut fail, mut skip) = (0, 0, 0);
            for row in self.rows.iter().filter(|row| row.group == group) {
                match &row.outcome {
                    Outcome::Pass => pass += 1,
                    Outcome::Fail(why) => {
                        fail += 1;
                        let _ = writeln!(failures, "  {group} / {}: {why}", row.name);
                    }
                    Outcome::Skip(why) => {
                        skip += 1;
                        let _ = writeln!(skips, "  {group} / {}: {why}", row.name);
                    }
                }
            }
            all_pass += pass;
            all_fail += fail;
            all_skip += skip;
            let skipped = if skip > 0 {
                format!(", {skip} skipped")
            } else {
                String::new()
            };
            println!("  {group:<14} {pass} passed, {fail} failed{skipped}");
        }
        println!(
            "  {:<14} {all_pass} passed, {all_fail} failed, {all_skip} skipped",
            "TOTAL"
        );

        // What did not run is part of the verdict: a run that quietly covered
        // half the surface must not read as a clean one.
        if all_skip > 0 {
            println!("\nnot run:\n{skips}");
        }
        if all_fail > 0 {
            println!("failures:\n{failures}");
            return 1;
        }
        println!("all checks passed");
        0
    }
}

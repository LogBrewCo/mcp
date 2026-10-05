use super::TextBudget;
use crate::Result;

#[test]
/// # Errors
/// Propagates admission failures for the valid boundary inputs.
///
/// # Panics
/// Panics if text-count or encoded-byte boundaries differ from the expected values.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn load_text_budget_counts_json_escaping_and_combined_fields() -> Result<()> {
    let mut escaped_budget = TextBudget::default();
    let escaped = "\u{0001}".repeat(1366);
    let _escaped_error: Box<dyn std::error::Error> = escaped_budget
        .strings(std::iter::once(escaped.as_str()))
        .expect_err("input must be rejected");
    let mut boundary_budget = TextBudget::default();
    let boundary = "a".repeat(4094);
    assert_eq!(
        boundary_budget
            .strings(std::iter::once(boundary.as_str()))?
            .len(),
        1
    );
    assert_eq!(
        boundary_budget
            .strings(std::iter::once(boundary.as_str()))?
            .len(),
        1
    );
    let _boundary_error: Box<dyn std::error::Error> = boundary_budget
        .strings(std::iter::once("more"))
        .expect_err("input must be rejected");
    let mut budget = TextBudget::default();
    assert_eq!(budget.strings(std::iter::repeat_n("a", 256))?.len(), 256);
    let _error: Box<dyn std::error::Error> = budget
        .strings(std::iter::once("a"))
        .expect_err("input must be rejected");
    Ok(())
}

#[test]
fn load_text_rejects_empty_control_and_oversized_values() {
    for value in ["", "library\0path", "library\npath", "library\rpath"] {
        let _error: Box<dyn std::error::Error> = TextBudget::default()
            .strings(std::iter::once(value))
            .expect_err("input must be rejected");
    }
    let long = "a".repeat(4097);
    let _error: Box<dyn std::error::Error> = TextBudget::default()
        .strings(std::iter::once(long.as_str()))
        .expect_err("input must be rejected");
}

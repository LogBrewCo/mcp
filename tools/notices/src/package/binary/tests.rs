use super::TextBudget;
use crate::Result;

#[test]
fn load_text_budget_counts_json_escaping_and_combined_fields() -> Result<()> {
    let mut budget = TextBudget::default();
    let escaped = "\u{0001}".repeat(1366);
    assert!(budget.strings(std::iter::once(escaped.as_str())).is_err());
    let mut budget = TextBudget::default();
    let boundary = "a".repeat(4094);
    assert_eq!(budget.strings(std::iter::once(boundary.as_str()))?.len(), 1);
    assert_eq!(budget.strings(std::iter::once(boundary.as_str()))?.len(), 1);
    assert!(budget.strings(std::iter::once("more")).is_err());
    let mut budget = TextBudget::default();
    assert_eq!(budget.strings(std::iter::repeat_n("a", 256))?.len(), 256);
    assert!(budget.strings(std::iter::once("a")).is_err());
    Ok(())
}

#[test]
fn load_text_rejects_empty_control_and_oversized_values() {
    for value in ["", "library\0path", "library\npath", "library\rpath"] {
        assert!(
            TextBudget::default()
                .strings(std::iter::once(value))
                .is_err()
        );
    }
    let long = "a".repeat(4097);
    assert!(
        TextBudget::default()
            .strings(std::iter::once(long.as_str()))
            .is_err()
    );
}

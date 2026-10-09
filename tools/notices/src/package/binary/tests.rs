use super::{TextBudget, requirements};
use crate::Result;
use crate::package::Target;

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
    let _escaped_error: Box<dyn core::error::Error> = escaped_budget
        .strings(core::iter::once(escaped.as_str()))
        .expect_err("input must be rejected");
    let mut boundary_budget = TextBudget::default();
    let boundary = "a".repeat(4094);
    assert_eq!(
        boundary_budget
            .strings(core::iter::once(boundary.as_str()))?
            .len(),
        1
    );
    assert_eq!(
        boundary_budget
            .strings(core::iter::once(boundary.as_str()))?
            .len(),
        1
    );
    let _boundary_error: Box<dyn core::error::Error> = boundary_budget
        .strings(core::iter::once("more"))
        .expect_err("input must be rejected");
    let mut budget = TextBudget::default();
    assert_eq!(budget.strings(core::iter::repeat_n("a", 256))?.len(), 256);
    let _error: Box<dyn core::error::Error> = budget
        .strings(core::iter::once("a"))
        .expect_err("input must be rejected");
    Ok(())
}

#[test]
fn load_text_rejects_empty_control_and_oversized_values() {
    for value in ["", "library\0path", "library\npath", "library\rpath"] {
        let _error: Box<dyn core::error::Error> = TextBudget::default()
            .strings(core::iter::once(value))
            .expect_err("input must be rejected");
    }
    let long = "a".repeat(4097);
    let _error: Box<dyn core::error::Error> = TextBudget::default()
        .strings(core::iter::once(long.as_str()))
        .expect_err("input must be rejected");
}

/// # Errors
/// Rejects a fixture field outside its buffer or an overflowing field extent.
fn field(input: &mut [u8], offset: usize, value: &[u8]) -> Result<()> {
    let end = offset
        .checked_add(value.len())
        .ok_or("fixture extent overflow")?;
    input
        .get_mut(offset..end)
        .ok_or("missing fixture field")?
        .copy_from_slice(value);
    Ok(())
}

/// # Errors
/// Propagates bounded fixture-field writes.
fn elf(target: Target, kind: u16) -> Result<Vec<u8>> {
    let mut input = vec![0; 128];
    let machine = if matches!(target, Target::LinuxArm) {
        183_u16
    } else {
        62_u16
    };
    for (offset, value) in [
        (0, b"\x7fELF\x02\x01\x01".to_vec()),
        (16, kind.to_le_bytes().to_vec()),
        (18, machine.to_le_bytes().to_vec()),
        (20, 1_u32.to_le_bytes().to_vec()),
        (24, 0x40_0078_u64.to_le_bytes().to_vec()),
        (32, 64_u64.to_le_bytes().to_vec()),
        (52, 64_u16.to_le_bytes().to_vec()),
        (54, 56_u16.to_le_bytes().to_vec()),
        (56, 1_u16.to_le_bytes().to_vec()),
        (64, 1_u32.to_le_bytes().to_vec()),
        (68, 5_u32.to_le_bytes().to_vec()),
        (80, 0x40_0000_u64.to_le_bytes().to_vec()),
        (96, 128_u64.to_le_bytes().to_vec()),
        (104, 128_u64.to_le_bytes().to_vec()),
        (112, 4096_u64.to_le_bytes().to_vec()),
    ] {
        field(&mut input, offset, &value)?;
    }
    Ok(input)
}

#[test]
/// # Errors
/// Propagates valid fixture construction and executable metadata parsing.
///
/// # Panics
/// Panics if absent, nonexecutable, truncated or overflowing entry mappings pass.
fn elf_entry_requires_file_backed_executable_code() -> Result<()> {
    for (target, kind) in [
        (Target::LinuxArm, 2_u16),
        (Target::LinuxArm, 3_u16),
        (Target::LinuxX86, 2_u16),
        (Target::LinuxX86, 3_u16),
    ] {
        let valid = elf(target, kind)?;
        let _initial_report = requirements(target, &valid)?;
        for (offset, value) in [
            (24, 0_u64.to_le_bytes().to_vec()),
            (24, 0x40_0080_u64.to_le_bytes().to_vec()),
            (68, 4_u32.to_le_bytes().to_vec()),
            (80, 0x40_0100_u64.to_le_bytes().to_vec()),
            (96, 0_u64.to_le_bytes().to_vec()),
            (96, 129_u64.to_le_bytes().to_vec()),
            (72, 1_u64.to_le_bytes().to_vec()),
            (72, u64::MAX.to_le_bytes().to_vec()),
            (80, (u64::MAX - 4).to_le_bytes().to_vec()),
            (104, u64::MAX.to_le_bytes().to_vec()),
        ] {
            let mut invalid = valid.clone();
            field(&mut invalid, offset, &value)?;
            let _error: Box<dyn core::error::Error> = requirements(target, &invalid)
                .expect_err("invalid executable mapping must be rejected");
        }
        for entry in [0x40_0000_u64, 0x40_007f] {
            let mut boundary = valid.clone();
            field(&mut boundary, 24, &entry.to_le_bytes())?;
            let _boundary_report = requirements(target, &boundary)?;
        }
    }
    Ok(())
}

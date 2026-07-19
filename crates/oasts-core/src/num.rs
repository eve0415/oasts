//! ECMAScript-compatible decimal rendering used by enum-name allocation.

/// Renders a finite binary64 value using ECMAScript's decimal/exponent cutovers.
///
/// Ryū supplies the shortest round-tripping digits. This function only changes
/// their layout: decimal notation is used for `1e-6 <= abs(value) < 1e21`, and
/// exponent notation with a lowercase `e` and explicit sign is used otherwise.
#[must_use]
pub fn render_number(value: f64) -> String {
    if value == 0.0 {
        return "0".to_owned();
    }
    debug_assert!(value.is_finite());

    let negative = value.is_sign_negative();
    let absolute = value.abs();
    let mut buffer = ryu::Buffer::new();
    let raw = buffer.format_finite(absolute);
    let parts = DecimalParts::parse(raw);
    let body = if (1e-6..1e21).contains(&absolute) {
        parts.decimal()
    } else {
        parts.scientific()
    };
    if negative { format!("-{body}") } else { body }
}

struct DecimalParts {
    digits: String,
    point: i32,
}

impl DecimalParts {
    fn parse(raw: &str) -> Self {
        let (mantissa, exponent) =
            raw.split_once(['e', 'E'])
                .map_or((raw, 0), |(mantissa, exponent)| {
                    let parsed = exponent.parse::<i32>().unwrap_or(0);
                    (mantissa, parsed)
                });
        let decimal_index = mantissa.find('.').map_or(mantissa.len(), |index| index);
        let digits = mantissa
            .chars()
            .filter(|character| *character != '.')
            .collect();
        let point = i32::try_from(decimal_index)
            .unwrap_or(i32::MAX)
            .saturating_add(exponent);
        Self { digits, point }
    }

    fn decimal(&self) -> String {
        let mut rendered = if self.point <= 0 {
            let zeros = usize::try_from(-self.point).unwrap_or(usize::MAX);
            format!("0.{}{}", "0".repeat(zeros), self.digits)
        } else {
            let point = usize::try_from(self.point).unwrap_or(usize::MAX);
            if point >= self.digits.len() {
                format!("{}{}", self.digits, "0".repeat(point - self.digits.len()))
            } else {
                format!("{}.{}", &self.digits[..point], &self.digits[point..])
            }
        };
        if rendered.contains('.') {
            while rendered.ends_with('0') {
                rendered.pop();
            }
            if rendered.ends_with('.') {
                rendered.pop();
            }
        }
        rendered
    }

    fn scientific(&self) -> String {
        let first_nonzero = self
            .digits
            .bytes()
            .position(|digit| digit != b'0')
            .unwrap_or(0);
        let mut significant = self.digits[first_nonzero..].to_owned();
        while significant.len() > 1 && significant.ends_with('0') {
            significant.pop();
        }
        let exponent = self
            .point
            .saturating_sub(i32::try_from(first_nonzero).unwrap_or(i32::MAX))
            .saturating_sub(1);
        let (first, rest) = significant.split_at(1);
        let mantissa = if rest.is_empty() {
            first.to_owned()
        } else {
            format!("{first}.{rest}")
        };
        format!("{mantissa}e{exponent:+}")
    }
}

#[cfg(test)]
mod tests {
    use super::{DecimalParts, render_number};

    #[test]
    fn matches_node_string_boundary_vectors() {
        // These expected strings were verified against Node's `String(value)`.
        let vectors = [
            (0.0, "0"),
            (-0.0, "0"),
            (1.0, "1"),
            (-1.5, "-1.5"),
            (1e21, "1e+21"),
            (0.000_001, "0.000001"),
            (0.000_000_1, "1e-7"),
            (123_456_789_012_345_680_000.0, "123456789012345680000"),
            (9_007_199_254_740_991.0, "9007199254740991"),
            (1e-7, "1e-7"),
            (5e-324, "5e-324"),
            (1.797_693_134_862_315_7e308, "1.7976931348623157e+308"),
        ];
        for (value, expected) in vectors {
            assert_eq!(render_number(value), expected, "{value:?}");
        }
    }

    #[test]
    fn scientific_rendering_trims_trailing_zeroes() {
        let parts = DecimalParts {
            digits: "1200".to_owned(),
            point: 9,
        };
        assert_eq!(parts.scientific(), "1.2e+8");
    }
}

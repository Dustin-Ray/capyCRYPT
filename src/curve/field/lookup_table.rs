#![allow(non_snake_case)]

use crypto_bigint::subtle::{ConditionallySelectable, ConstantTimeEq};

use crate::curve::{extended_edwards::ExtendedCurvePoint, projective_niels::ProjectiveNielsPoint};

pub struct LookupTable([ProjectiveNielsPoint; 8]);

/// Precomputes odd multiples of the point passed in
impl From<&ExtendedCurvePoint> for LookupTable {
    fn from(point: &ExtendedCurvePoint) -> LookupTable {
        let P = point.to_extensible();

        let mut table = [P.to_projective_niels(); 8];

        for i in 1..8 {
            table[i] = P.add_projective_niels(&table[i - 1]).to_projective_niels();
        }

        LookupTable(table)
    }
}

impl LookupTable {
    /// Selects a projective niels point from a lookup table in constant time
    pub fn select(&self, index: u32) -> ProjectiveNielsPoint {
        let mut result = ProjectiveNielsPoint::id_point();

        for i in 1..9 {
            let swap = index.ct_eq(&(i as u32));
            result.conditional_assign(&self.0[i - 1], swap);
        }
        result
    }
}

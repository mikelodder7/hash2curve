//! Implements hash to curve as described in Section 8.7.1 of
//! <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
//! and Section 5 of
//!  <https://eprint.iacr.org/2019/403.pdf>


use crate::{DomainSeparationTag, expand_message_xmd};
use crate::error::HashingError;
use crate::isogeny::bls381g1::*;
use crate::HashToCurve;
use amcl_miracl::{arch::CHUNK, bls381::{big::BIG, dbig::DBIG, fp::FP, ecp::ECP}};
use digest::{
    Digest,
    BlockInput,
    generic_array::{
        GenericArray,
        ArrayLength,
        typenum::{
            U32,
            U64,
            U128,
            marker_traits::Unsigned
        }
    }
};
use std::cmp::Ordering;

/// To compute a `L` use the following formula
/// L = ceil(ceil(log2(p) + k) / 8). For example, in our case log2(p) = 381, k = 128
/// L = 64
type L = U64;
type TWO_L = U128;
const MODULUS: BIG = BIG { w: amcl_miracl::bls381::rom::MODULUS };
const PM1DIV2: BIG = BIG { w: [71916856549561685, 108086211381297143, 186063435852751093, 218960087668936289, 225643796693662629, 229680090418738422, 3490221905] };
const H_EFF: BIG = BIG { w: [144396663052632065, 52, 0, 0, 0, 0, 0] };
const C1: BIG = BIG { w: [132416828320029820, -36241730206030966, -183175740354038500, -108808289511770161, 19716962043635886, 150180602526288156, 2033276157 ] };
const C2: BIG = BIG { w: [170292360909944894, 176868607242987704, 7626954141253676, 39810925030715689, 14823383385055774, 15557254971433191, 634585801] };
const SQRT_C1: BIG = BIG {w: [ 180073616350636715, 198158293766504443, 237146906002231418, 253595231910324016, 112821898346831314, 258955233285225083, 1745110952 ]};
const C1_PM3D4: BIG = BIG { w: [180073616350636714, 198158293766504443, 237146906002231418, 253595231910324016, 112821898346831314, 258955233285225083, 1745110952] };
const C2_PM3D4: BIG = BIG { w: [143833713099122040, 216172422762594286, 83896495553790442, 149689799186160835, 163057217235613515, 171129804685765101, 6980443811] };

/// BLS12381G1_XMD:SHA-256_SSWU provides both
/// Random Oracle (RO)
/// Nonuniform (NU)
pub struct Bls12381G1XmdSha256Sswu {
    dst: DomainSeparationTag
}

impl Bls12381G1XmdSha256Sswu {
    /// Create a new implementation with the default
    pub fn new() -> Self {
        Self {
            dst: DomainSeparationTag::new("BLS12381G1_XMD:SHA-256_SSWU_", Some("0_0_1"), None, None).unwrap(),
        }
    }
}

impl From<DomainSeparationTag> for Bls12381G1XmdSha256Sswu {
    fn from(dst: DomainSeparationTag) -> Self {
        Self { dst }
    }
}

impl HashToCurve for Bls12381G1XmdSha256Sswu {
    type Output = ECP;

    fn encode_to_curve<I: AsRef<[u8]>>(&self, data: I) -> Result<Self::Output, HashingError> {
        let u = hash_to_field_xmd_1::<sha2::Sha256, I>(data, &self.dst)?;
        let q = map_to_curve(u);
        let p = clear_cofactor(q);
        Ok(p)
    }

    fn hash_to_curve<I: AsRef<[u8]>>(&self, data: I) -> Result<Self::Output, HashingError> {
        let (u0, u1) = hash_to_field_xmd_2::<sha2::Sha256, I>(data, &self.dst)?;
        let mut q0 = map_to_curve(u0);
        let q1 = map_to_curve(u1);
        q0.add(&q1);
        let p = clear_cofactor(q0);
        Ok(p)
    }
}

fn clear_cofactor(p: ECP) -> ECP {
    p.mul(&H_EFF)
}

fn map_to_curve(u: BIG) -> ECP {
    let (mut x, mut y) = map_to_curve_simple_swu(u);
    iso_map(x, y)
}

/// See Section 6.6.2.1 in
/// <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
fn map_to_curve_3mod4(u: BIG) -> ECP {
    let (mut x, mut y) = map_to_curve_simple_swu_3mod4(u);
    iso_map(x, y)
}

/// See Section 6.6.2.1 in
/// <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
fn map_to_curve_simple_swu(u: BIG) -> (BIG, BIG) {
    // tv1 = Z * u^2
    let mut tv1 = BIG::modmul(&Z, &BIG::modsqr(&u, &MODULUS), &MODULUS);
    // tv2 = tv1^2
    let mut tv2 = BIG::modsqr(&tv1, &MODULUS);

    // x1 = tv1 + tv2
    let mut x1 = BIG::new_big(&tv1);
    x1.add(&tv2);
    x1.rmod(&MODULUS);

    // x1 = inv0(x1)
    x1.invmodp(&MODULUS);

    let e1 = if x1.iszilch() { 1 } else{ 0 };

    // x1 = x1 + 1
    x1.inc(1);

    // x1 = CMOV(x1, c2, e1)
    x1.cmove(&C2, e1);

    // x1 = x1 * c1
    x1 = BIG::modmul(&x1, &C1, &MODULUS);

    // gx1 = x1^2
    let mut gx1 = BIG::modsqr(&x1, &MODULUS);
    // gx1 = gx1 + A
    gx1.add(&ISO_A);
    gx1.rmod(&MODULUS);

    // gx1 = gx1 * x1
    gx1 = BIG::modmul(&gx1, &x1, &MODULUS);

    // gx1 = gx1 + B
    gx1.add(&ISO_B);
    gx1.rmod(&MODULUS);

    // x2 = tv1 * x1
    let mut x2 = BIG::modmul(&tv1, &x1, &MODULUS);

    // tv2 = tv1 * tv2
    tv2 = BIG::modmul(&tv1, &tv2, &MODULUS);

    // gx2 = gx1 * tv2
    let mut gx2 = BIG::modmul(&gx1, &tv2, &MODULUS);

    // e2 = is_square(gx1)
    let e2 = if is_square(&gx1) { 1 } else { 0 };

    // x = CMOV(x2, x1, e2)
    let mut x = BIG::new_copy(&x2);
    x.cmove(&x1, e2);

    // y2 = CMOV(gx2, gx1, e2)
    let mut y2 = BIG::new_copy(&gx2);
    y2.cmove(&gx1, e2);

    // y = sqrt(y2)
    let mut y = sqrt_3mod4(&y2);

    // e3 = sgn0(u) == sgn0(y)
    let e3 = if sgn0(&u) == sgn0(&y) { 1 } else { 0 };

    // y = CMOV(-y, y, e3)
    let mut y_neg = BIG::modneg(&y, &MODULUS);
    y_neg.cmove(&y, e3);

    (x, y_neg)
}

/// Section F.1 in
///
fn sqrt_3mod4(x: &BIG) -> BIG {
    let mut t = BIG::new_big(x);
    t.powmod(&SQRT_C1, &MODULUS)
}

/// is_square(x) := { True,  if x^((q - 1) / 2) is 0 or 1 in F;
///                 { False, otherwise.
fn is_square(x: &BIG) -> bool {
    let mut t = BIG::new_copy(x);
    t = t.powmod(&PM1DIV2, &MODULUS);
    let mut sum = 0;
    for i in 1..t.w.len() {
        sum |= t.w[i];
    }
    sum == 0 && (t.w[0] == 0 || t.w[0] == 1)
}

/// Simplified SWU for AB == 0 as described in Section 6.6.3 in
/// <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
fn map_to_curve_simple_swu_3mod4(u: BIG) -> (BIG, BIG) {
    let mut tv1 = BIG::modsqr(&u, &MODULUS);
    let mut tv3 = BIG::modmul(&tv1, &Z, &MODULUS);
    let mut tv2 = BIG::modsqr(&tv3, &MODULUS);

    let mut xd = BIG::new_copy(&tv2);
    xd.add(&tv3);
    xd.rmod(&MODULUS);

    let mut x1n = BIG::new_copy(&xd);
    x1n.inc(1);
    x1n = BIG::modmul(&ISO_B, &x1n, &MODULUS);

    xd = BIG::modmul(&xd, &BIG::modneg(&ISO_A, &MODULUS), &MODULUS);

    let e1 = if xd.iszilch() { 1 } else { 0 };

    let z_a = BIG::modmul(&Z, &ISO_A, &MODULUS);

    xd.cmove(&z_a, e1);

    tv2 = BIG::modsqr(&xd, &MODULUS);

    let mut gxd = BIG::modmul(&tv2, &ISO_A, &MODULUS);

    tv2 = BIG::modmul(&ISO_A, &tv2, &MODULUS);

    let mut gx1 = BIG::modsqr(&x1n, &MODULUS);
    gx1.add(&tv2);
    gx1.rmod(&MODULUS);

    gx1 = BIG::modmul(&x1n, &gx1, &MODULUS);

    tv2 = BIG::modmul(&gxd, &ISO_B, &MODULUS);

    gx1.add(&tv2);
    gx1.rmod(&MODULUS);

    let mut tv4 = BIG::modsqr(&gxd, &MODULUS);

    tv2 = BIG::modmul(&gx1, &gxd, &MODULUS);

    tv4 = BIG::modmul(&tv4, &tv2, &MODULUS);

    let mut y1 = BIG::new_copy(&tv4);
    y1 = y1.powmod(&C1_PM3D4, &MODULUS);
    y1 = BIG::modmul(&y1, &tv2, &MODULUS);

    let mut x2n = BIG::modmul(&tv3, &x1n, &MODULUS);

    let mut y2 = BIG::modmul(&y1, &C2_PM3D4, &MODULUS);

    y2 = BIG::modmul(&y2, &tv1, &MODULUS);

    y2 = BIG::modmul(&y2, &u, &MODULUS);

    tv2 = BIG::modsqr(&y1, &MODULUS);

    tv2 = BIG::modmul(&tv2, &gxd, &MODULUS);
    let e2 = if tv2 == gx1 { 1 } else { 0 };

    let mut xn = BIG::new_copy(&x2n);
    xn.cmove(&x1n, e2);

    let mut y = BIG::new_copy(&y2);
    y.cmove(&y1, e2 as isize);

    let e3 = if sgn0(&u) == sgn0(&y) { 1 } else { 0 };

    let mut neg_y = BIG::modneg(&y, &MODULUS);
    neg_y.cmove(&y, e3 as isize);

    xn.div(&xd);

    (xn, neg_y)
}

/// See Section 4.1 in
/// <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
fn sgn0(x: &BIG) -> Ordering {
    if *x > PM1DIV2 {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

/// See Section 4.3 in
/// <https://eprint.iacr.org/2019/403.pdf>
fn iso_map(x_prime: BIG, y_prime: BIG) -> ECP {
    let mut x_values: [BIG; 16] = [BIG::new(); 16];
    x_values[0]  = BIG::new_int(1);
    x_values[1]  = x_prime;
    x_values[2]  = BIG::modsqr(&x_prime, &MODULUS);
    x_values[3]  = BIG::modmul(&x_values[2], &x_prime, &MODULUS);
    x_values[4]  = BIG::modmul(&x_values[3], &x_prime, &MODULUS);
    x_values[5]  = BIG::modmul(&x_values[4], &x_prime, &MODULUS);
    x_values[6]  = BIG::modmul(&x_values[5], &x_prime, &MODULUS);
    x_values[7]  = BIG::modmul(&x_values[6], &x_prime, &MODULUS);
    x_values[8]  = BIG::modmul(&x_values[7], &x_prime, &MODULUS);
    x_values[9]  = BIG::modmul(&x_values[8], &x_prime, &MODULUS);
    x_values[10] = BIG::modmul(&x_values[9], &x_prime, &MODULUS);
    x_values[11] = BIG::modmul(&x_values[10], &x_prime, &MODULUS);
    x_values[12] = BIG::modmul(&x_values[11], &x_prime, &MODULUS);
    x_values[13] = BIG::modmul(&x_values[12], &x_prime, &MODULUS);
    x_values[14] = BIG::modmul(&x_values[13], &x_prime, &MODULUS);
    x_values[15] = BIG::modmul(&x_values[14], &x_prime, &MODULUS);

    let mut x = iso_map_helper(&x_values, &X_NUM);
    let mut x_den = iso_map_helper(&x_values, &X_DEN);
    let mut y = iso_map_helper(&x_values, &Y_NUM);
    let mut y_den = iso_map_helper(&x_values, &Y_DEN);

    x_den.invmodp(&MODULUS);
    x = BIG::modmul(&x, &x_den, &MODULUS);

    y_den.invmodp(&MODULUS);
    y = BIG::modmul(&y, &y_den, &MODULUS);
    y = BIG::modmul(&y, &y_prime, &MODULUS);

    println!("q.x = {}", x.to_hex());
    println!("q.y = {}", y.to_hex());
    ECP::new_bigs(&x, &y)
}

/// Compute a section of iso map
fn iso_map_helper(x: &[BIG], k: &[BIG]) -> BIG {
    let mut new_x = BIG::new();
    for i in 0..k.len() {
        let t = BIG::modmul(&x[i], &k[i], &MODULUS);
        new_x.add(&t);
        new_x.rmod(&MODULUS);
    }
    new_x
}

/// Hash to field using expand_message_xmd to compute two `u`s as specified in Section 5.2 in
/// <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
fn hash_to_field_xmd_1<D: BlockInput + Digest<OutputSize = U32>, M: AsRef<[u8]>>(msg: M, dst: &DomainSeparationTag) -> Result<BIG, HashingError> {
    // length_in_bytes = count * m * L = 1 * 1 * 64 = 64
    let random_bytes = expand_message_xmd::<M, D, L>(msg, dst)?;
    // elm_offset = L * (j + i * m) = 64 * (0 + 0 * 1) = 0
    // tv = substr(random_bytes, 0, 64)
    Ok(field_elem_from_larger_bytearray(random_bytes.as_slice()))
}

/// Hash to field using expand_message_xmd to compute two `u`s as specified in Section 5.2 in
/// <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
///
/// We avoid the loop and get compile time checking this way
fn hash_to_field_xmd_2<D: BlockInput + Digest<OutputSize = U32>, M: AsRef<[u8]>>(msg: M, dst: &DomainSeparationTag) -> Result<(BIG, BIG), HashingError> {
    // length_in_bytes = count * m * L = 2 * 1 * 64 = 128
    let random_bytes = expand_message_xmd::<M, D, TWO_L>(msg, dst)?;
    // elm_offset_0 = L * (j + i * m) = 64 * (0 + 0 * 1) = 0
    // elm_offset_1 = L * (j + i * m) = 64 * (0 + 1 * 1) = 64
    // tv_0 = substr(random_bytes, 0, 64)
    // tv_1 = substr(random_bytes, 64, 64)
    let mut u_0 = field_elem_from_larger_bytearray(&random_bytes[0..L::to_usize()]);
    let mut u_1 = field_elem_from_larger_bytearray(&random_bytes[L::to_usize()..]);
    println!("u0 = {}", u_0.to_hex());
    println!("u1 = {}", u_1.to_hex());
    Ok((u_0, u_1))
}

/// FIELD_ELEMENT_SIZE <= random_bytes.len() <= FIELD_ELEMENT_SIZE * 2
fn field_elem_from_larger_bytearray(random_bytes: &[u8]) -> BIG {
    // e_j = OS2IP(tv) mod p
    let mut d = DBIG::new();
    for i in 0..random_bytes.len() {
        d.shl(8);
        d.w[0] += random_bytes[i] as amcl_miracl::arch::Chunk;
    }
    // u = (e_0, ..., e_( m - 1 ) )
    let u = d.dmod(&MODULUS);
    u
}

#[cfg(test)]
mod tests {
    use crate::{DomainSeparationTag, HashToCurve};
    use crate::bls381g1::{hash_to_field_xmd_1, hash_to_field_xmd_2, map_to_curve, Bls12381G1XmdSha256Sswu};
    use amcl_miracl::bls381::{big::BIG, ecp::ECP};
    use super::MODULUS;

    #[ignore]
    #[test]
    fn print_constants() {
        let mut p = BIG::new_big(&MODULUS);
        p.rmod(&BIG::new_int(4));
        println!("p = {}", p.w[0]);
    }

    #[test]
    fn hash_to_curve_tests() {
        let dst = DomainSeparationTag::new("BLS12381G1_XMD:SHA-256_SSWU_RO_",
                                           Some("TESTGEN"),
                                           None,
                                           None).unwrap();
        let msgs = [
            "",
            "abc",
            "abcdef0123456789",
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ];
        let p = [
            ("045f87745ff759f9197e131ad83d47d635dc36a3e0c7e4a1be5e1effe5e63ac69c8f34e6c3aef9c5cf28224922788367", "06125886a03f883740a078313d5fa6e4a68b9c0394eb75f77c65fc8b44db3f4ef933ac6adf341bc45fabc7907afcb832"),
            ("009a357691a6f7b2917d9a34ba64d896d40b49733fcb3207f8c146e20fffb47823198a26b6ceeb01215fc3422908020e", "03fe44c894c107a8547826b60f577b90f80c63f899ef9dcff94daadae180ad803609337c9ec97d6d9b8ba306df7a9849"),
            ("04eb09680fe48598533932907810fb7681e60b3689cb138454bec627490c5089b6dd755556e52a36c3817e98b62d7497", "1763dd8bf6823d9a22124d22a4ab3d93d8a9603ec80b4a40905b26664b16033fa6e73a6155c9bc4c6faa42bf911ffba1"),
            ("0915842b42c2c4d3b509823c60c1fad834784ff451855f43390b80c3b6985d76aadc6ecfbb4b42a07921410d6821f0bb", "052873ee0b444dd8337ce403636d680cff1e9402b7a1ce2ab210bff11a83fe4e14216fe96efe3f344c1a2ec0fc1b2c5f"),
        ];

        let blshasher = Bls12381G1XmdSha256Sswu::from(dst);

        for i in 0..msgs.len() {
            let expected_p = ECP::new_bigs(&BIG::from_hex(p[i].0.to_string()), &BIG::from_hex(p[i].1.to_string()));
            let actual_p = blshasher.hash_to_curve(msgs[i]);
            assert!(actual_p.is_ok());
            let actual_p = actual_p.unwrap();
            assert_eq!(expected_p, actual_p);
        }
    }

    #[test]
    fn map_to_curve_2_tests() {
        let dst = DomainSeparationTag::new("BLS12381G1_XMD:SHA-256_SSWU_RO_",
                                           Some("TESTGEN"),
                                           None,
                                           None).unwrap();
        let msgs = [
            "",
            "abc",
            "abcdef0123456789",
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ];

        let expected_q = [
            ("02f2686965a4dd27ccb11119f2e131aefee818744a414d23ecef4db1407991fdf058f0affaee18fd586a9ab81060ae20",
             "0341a16c88a39b3d111b36b7cf885b7147b1d54b9201faaba5b47d7839bcf433cc35bb1f7b8e55aa9382a52fe4d84370",
             "1357bddd2bc6c8e752f3cf498ffe29ae87d8ff933701ae76f82d2839b0d9aee5229d4fff54dfb8223be0d88fa4485863",
             "09ba0ec3c78cf1e65330721f777b529aef27539642c39be11f459106b890ec5eb4a21c5d94885603e822cfa765170857"),

            ("119cc1d21e3e494d388a8718fe9f8ec6d8ff134486ce5c1f97129797616c4b8125f0dc568c59836cbf064496136438bc",
             "19e6c998825ee57b82c4808e4df477680f0f254c9edce228104422494a4e5d40d11ee676f6b861b6c49cf7de9d777aef",
             "0d1783f40bd83461b921c3fcd0e9ba326ef75272b122cf44338f0060d7179995a38ea9c66f3ce800e2f693d2634a4524",
             "017b2566d55fa7ee43844f1fa068cb0a11d5889c11607d939da046697c8ba25cf71054c2a8eb2189d3680485a39f5bdd"),

            ("1614d05720a39379fb89469883f90ae3e50995def9e17f8f8566a3f6cfb4fe88267eac1dc7834406fc597965065ef100",
             "1060e5aab331ac4940693a936ea80029bb2c4a3945add7ae35bce805e767af827c4a9ffcb5842fbc50ab234716d895f6",
             "0f612cda21cee750b1ccff361a4ce047e70d9a9e152e96a60aa29b5d8a5dcd25f7c5bd71bb56bd34e6a8af7532afaa4f",
             "1878f926302468949ef290b4fee621d1172e072eda1b42e366df68fc87f53c35583dbc043009e0b38a04a9b1ff617efe"),

            ("0a817078e7f30f08e94a25c2a1947160db1fe52042626660b8252cd339e678a1fecc0e6da60390a203532bd089a426b6",
             "097bd5d6ae3f5b5d0ba5e4099485caa2c505a1d900e4525af10254b3927ae0c82611be944ff8fdc6b278aab9e17ee27c",
             "1098f203da72c58dca61ffd52a3de82603d3154c527df51c2efe6298ea0eeaa065d57ba3a809b5e32d9d56dade119006",
             "0bcbd9df3505f049476f060c1d1c958fe8b34e426fd7e75424c9e227d9c4d3edbd5eddb8b1e89cc91b4a7bd3275d4d70"),
        ];

        for i in 0..msgs.len() {
            let u = hash_to_field_xmd_2::<sha2::Sha256, &str>(msgs[i], &dst).unwrap();
            let exp_q= ECP::new_bigs(
                &BIG::from_hex(expected_q[i].0.to_string()),
                &BIG::from_hex(expected_q[i].1.to_string())
            );
            let actual_q = map_to_curve(u.0);
            assert_eq!(exp_q, actual_q);
            let exp_q = ECP::new_bigs(
                &BIG::from_hex(expected_q[i].2.to_string()),
                &BIG::from_hex(expected_q[i].3.to_string())
            );
            let actual_q = map_to_curve(u.1);
            assert_eq!(exp_q, actual_q);
        }
    }

    // Take from section G.9.2
    #[test]
    fn map_to_curve_1_tests() {
        let dst = DomainSeparationTag::new("BLS12381G1_XMD:SHA-256_SSWU_NU_",
                                           Some("TESTGEN"),
                                           None,
                                           None).unwrap();
        let msgs = [
            "",
            "abc",
            "abcdef0123456789",
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ];
        let q_s = [
            ("0dddf77f320e7848a457358ab8d3b84cbaf19307be26b91a10c211651691cd736b1f59d77aed3954f857f108d6966f5b", "0450ab32020649f22a2fca166a1d8a59d4c93f1eb078a4bedd6c48027b9933507a2a8ae4d915305f58ede781283325a9"),
            ("12897a9a513b12303a7f0f3a3cc7c838d16847a31507980945312bede915848159bd390b16b8e378b398e31a385d9180", "1372530cc0811d70071e50640281aa8aaf96ee09c01281ccfead92296cb9dacf5054aa51dbea730e46239e709042a15d"),
            ("08459bd42a955d6e247fce6c81eda0ad9645f9e666d141a71f0afa3fbc509b2c58550fe077d073cc752493400399fddd", "169d35a8c6bb915ae910f4c6cde359622746b0c8b2b241b411d0e92ef991d3e6a7b0fafabb93c1de2e3997d6e362ce8a"),
            ("08c937d529c01ab2398b85b0bff6da465ed6265d4944dbbef7d383eea40157927082739c7b5417027d2225c6cb9d5ef0", "059047d83b5ea1ff7f0665b406acede27f233d3414055cbff25b37614b679f08fd6d807b5956edec6abad36c5321d99e"),
        ];

        for i in 0..msgs.len() {
            let u = hash_to_field_xmd_1::<sha2::Sha256, &str>(msgs[i], &dst).unwrap();
            let expected_q = ECP::new_bigs(
                &BIG::from_hex(q_s[i].0.to_string()),
                &BIG::from_hex(q_s[i].1.to_string())
            );
            let actual_q1 = map_to_curve(u);
            assert_eq!(expected_q, actual_q1);
        }
    }

    // Take from section G.9.2
    #[test]
    fn hash_to_field_xmd_1_tests() {
        let dst = DomainSeparationTag::new("BLS12381G1_XMD:SHA-256_SSWU_NU_",
                                           Some("TESTGEN"),
                                           None,
                                           None).unwrap();
        let msgs = [
            "",
            "abc",
            "abcdef0123456789",
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ];
        let executed_u_s = [
            "0ccb6bda9b602ab82aae21c0291623e2f639648a6ada1c76d8ffb664130fd18d98a2cc6160624148827a9726678e7cd4",
            "08accd9a1bd4b75bb2e9f014ac354a198cbf607f0061d00a6286f5544cf4f9ecc1439e3194f570cbbc7b96d1a754f231",
            "0a359cf072db3a39acf22f086d825fcf49d0daf241d98902342380fc5130b44e55de8f684f300bc11c44dee526413363",
            "181d09392c52f7740d5eaae52123c1dfa4808343261d8bdbaf19e7773e5cdfd989165cd9ecc795500e5da2437dde2093",
        ];

        for i in 0..msgs.len() {
            let expected_u = BIG::from_hex(executed_u_s[i].to_string());
            let actual_u = hash_to_field_xmd_1::<sha2::Sha256, &str>(msgs[i], &dst);
            assert!(actual_u.is_ok());
            assert_eq!(actual_u.unwrap(), expected_u);
        }
    }

    // Take from section G.9.1
    #[test]
    fn hash_to_field_xmd_2_tests() {
        let dst = DomainSeparationTag::new("BLS12381G1_XMD:SHA-256_SSWU_RO_",
                                           Some("TESTGEN"),
                                           None,
                                           None).unwrap();
        let msgs = [
            "",
            "abc",
            "abcdef0123456789",
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ];
        let expected_u_s = [
            ("14700e34d15178550475044b044b4e41ca8d52a655c34f8afea856d21d499f48c9370d2bae4ae8351305493e48d36ab5", "17e2da57f6fd3f11dba6119db4cd26b03e63e67b4e42db678d9c41fdfcaff00ba336d8563abcd9da6c17d2e1784ee858"),
            ("10c84aa245c74ee20579a27e63199be5d19cdfb5e44c6b587765931605d7790a1df6e1433f78bcddb4edb8553374f75e", "0f73433dcc2b5f9905c49d905bd62e1a1529b057c77194e56d196860d9d645167e0430aec9d3c70de31dd046fcab4a20"),
            ("11503eb4a558d0d2c5fc7cdddb51ba715c33577cf1a7f2f21a7eee6d2a570332bbbe53ae3392c9f8d8f6c172ae484692", "0efd59b8d98be7c491dfdb9d2a669e32e9bb348f8a64dbf7e47708dd5d40f484b1439109a3f96230bf63af72b908c43d"),
            ("134dc7f817cc08c5a3128892385ff6e9dd55f5e39d9a2d74ac74058d5dfc025d507806ab5d9254bd2334defbb477400d", "0eeaf2c6f4c1ca5cc039d99cb94234f67e65968f36d9dd77e95da55dadd085b50fbb11489167ded9157e5aac0d99d5be"),
        ];

        for i in 0..msgs.len() {
            let expected_u0 = BIG::from_hex(expected_u_s[i].0.to_string());
            let expected_u1 = BIG::from_hex(expected_u_s[i].1.to_string());
            let res = hash_to_field_xmd_2::<sha2::Sha256, &str>(msgs[i], &dst);
            assert!(res.is_ok());
            let (actual_u0, actual_u1) = res.unwrap();
            assert_eq!(actual_u0, expected_u0);
            assert_eq!(actual_u1, expected_u1);
        }
    }
}
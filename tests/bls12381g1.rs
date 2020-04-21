#[cfg(feature = "bls")]
mod tests {
    use digest::generic_array::{typenum::U48, GenericArray};
    use hash2curve::{
        bls381g1::{Bls12381G1Sswu, G1},
        DomainSeparationTag, HashToCurveXmd, HashToCurveXof,
    };
    use std::str::FromStr;

    #[test]
    fn g1_byte_tests() {
        let bytes: GenericArray<u8, U48> = GenericArray::clone_from_slice(
            vec![
                20, 115, 141, 175, 112, 245, 20, 45, 240, 56, 201, 227, 190, 118, 245, 215, 27, 13,
                182, 97, 62, 94, 245, 92, 254, 142, 67, 226, 127, 132, 13, 199, 93, 233, 112, 146,
                218, 97, 115, 118, 169, 245, 152, 231, 160, 146, 12, 71,
            ]
            .as_slice(),
        );
        let g1 = G1::from(bytes);
        assert_eq!(g1, bytes);
        let bytes: [u8; 96] = [
            20, 115, 141, 175, 112, 245, 20, 45, 240, 56, 201, 227, 190, 118, 245, 215, 27, 13,
            182, 97, 62, 94, 245, 92, 254, 142, 67, 226, 127, 132, 13, 199, 93, 233, 112, 146, 218,
            97, 115, 118, 169, 245, 152, 231, 160, 146, 12, 71, 18, 100, 91, 124, 176, 113, 148,
            54, 49, 208, 98, 178, 44, 166, 26, 138, 61, 242, 168, 189, 172, 78, 111, 205, 44, 24,
            100, 62, 243, 122, 152, 190, 172, 247, 112, 206, 40, 203, 1, 200, 171, 245, 237, 99,
            209, 161, 155, 83,
        ];
        let g1 = G1::from(bytes);
        assert!(g1.eq(&bytes));
    }

    #[test]
    fn g1_string_tests() {
        let g1 = G1::from_str("14738daf70f5142df038c9e3be76f5d71b0db6613e5ef55cfe8e43e27f840dc75de97092da617376a9f598e7a0920c47");
        assert!(g1.is_ok());
        assert_eq!(g1.unwrap().encode_to_hex(), "14738daf70f5142df038c9e3be76f5d71b0db6613e5ef55cfe8e43e27f840dc75de97092da617376a9f598e7a0920c47");
        let g1 = G1::from_str("14738daf70f5142df038c9e3be76f5d71b0db6613e5ef55cfe8e43e27f840dc75de97092da617376a9f598e7a0920c4712645b7cb071943631d062b22ca61a8a3df2a8bdac4e6fcd2c18643ef37a98beacf770ce28cb01c8abf5ed63d1a19b53");
        assert!(g1.is_ok());
        assert_eq!(g1.unwrap().encode_to_hex_uncompressed(), "14738daf70f5142df038c9e3be76f5d71b0db6613e5ef55cfe8e43e27f840dc75de97092da617376a9f598e7a0920c4712645b7cb071943631d062b22ca61a8a3df2a8bdac4e6fcd2c18643ef37a98beacf770ce28cb01c8abf5ed63d1a19b53");
        let g1 = G1::from_str("a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(g1.is_err());

        let g1 = G1::from_str("");
        assert!(g1.is_ok());
        assert_eq!(g1.unwrap().encode_to_hex(), "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

        let g1 = G1::from_str("abcdefghijklmnopqrstuvwxyz0123456789");
        assert!(g1.is_err());
    }

    #[test]
    fn hash_to_curve_xmd_tests() {
        let dst = DomainSeparationTag::new(
            b"BLS12381G1_XMD:SHA-256_SSWU_RO_",
            Some(b"TESTGEN"),
            None,
            None,
        )
        .unwrap();
        let msgs = [
            "",
            "abc",
            "abcdef0123456789",
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ];
        let p = [
            ("14738daf70f5142df038c9e3be76f5d71b0db6613e5ef55cfe8e43e27f840dc75de97092da617376a9f598e7a0920c47", "12645b7cb071943631d062b22ca61a8a3df2a8bdac4e6fcd2c18643ef37a98beacf770ce28cb01c8abf5ed63d1a19b53"),
            ("01fea27a940188120178dfceec87dca78b745b6e73757be21c54d6cee6f07e3d5a465cf425c9d34dccfa95acffa86bf2", "18def9271f5fd253380c764a6818e8b6524c3d35864fcf963d85031225d62bf8cd0abeb326c3c62fec56f6100fa04367"),
            ("0bdbca067fc4458a1206ecf3e235b400449c5693dd99e99a9793da076cb65e1b796bc279c892ae1c320c3783e25062d2", "12ca3f12b93b0028390a4ef4fa7083cb23f66ca42423e6e53987620e1d57c23a0ad6a14db1f709d0494c7d5122e0632f"),
            ("0a81ca09b6a8c05712396801e6432a87b14ab1f764fa519e9f515816607283fe2a653a191fc1c8fee89cd30195e7a8e1", "11c7f1b59bb552692288da6557d1b5c72a448101faf56dd4125d8422af1425c4ddeecfbd5200525064657a79bdd0c3ed"),
        ];

        let blshasher = Bls12381G1Sswu::from(dst);

        for i in 0..msgs.len() {
            let expected_p = G1::decode_from_hex_points(p[i].0, p[i].1).unwrap();
            let actual_p = blshasher.hash_to_curve_xmd::<sha2::Sha256>(msgs[i].as_bytes());
            assert!(actual_p.is_ok());
            let actual_p = actual_p.unwrap();
            assert_eq!(expected_p, actual_p);
        }
    }

    #[test]
    fn hash_to_curve_xof_tests() {
        let dst = DomainSeparationTag::new(
            b"BLS12381G1_XOF:SHAKE-128_SSWU_RO_",
            Some(b"TESTGEN"),
            None,
            None,
        )
        .unwrap();
        let msgs = [
            "",
            "abc",
            "abcdef0123456789",
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ];
        let p = [
            ("13BE5D0DA8916DC22A4683102E25158FCCF9695664B98E3CD41F723FEF99F92476FE5BFE495B787FDA5561AC6F0AB3B9", "10D5EFB4C0540BE37B23AB3A67324EA63D94AA5D7129210C7A4CA8AE5C48A3104CE74CEDC0117B56320CDD4242FEC1BC"),
            ("185782F1391BE17A64BC8ECB88CD7957118C0B968B7DBFAAEA4D0288BE243E4CF8CC10306AC58DED6994AC48837701BB", "12D37C727D8F5AF320B9DAB4E563D6E6578BBAAA1300EBEC58C1003C1A121669A53B39795F387AD510DA12E389B7CD6B"),
            ("19C3D7FF10EEF43623889C6221632C373A198AE108509A969D6B47A0D4ECA2483A884D2EAEA26A9214E6A54EBAD0E9C3", "025A8BD2768EC20CEA2E3D405FF72D4796BE83F8634317D1D70793591C6693954C91DEF9E6F553CE7ED4DC364CF05513"),
            ("0398FD7E656CEC001E1B3E1F88CA0CF6791A8F1C2C970E78E7E4E672EAD45340D53F958E20BF384FBB333F6F45328A1F", "0478D9837665E168D9AC3505C08AE122C504A78D8BE487012F078864D6C7043463E665F0DEA92EB6B374CADC65780A35"),
        ];

        let blshasher = Bls12381G1Sswu::from(dst);

        for i in 0..msgs.len() {
            let expected_p = G1::decode_from_hex_points(p[i].0, p[i].1).unwrap();
            let actual_p = blshasher.hash_to_curve_xof::<sha3::Shake128>(msgs[i].as_bytes());
            assert!(actual_p.is_ok());
            let actual_p = actual_p.unwrap();
            assert_eq!(expected_p, actual_p);
        }
    }

    #[test]
    fn encode_to_curve_xmd_tests() {
        let dst = DomainSeparationTag::new(
            b"BLS12381G1_XMD:SHA-256_SSWU_NU_",
            Some(b"TESTGEN"),
            None,
            None,
        )
        .unwrap();
        let msgs = [
            "",
            "abc",
            "abcdef0123456789",
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ];
        let p = [
            ("115281bd55a4103f31c8b12000d98149598b72e5da14e953277def263a24bc2e9fd8fa151df73ea3800f9c8cbb9b245c", "0796506faf9edbf1957ba8d667a079cab0d3a37e302e5132bd25665b66b26ea8556a0cfb92d6ae2c4890df0029b455ce"),
            ("04a7a63d24439ade3cd16eaab22583c95b061136bd5013cf109d92983f902c31f49c95cbeb97222577e571e97a68a32e", "09a8aa8d6e4b409bbe9a6976c016688269024d6e9d378ed25e8b4986194511f479228fa011ec88b8f4c57a621fc12187"),
            ("05c59faaf88187f51cd9cc6c20ca47ac66cc38d99af88aef2e82d7f35104168916f200a79562e64bc843f83cdc8a4675", "0b10472100a4aaa665f35f044b14a234b8f74990fa029e3dd06aa60b232fd9c232564ceead8cdb72a8a0320fc1071845"),
            ("10147709f8d4f6f2fa6f957f6c6533e3bf9069c01be721f9421d88e0f02d8c617d048c6f8b13b81309d1ef6b56eeddc7", "1048977c38688f1a3acf48ae319216cb1509b6a29bd1e7f3b2e476088a280e8c97d4a4c147f0203c7b3acb3caa566ae8"),
        ];

        let blshasher = Bls12381G1Sswu::from(dst);

        for i in 0..msgs.len() {
            let expected_p = G1::decode_from_hex_points(p[i].0, p[i].1).unwrap();
            let actual_p = blshasher.encode_to_curve_xmd::<sha2::Sha256>(msgs[i].as_bytes());
            assert!(actual_p.is_ok());
            let actual_p = actual_p.unwrap();
            assert_eq!(expected_p, actual_p);
        }
    }
}

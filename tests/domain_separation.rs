use hash2curve::DomainSeparationTag;

#[test]
fn to_bytes() {
    let dms = DomainSeparationTag::new("bbs", None, None, None);
    assert!(dms.is_ok());
    let dms = dms.unwrap();
    let res = dms.to_bytes::<sha2::Sha256>();
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), b"bbs");

    assert!(DomainSeparationTag::new("", None, None, None).is_err());
    let dms = DomainSeparationTag::new("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus facilisis erat eu dui tempus, nec luctus sem convallis. Quisque tempor, erat eget blandit lacinia, risus eros facilisis dolor, vitae tincidunt erat velit ac massa. Nunc euismod porta amet.", None, None, None);
    assert!(dms.is_ok());
    let dms = dms.unwrap();
    assert!(dms.to_bytes::<sha2::Sha256>().is_ok());
    let dms = DomainSeparationTag::new("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Cras nulla dolor, tincidunt vitae viverra non, vulputate vel quam. Donec vel condimentum metus. Sed id tincidunt nisl, quis vehicula urna. Vestibulum a consectetur neque. Sed ultrices finibus nullam.", None, None, None).unwrap();
    assert!(dms.to_bytes::<sha2::Sha256>().is_ok());
}

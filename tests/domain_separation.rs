use hash2curve::DomainSeparationTag;

#[test]
fn to_bytes() {
    let dms = DomainSeparationTag::new(b"bbs", None, None, None);
    assert!(dms.is_ok());
    let dms = dms.unwrap();
    let res = dms.to_bytes::<sha2::Sha256>();
    assert_eq!(res, b"bbs");

    assert!(DomainSeparationTag::new(b"", None, None, None).is_err());
    let mut protocol_id = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus facilisis erat eu dui tempus, nec luctus sem convallis.".to_vec();
    protocol_id.extend_from_slice(b" Quisque tempor, erat eget blandit lacinia, risus eros facilisis dolor, vitae tincidunt erat velit ac massa. Nunc euismod porta amet.");
    let dms = DomainSeparationTag::new(protocol_id.as_slice(), None, None, None);
    assert!(dms.is_ok());
    let dms = dms.unwrap();
    assert_eq!(dms.to_bytes::<sha2::Sha256>().len(), 255);
    let mut protocol_id = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Cras nulla dolor, tincidunt vitae viverra non, vulputate vel quam. ".to_vec();
    protocol_id.extend_from_slice(b"Donec vel condimentum metus. Sed id tincidunt nisl, quis vehicula urna. Vestibulum a consectetur neque. Sed ultrices finibus nullam.");
    let dms = DomainSeparationTag::new(protocol_id.as_slice(), None, None, None).unwrap();
    assert_eq!(dms.to_bytes::<sha2::Sha256>().len(), 32);
}

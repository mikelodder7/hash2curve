use crate::{expand_msg::ExpandMsg, from_ro::FromRO};
use digest::generic_array::{typenum::Unsigned, GenericArray};

/// Create `count` elements by hashing `msg` and `dst`
#[cfg(feature = "alloc")]
pub fn hash_to_field<T, X, M, D>(msg: M, dst: D, count: usize) -> crate::lib::Vec<T>
where
    T: FromRO,
    X: ExpandMsg,
    M: AsRef<[u8]>,
    D: AsRef<[u8]>,
{
    let len_per_elm = T::Length::to_usize();
    let len_in_bytes = count * len_per_elm;
    let pseudo_random_bytes = X::expand_message(msg, dst, len_in_bytes);

    let mut r = crate::lib::Vec::<T>::with_capacity(count);
    for i in 0..count {
        let bytes = GenericArray::<u8, T::Length>::from_slice(
            &pseudo_random_bytes[i * len_per_elm..(i + 1) * len_per_elm],
        );
        r.push(T::from_ro(bytes));
    }
    r
}

/// Create `count` elements by hashing `msg` and `dst`
pub fn hash_to_field_in_place<T, X, M, D>(msg: M, dst: D, out: &mut [T], buffer: &mut [u8])
where
    T: FromRO,
    X: ExpandMsg,
    M: AsRef<[u8]>,
    D: AsRef<[u8]>,
{
    let len_per_elm = T::Length::to_usize();
    let len_in_bytes = out.len() * len_per_elm;
    X::expand_message_in_place(msg, dst, len_in_bytes, buffer);

    for i in 0..out.len() {
        let bytes = GenericArray::<u8, T::Length>::from_slice(
            &buffer[i * len_per_elm..(i + 1) * len_per_elm],
        );
        out[i] = T::from_ro(bytes);
    }
}

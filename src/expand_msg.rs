/// Traits and methods for implementing `expand_msg_xmd` in section 5.4.1 of
/// <https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-10.html>
use crate::lib::*;

use digest::{
    generic_array::{typenum::Unsigned, GenericArray},
    BlockInput, Digest, ExtendableOutput, Update, XofReader,
};

/// Trait for types implementing expand_message interface for hash_to_field
pub trait ExpandMsg {
    /// Expand the message with the domain separation tag into a random byte sequence
    #[cfg(feature = "alloc")]
    fn expand_message<M, D>(msg: M, dst: D, len_in_bytes: usize) -> Vec<u8>
    where
        M: AsRef<[u8]>,
        D: AsRef<[u8]>;

    /// Expand the message with the domain separation tag into a random byte sequence
    /// and store it in `out`. `out` must be big enough to hold all computational storage.
    fn expand_message_in_place<M, D>(msg: M, dst: D, len_in_bytes: usize, out: &mut [u8])
    where
        M: AsRef<[u8]>,
        D: AsRef<[u8]>;
}

/// Placeholder type for implementing expand_message_xof based on a hash function
#[derive(Debug)]
pub struct ExpandMsgXof<HashT> {
    phantom: PhantomData<HashT>,
}

impl<HashT> ExpandMsgXof<HashT>
where
    HashT: Default + ExtendableOutput + Update,
{
    fn xof<M, D>(msg: M, dst: D, len_in_bytes: usize) -> HashT
    where
        M: AsRef<[u8]>,
        D: AsRef<[u8]>,
    {
        let dst = dst.as_ref();
        HashT::default()
            .chain(msg)
            .chain([(len_in_bytes >> 8) as u8, len_in_bytes as u8])
            .chain(dst)
            .chain([dst.len() as u8])
    }
}

impl<HashT> ExpandMsg for ExpandMsgXof<HashT>
where
    HashT: Default + ExtendableOutput + Update,
{
    #[cfg(feature = "alloc")]
    fn expand_message<M, D>(msg: M, dst: D, len_in_bytes: usize) -> Vec<u8>
    where
        M: AsRef<[u8]>,
        D: AsRef<[u8]>,
    {
        Self::xof(msg, dst, len_in_bytes)
            .finalize_boxed(len_in_bytes)
            .to_vec()
        // let dst = dst.as_ref();
        //     HashT::default()
        //         .chain(msg)
        //         .chain([(len_in_bytes >> 8) as u8, len_in_bytes as u8])
        //         .chain(dst)
        //         .chain([dst.len() as u8])
        //         .finalize_boxed(len_in_bytes).to_vec()
    }

    fn expand_message_in_place<M, D>(msg: M, dst: D, len_in_bytes: usize, out: &mut [u8])
    where
        M: AsRef<[u8]>,
        D: AsRef<[u8]>,
    {
        let dst = dst.as_ref();
        let mut reader =
        // HashT::default()
        //     .chain(msg)
        //     .chain([(out.len() >> 8) as u8, out.len() as u8])
        //     .chain(dst)
        //     .chain([dst.len() as u8])
        Self::xof(msg, dst, out.len())
            .finalize_xof();
        reader.read(&mut out[..len_in_bytes]);
    }
}

/// Placeholder type for implementing expand_message_xmd based on a hash function
#[derive(Debug)]
pub struct ExpandMsgXmd<HashT> {
    phantom: PhantomData<HashT>,
}

impl<HashT> ExpandMsg for ExpandMsgXmd<HashT>
where
    HashT: Digest + BlockInput,
{
    #[cfg(feature = "alloc")]
    fn expand_message<M, D>(msg: M, dst: D, len_in_bytes: usize) -> Vec<u8>
    where
        M: AsRef<[u8]>,
        D: AsRef<[u8]>,
    {
        let b_in_bytes = <HashT as Digest>::OutputSize::to_usize();
        let ell = (len_in_bytes + b_in_bytes - 1) / b_in_bytes;
        let mut out = (0..len_in_bytes * ell).map(|_| 0u8).collect::<Vec<u8>>();

        Self::expand_message_in_place(msg, dst, len_in_bytes, out.as_mut_slice());
        out.truncate(len_in_bytes);
        out
    }

    fn expand_message_in_place<M, D>(msg: M, dst: D, len_in_bytes: usize, out: &mut [u8])
    where
        M: AsRef<[u8]>,
        D: AsRef<[u8]>,
    {
        let b_in_bytes = <HashT as Digest>::OutputSize::to_usize();
        let ell = (len_in_bytes + b_in_bytes - 1) / b_in_bytes;
        // Since ell is basically checked at compile time, is this check needed?
        // if ell > 255 {
        //     return Err(Error::TooManyBytesRequest);
        // }
        let dst = dst.as_ref();

        let b_0 = HashT::new()
            .chain(GenericArray::<u8, <HashT as BlockInput>::BlockSize>::default())
            .chain(msg.as_ref())
            .chain([(len_in_bytes >> 8) as u8, len_in_bytes as u8])
            .chain(dst)
            .chain([dst.len() as u8])
            .finalize();

        // b_1
        out[..b_in_bytes].copy_from_slice(
            HashT::new()
                .chain(b_0.as_ref())
                .chain([1u8])
                .chain(dst)
                .chain([dst.len() as u8])
                .finalize()
                .as_ref(),
        );

        for i in 1..ell {
            // b_0 xor b(i - 1)
            let mut tmp = GenericArray::<u8, <HashT as Digest>::OutputSize>::default();
            b_0.iter()
                .zip(&out[(i - 1) * b_in_bytes..i * b_in_bytes])
                .enumerate()
                .for_each(|(j, (b0, b1))| tmp[j] = b0 ^ b1);
            out[i * b_in_bytes..(i + 1) * b_in_bytes].copy_from_slice(
                HashT::new()
                    .chain(tmp)
                    .chain([(i + 1) as u8])
                    .chain(dst)
                    .chain([dst.len() as u8])
                    .finalize()
                    .as_ref(),
            );
        }
    }
}

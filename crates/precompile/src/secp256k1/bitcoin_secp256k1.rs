//! bitcoin_secp256k1 implementation of `ecrecover`. More about it in [`crate::secp256k1`].
use primitives::{alloy_primitives::B512, B256};

// Silence the unused crate dependency warning.
use k256 as _;

#[cfg(not(feature = "solana-sbf"))]
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, SECP256K1,
};

#[cfg(not(feature = "solana-sbf"))]
use primitives::keccak256;

#[cfg(not(feature = "solana-sbf"))]
/// Recover the public key from a signature and a message.
///
/// This function is using the `secp256k1` crate, it is enabled by `secp256k1` feature and it is in default.
pub fn ecrecover(sig: &B512, recid: u8, msg: &B256) -> Result<B256, secp256k1::Error> {
    let recid = RecoveryId::try_from(recid as i32).expect("recovery ID is valid");
    let sig = RecoverableSignature::from_compact(sig.as_slice(), recid)?;




    let msg = Message::from_digest(msg.0);
    let public = SECP256K1.recover_ecdsa(msg, &sig)?;

    let mut hash = keccak256(&public.serialize_uncompressed()[1..]);
    hash[..12].fill(0);
    Ok(hash)
}

#[cfg(feature = "solana-sbf")]
use solana_program::secp256k1_recover::{secp256k1_recover, Secp256k1RecoverError, keccak256};


#[cfg(feature = "solana-sbf")]
/// Recover the public key from a signature and a message.
///
/// Solana onchain adapted implementation using syscall
pub fn ecrecover(sig: &B512, recid: u8, msg: &B256) -> Result<B256, secp256k1::Error> {
    let public = secp256k1_recover(msg.as_slice(), recid, sig.as_slice()).map_err(|err| match err {
        Secp256k1RecoverError::InvalidHash => secp256k1::Error::InvalidMessage,
        Secp256k1RecoverError::InvalidRecoveryId => secp256k1::Error::InvalidRecoveryId,
        Secp256k1RecoverError::InvalidSignature => secp256k1::Error::InvalidSignature,
    })?;

    let mut hash = keccak256::hash(&public.to_bytes());
    hash[..12].fill(0);
    Ok(hash)
}

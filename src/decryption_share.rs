use bulletproofs::{
    group::GroupEncoding,
    vsss_rs::{DefaultShare, IdentifierPrimeField, ValueGroup},
    BulletproofCurveArithmetic,
};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use crate::{Ciphertext, VerifiableEncryption, VerifiableEncryptionDecryptor};

/// The representation of a secret share
pub type SecretShare<F, G> = DefaultShare<IdentifierPrimeField<F>, ValueGroup<G>>;

/// A decryption key share that allows for decryption of a ciphertext
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DecryptionShare<C: BulletproofCurveArithmetic> {
    pub inner: Vec<SecretShare<C::Scalar, C::Point>>,
    pub _marker: PhantomData<C>,
}

#[cfg(feature = "v1")]
impl<
        P: legacy_vsss_rs::Share<Identifier = u8>,
        C: VerifiableEncryption + VerifiableEncryptionDecryptor,
    > From<crate::v1::DecryptionShare<P, C>> for DecryptionShare<C>
{
    fn from(value: crate::v1::DecryptionShare<P, C>) -> Self {
        let mut inner = Vec::with_capacity(value.inner.len());
        let mut repr = <C::Point as GroupEncoding>::Repr::default();
        for share in value.inner {
            share
                .value(repr.as_mut())
                .expect("Failed to deserialize point");
            let p = C::Point::from_bytes(&repr).expect("Failed to deserialize point");
            inner.push(DefaultShare {
                identifier: IdentifierPrimeField(C::Scalar::from(share.identifier() as u64)),
                value: ValueGroup(p),
            });
        }
        Self {
            inner,
            _marker: PhantomData,
        }
    }
}

#[cfg(feature = "v1")]
impl<
        P: legacy_vsss_rs::Share<Identifier = u8>,
        C: VerifiableEncryption + VerifiableEncryptionDecryptor,
    > From<DecryptionShare<C>> for crate::v1::DecryptionShare<P, C>
{
    fn from(value: DecryptionShare<C>) -> Self {
        use bulletproofs::group::ff::PrimeField;

        let repr = C::Point::default().to_bytes();
        let share_len = repr.as_ref().len();
        let mut inner = crate::v1::default_shares(share_len);

        for (old, new) in inner.iter_mut().zip(value.inner.iter()) {
            let new_repr = new.identifier.0.to_repr();
            let new_repr_bytes = new_repr.as_ref();
            let identifier = if new_repr_bytes[0] != 0 {
                new_repr_bytes[0]
            } else {
                let id = new_repr_bytes.last().expect("to be not zero");
                assert_ne!(id, &0);
                *id
            };
            let repr = new.value.0.to_bytes();
            *old = P::with_identifier_and_value(identifier, repr.as_ref());
        }
        Self {
            inner,
            _marker: PhantomData,
        }
    }
}

impl<C: VerifiableEncryption + VerifiableEncryptionDecryptor> DecryptionShare<C> {
    /// Create a new decryption share from a key share and a ciphertext
    pub fn new(
        key_share: &DefaultShare<IdentifierPrimeField<C::Scalar>, IdentifierPrimeField<C::Scalar>>,
        ciphertext: &Ciphertext<C>,
    ) -> Self {
        let mut inner = Vec::with_capacity(C::SCALAR_BYTES);
        for c1 in &ciphertext.c1 {
            inner.push(DefaultShare {
                identifier: key_share.identifier,
                value: ValueGroup(*c1 * key_share.value.0),
            });
        }

        Self {
            inner,
            _marker: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    #[case::k256(bulletproofs::k256::Secp256k1)]
    #[case::p256(bulletproofs::p256::NistP256)]
    #[case::p384(bulletproofs::p384::NistP384)]
    #[case::ristretto25519(bulletproofs::Ristretto25519)]
    #[case::ed25519(bulletproofs::Ed25519)]
    #[case::bls12_381(bulletproofs::bls12_381_plus::Bls12381G1)]
    #[case::bls12_381_std(bulletproofs::blstrs_plus::Bls12381G1)]
    #[case::ed448(bulletproofs::ed448::Ed448)]
    fn decryption_share_test<C: VerifiableEncryption + VerifiableEncryptionDecryptor>(
        #[case] _c: C,
    ) {
        use bulletproofs::group::{ff::Field, Group};

        let mut rng = rand::thread_rng();
        let signing_key = C::Scalar::random(&mut rng);
        let decryption_key = C::Scalar::random(&mut rng);
        let encryption_key = C::Point::generator() * decryption_key;

        let (ciphertext, _) =
            C::encrypt_and_prove(encryption_key, &signing_key, &[], None, &mut rng);
        let dk = IdentifierPrimeField(decryption_key);
        let shares = bulletproofs::vsss_rs::shamir::split_secret(2, 3, &dk, &mut rng).unwrap();

        let decryption_share1 = DecryptionShare::<C>::new(&shares[0], &ciphertext);
        let decryption_share2 = DecryptionShare::<C>::new(&shares[1], &ciphertext);

        let signing_key2 =
            C::decrypt_with_shares(&[decryption_share1, decryption_share2], &ciphertext, None)
                .unwrap();
        assert_eq!(signing_key, signing_key2);
    }

    #[rstest]
    #[case::k256(bulletproofs::k256::Secp256k1)]
    #[case::p256(bulletproofs::p256::NistP256)]
    #[case::p384(bulletproofs::p384::NistP384)]
    #[case::ristretto25519(bulletproofs::Ristretto25519)]
    #[case::ed25519(bulletproofs::Ed25519)]
    #[case::bls12_381(bulletproofs::bls12_381_plus::Bls12381G1)]
    #[case::bls12_381_std(bulletproofs::blstrs_plus::Bls12381G1)]
    #[case::ed448(bulletproofs::ed448::Ed448)]
    fn decryption_share_serialize_test<
        C: VerifiableEncryption + VerifiableEncryptionDecryptor + PartialEq,
    >(
        #[case] _c: C,
    ) {
        use bulletproofs::group::{ff::Field, Group};

        let mut rng = rand::thread_rng();
        let signing_key = C::Scalar::random(&mut rng);
        let decryption_key = C::Scalar::random(&mut rng);
        let encryption_key = C::Point::generator() * decryption_key;

        let dk = IdentifierPrimeField(decryption_key);
        let (ciphertext, _) =
            C::encrypt_and_prove(encryption_key, &signing_key, &[], None, &mut rng);
        let shares = bulletproofs::vsss_rs::shamir::split_secret(2, 3, &dk, &mut rng).unwrap();

        let decryption_share1 = DecryptionShare::<C>::new(&shares[0], &ciphertext);

        let bytes = serde_bare::to_vec(&decryption_share1).unwrap();
        let deserialized_share2: DecryptionShare<C> = serde_bare::from_slice(&bytes).unwrap();
        assert_eq!(decryption_share1, deserialized_share2);

        let json = serde_json::to_string(&decryption_share1).unwrap();
        let deserialized_share2: DecryptionShare<C> = serde_json::from_str(&json).unwrap();
        assert_eq!(decryption_share1, deserialized_share2);
    }
}

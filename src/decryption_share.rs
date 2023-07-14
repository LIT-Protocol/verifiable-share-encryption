use bulletproofs::group::GroupEncoding;
use bulletproofs::{vsss_rs::Share, BulletproofCurveArithmetic};
use serde::{ser::SerializeTuple, Deserialize, Deserializer, Serialize, Serializer};
use std::marker::PhantomData;

use crate::{Ciphertext, VerifiableEncryption, VerifiableEncryptionDecryptor};

/// A decryption key share that allows for decryption of a ciphertext
#[derive(Clone, Debug, Default)]
pub struct DecryptionShare<P: Share<Identifier = u8>, C: BulletproofCurveArithmetic> {
    pub(crate) inner: [P; 32],
    pub(crate) _marker: PhantomData<C>,
}

impl<P: Share<Identifier = u8>, C: VerifiableEncryption + VerifiableEncryptionDecryptor> Serialize
    for DecryptionShare<P, C>
{
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if s.is_human_readable() {
            let mut tupler = s.serialize_tuple(32)?;
            for share in self.inner.iter() {
                let identifier = share.identifier();
                let bytes = share.value();
                let mut data = Vec::with_capacity(1 + bytes.len());
                data.push(identifier);
                data.extend_from_slice(bytes);
                tupler.serialize_element(&data_encoding::BASE64.encode(&data))?;
            }
            tupler.end()
        } else {
            let mut bytes = Vec::<u8>::with_capacity(32 * 33);
            for share in self.inner.iter() {
                let identifier = share.identifier();
                let value = share.value();
                bytes.push(identifier);
                bytes.extend_from_slice(value);
            }

            bytes.serialize(s)
        }
    }
}

impl<'de, P: Share<Identifier = u8>, C: VerifiableEncryption + VerifiableEncryptionDecryptor>
    Deserialize<'de> for DecryptionShare<P, C>
{
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = C::Point::default().to_bytes();
        let share_len = repr.as_ref().len();
        let mut inner = default_shares::<P>(share_len);
        if d.is_human_readable() {
            let inner_shares = <[String; 32]>::deserialize(d)?;
            let inner_bytes = inner_shares
                .iter()
                .map(|s| data_encoding::BASE64.decode(s.as_bytes()).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(inner_bytes.len(), 32);
            for (share, bytes) in inner.iter_mut().zip(inner_bytes.iter()) {
                *share.identifier_mut() = bytes[0];
                share.value_mut().copy_from_slice(&bytes[1..]);
            }
        } else {
            let bytes = Vec::<u8>::deserialize(d)?;
            let mut pos = &bytes[..];
            for share in inner.iter_mut() {
                *share.identifier_mut() = pos[0];
                share.value_mut().copy_from_slice(&pos[1..share_len + 1]);
                pos = &pos[share_len + 1..];
            }
        }
        Ok(Self {
            inner,
            _marker: PhantomData,
        })
    }
}

impl<P: Share<Identifier = u8>, C: VerifiableEncryption + VerifiableEncryptionDecryptor>
    DecryptionShare<P, C>
{
    /// Create a new decryption share from a key share and a ciphertext
    pub fn new<S: Share<Identifier = u8>>(key_share: &S, ciphertext: &Ciphertext<C>) -> Self {
        let share = key_share.as_field_element::<C::Scalar>().unwrap();
        let inner = [
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[0] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[1] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[2] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[3] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[4] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[5] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[6] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[7] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[8] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[9] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[10] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[11] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[12] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[13] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[14] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[15] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[16] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[17] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[18] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[19] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[20] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[21] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[22] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[23] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[24] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[25] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[26] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[27] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[28] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[29] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[30] * share).to_bytes().as_ref(),
            ),
            P::with_identifier_and_value(
                key_share.identifier(),
                (ciphertext.c1[31] * share).to_bytes().as_ref(),
            ),
        ];
        Self {
            inner,
            _marker: PhantomData,
        }
    }
}

fn default_shares<P: Share<Identifier = u8>>(size: usize) -> [P; 32] {
    [
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
        P::empty_share_with_capacity(size),
    ]
}

#[test]
fn decryption_share_test_k256() {
    decryption_share_test::<bulletproofs::k256::Secp256k1>()
}

#[test]
fn decryption_share_test_p256() {
    decryption_share_test::<bulletproofs::p256::NistP256>()
}

#[test]
fn decryption_share_test_curve25519() {
    decryption_share_test::<bulletproofs::Curve25519>()
}

#[test]
fn decryption_share_test_bls12_381() {
    decryption_share_test::<bulletproofs::bls12_381_plus::Bls12381G1>()
}

#[test]
fn decryption_share_test_bls12_381_std() {
    decryption_share_test::<bulletproofs::blstrs_plus::Bls12381G1>()
}

#[cfg(test)]
fn decryption_share_test<C: VerifiableEncryption + VerifiableEncryptionDecryptor>() {
    use bulletproofs::{
        group::{ff::Field, Group},
        vsss_rs::shamir,
    };

    let mut rng = rand::thread_rng();
    let signing_key = C::Scalar::random(&mut rng);
    let decryption_key = C::Scalar::random(&mut rng);
    let encryption_key = C::Point::generator() * decryption_key;

    let (ciphertext, _) = C::encrypt_and_prove(encryption_key, &signing_key, &mut rng);
    let shares: Vec<Vec<u8>> = shamir::split_secret(2, 3, decryption_key, &mut rng).unwrap();

    let decryption_share1 = DecryptionShare::<Vec<u8>, C>::new(&shares[0], &ciphertext);
    let decryption_share2 = DecryptionShare::<Vec<u8>, C>::new(&shares[1], &ciphertext);

    let signing_key2 =
        C::decrypt_with_shares(&[decryption_share1, decryption_share2], &ciphertext).unwrap();
    assert_eq!(signing_key, signing_key2);
}

#[test]
fn decryption_share_serialize_test_k256() {
    decryption_share_serialize_test::<bulletproofs::k256::Secp256k1>()
}

#[test]
fn decryption_share_serialize_test_p256() {
    decryption_share_serialize_test::<bulletproofs::p256::NistP256>()
}

#[test]
fn decryption_share_serialize_test_curve25519() {
    decryption_share_serialize_test::<bulletproofs::Curve25519>()
}

#[test]
fn decryption_share_serialize_test_bls12_381() {
    decryption_share_serialize_test::<bulletproofs::bls12_381_plus::Bls12381G1>()
}

#[test]
fn decryption_share_serialize_test_bls12_381_std() {
    decryption_share_serialize_test::<bulletproofs::blstrs_plus::Bls12381G1>()
}

#[cfg(test)]
fn decryption_share_serialize_test<C: VerifiableEncryption + VerifiableEncryptionDecryptor>() {
    use bulletproofs::{
        group::{ff::Field, Group},
        vsss_rs::shamir,
    };

    let mut rng = rand::thread_rng();
    let signing_key = C::Scalar::random(&mut rng);
    let decryption_key = C::Scalar::random(&mut rng);
    let encryption_key = C::Point::generator() * decryption_key;

    let (ciphertext, _) = C::encrypt_and_prove(encryption_key, &signing_key, &mut rng);
    let shares: Vec<Vec<u8>> = shamir::split_secret(2, 3, decryption_key, &mut rng).unwrap();

    let decryption_share1 = DecryptionShare::<Vec<u8>, C>::new(&shares[0], &ciphertext);

    let bytes = serde_bare::to_vec(&decryption_share1).unwrap();
    let deserialized_share2: DecryptionShare<Vec<u8>, C> = serde_bare::from_slice(&bytes).unwrap();
    for (a, b) in decryption_share1
        .inner
        .iter()
        .zip(deserialized_share2.inner.iter())
    {
        assert_eq!(a, b);
    }

    let json = serde_json::to_string(&decryption_share1).unwrap();
    let deserialized_share2: DecryptionShare<Vec<u8>, C> = serde_json::from_str(&json).unwrap();
    for (a, b) in decryption_share1
        .inner
        .iter()
        .zip(deserialized_share2.inner.iter())
    {
        assert_eq!(a, b);
    }
}

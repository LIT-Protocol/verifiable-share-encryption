mod byte_proof;
mod ciphertext;
mod decryption_share;
mod dlog_proof;
mod errors;
mod proof;
#[cfg(feature = "v1")]
pub mod v1;

pub use byte_proof::*;
pub use ciphertext::*;
pub use decryption_share::*;
pub use dlog_proof::*;
pub use errors::*;
pub use proof::*;

use bulletproofs::{
    group::{
        ff::{Field, PrimeField},
        Group,
    },
    merlin::Transcript,
    vsss_rs::ReadableShareSet,
    BulletproofCurveArithmetic, BulletproofGens, PedersenGens, RangeProof, TranscriptProtocol,
};
use rand_core::{CryptoRng, RngCore};
use std::ops::Deref;

/// A trait for types that can use ElGamal encryption scheme for a scalar
pub trait VerifiableEncryption: BulletproofCurveArithmetic {
    /// Applies blind encryption to the given scalar
    /// with the specified encryption key
    /// and generates a zero-knowledge proof of the encryption.
    ///
    /// Decryption only returns the blinded value without the blinding factor.
    fn blind_encrypt_and_prove(
        encryption_key: Self::Point,
        key_share: &Self::Scalar,
        blinder: &Self::Scalar,
        authenticated_data: &[u8],
        rng: impl RngCore + CryptoRng,
    ) -> (Ciphertext<Self>, Proof<Self>) {
        let blinded_key_share = *key_share + blinder;
        let (ciphertext, proof) =
            Self::encrypt_and_prove(encryption_key, &blinded_key_share, authenticated_data, rng);
        (ciphertext, proof)
    }

    /// Encrypt the scalar with the given encryption key
    /// and generate a zero-knowledge proof of the encryption
    fn encrypt_and_prove(
        encryption_key: Self::Point,
        key_share: &Self::Scalar,
        authenticated_data: &[u8],
        mut rng: impl RngCore + CryptoRng,
    ) -> (Ciphertext<Self>, Proof<Self>) {
        let mut transcript = Transcript::new(b"ElGamalVerifiableEncryption");
        let key_bytes = Self::scalar_to_verifiable_encryption_bytes(key_share);
        let key_segments = key_bytes.iter().map(|b| *b as u64).collect::<Vec<_>>();
        let blinders = (0..key_bytes.len())
            .map(|_| Self::Scalar::random(&mut rng))
            .collect::<Vec<_>>();
        let blinder_blinders = (0..key_bytes.len())
            .map(|_| Self::Scalar::random(&mut rng))
            .collect::<Vec<_>>();
        let c1s = blinders
            .iter()
            .map(|r| Self::Point::generator() * r)
            .collect::<Vec<Self::Point>>();

        let bp_gens = BulletproofGens::new(8, key_bytes.len());
        let pc_gens = PedersenGens {
            B: Self::Point::generator(),
            B_blinding: encryption_key,
        };
        let (range_proof, c2s) = RangeProof::prove_multiple_with_rng(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            &key_segments,
            &blinders,
            8,
            &mut rng,
        )
        .unwrap();

        transcript.append_message(b"elgamal_segment_proofs", &[key_bytes.len() as u8]);
        for i in 0..key_bytes.len() {
            transcript.append_u64(b"elgamal_segment_proofs_index", i as u64);
            transcript.append_point::<Self>(b"elgamal_segment_proofs_c1", &c1s[i]);
            transcript.append_point::<Self>(b"elgamal_segment_proofs_c2", &c2s[i]);
            let r1 = Self::Point::generator() * blinder_blinders[i];
            let r2 = c1s[i] + encryption_key * blinder_blinders[i];
            transcript.append_point::<Self>(b"elgamal_segment_proofs_r1", &r1);
            transcript.append_point::<Self>(b"elgamal_segment_proofs_r2", &r2);
        }

        let dlog_committing =
            DlogProof::<Self>::create(encryption_key, *key_share, &mut transcript, &mut rng);

        transcript.append_message(b"authenticated_data", authenticated_data);
        let challenge = transcript.challenge_scalar::<Self>(b"elgamal_segment_proofs_challenge");
        let dlog_proof = dlog_committing.finalize(challenge);

        let byte_proofs = (0..key_bytes.len())
            .map(|i| ByteProof {
                message: blinders[i] - challenge * Self::Scalar::from(key_bytes[i] as u64),
                blinder: blinder_blinders[i] - challenge * blinders[i],
            })
            .collect::<Vec<_>>();

        (
            Ciphertext { c1: c1s, c2: c2s },
            Proof {
                byte_proofs,
                challenge,
                dlog_proof,
                range_proof,
            },
        )
    }

    /// Verify the ciphertext encrypts a key share that corresponds
    /// to the verification key
    fn verify(
        encryption_key: Self::Point,
        verification_key: Self::Point,
        ciphertext: &Ciphertext<Self>,
        proof: &Proof<Self>,
        authenticated_data: &[u8],
    ) -> Result<()> {
        let key_bytes = ciphertext.c1.len();
        let mut transcript = Transcript::new(b"ElGamalVerifiableEncryption");
        let bp_gens = BulletproofGens::new(8, key_bytes);
        let pc_gens = PedersenGens {
            B: Self::Point::generator(),
            B_blinding: encryption_key,
        };
        proof
            .range_proof
            .verify_multiple(&bp_gens, &pc_gens, &mut transcript, &ciphertext.c2, 8)
            .map_err(|_e| Error::InvalidRangeProof)?;

        transcript.append_message(b"elgamal_segment_proofs", &[key_bytes as u8]);
        for i in 0..key_bytes {
            transcript.append_u64(b"elgamal_segment_proofs_index", i as u64);
            transcript.append_point::<Self>(b"elgamal_segment_proofs_c1", &ciphertext.c1[i]);
            transcript.append_point::<Self>(b"elgamal_segment_proofs_c2", &ciphertext.c2[i]);
            let r1 = ciphertext.c1[i] * proof.challenge
                + Self::Point::generator() * proof.byte_proofs[i].blinder;
            let r2 = ciphertext.c2[i] * proof.challenge
                + encryption_key * proof.byte_proofs[i].blinder
                + Self::Point::generator() * proof.byte_proofs[i].message;
            transcript.append_point::<Self>(b"elgamal_segment_proofs_r1", &r1);
            transcript.append_point::<Self>(b"elgamal_segment_proofs_r2", &r2);
        }

        transcript.append_point::<Self>(b"G", &Self::Point::generator());
        transcript.append_point::<Self>(b"Y", &encryption_key);
        transcript.append_point::<Self>(b"C1", &proof.dlog_proof.c1);
        transcript.append_point::<Self>(b"C2", &proof.dlog_proof.c2);
        transcript.append_point::<Self>(b"Q", &verification_key);
        transcript.append_point::<Self>(b"A1", &proof.dlog_proof.a1);
        transcript.append_point::<Self>(b"A2", &proof.dlog_proof.a2);
        transcript.append_point::<Self>(b"A3", &proof.dlog_proof.a3);
        transcript.append_message(b"authenticated_data", authenticated_data);
        let challenge = transcript.challenge_scalar::<Self>(b"elgamal_segment_proofs_challenge");

        if challenge != proof.challenge {
            return Err(Error::InvalidSegmentsProof);
        }

        //DLOG verify

        // (r1 + c.x).G
        let lhs1 = Self::Point::generator() * proof.dlog_proof.message;
        // r1.G + c.x.G
        let rhs1 = proof.dlog_proof.a1 + verification_key * challenge;

        // (r2 + c.r).Y
        let lhs2 = encryption_key * proof.dlog_proof.blinding;
        // r2.Y + c.x.G + c.r.Y - c.x.G
        let rhs2 = proof.dlog_proof.a2 + (proof.dlog_proof.c2 - verification_key) * challenge;

        // (r2 + c.r).G
        let lhs3 = Self::Point::generator() * proof.dlog_proof.blinding;
        // r2.G + c.r.G
        let rhs3 = proof.dlog_proof.a3 + proof.dlog_proof.c1 * challenge;

        if lhs1 == rhs1 && lhs2 == rhs2 && lhs3 == rhs3 {
            Ok(())
        } else {
            Err(Error::InvalidDlogProof)
        }
    }

    fn scalar_to_verifiable_encryption_bytes(scalar: &Self::Scalar) -> Vec<u8> {
        scalar.to_repr().as_ref().to_vec()
    }
}

/// A trait for types that can use ElGamal decryption scheme for a scalar
pub trait VerifiableEncryptionDecryptor: BulletproofCurveArithmetic {
    /// Decrypt the ciphertext using the decryption key
    fn decrypt(
        decryption_key: &Self::Scalar,
        ciphertext: &Ciphertext<Self>,
    ) -> Result<Self::Scalar> {
        use rayon::prelude::*;

        let mut key_bytes = vec![0u8; ciphertext.c1.len()];

        key_bytes.par_iter_mut().enumerate().for_each(|(i, b)| {
            let vi = ciphertext.c2[i] - ciphertext.c1[i] * *decryption_key;

            for ki in 0u8..=255 {
                let si = Self::Scalar::from(ki as u64);
                if vi == Self::Point::generator() * si {
                    *b = ki;
                    break;
                }
            }
        });
        Self::verifiable_encryption_bytes_to_scalar(&key_bytes)
    }

    /// Decrypt the ciphertext and verify the decrypted value is correct
    fn decrypt_and_verify(
        decryption_key: &Self::Scalar,
        ciphertext: &Ciphertext<Self>,
        proof: &Proof<Self>,
    ) -> Result<Self::Scalar> {
        let plaintext = Self::decrypt(decryption_key, ciphertext)?;
        if proof.dlog_proof.c2 - proof.dlog_proof.c1 * decryption_key
            == Self::Point::generator() * plaintext
        {
            Ok(plaintext)
        } else {
            Err(Error::InvalidCiphertext)
        }
    }

    /// Decrypt the ciphertext given the decryption shares
    fn decrypt_with_shares(
        decryption_shares: &[DecryptionShare<Self>],
        ciphertext: &Ciphertext<Self>,
    ) -> Result<Self::Scalar> {
        use rayon::prelude::*;

        let mut key_bytes = vec![0u8; ciphertext.c1.len()];
        let mut decryption_parts = Vec::with_capacity(ciphertext.c1.len());
        for i in 0..ciphertext.c1.len() {
            let parts = decryption_shares
                .iter()
                .map(|s| s.inner[i])
                .collect::<Vec<_>>();
            let share = parts.combine().map_err(|_| Error::InvalidDecryptionShare)?;
            decryption_parts.push(share.0);
        }

        key_bytes
            .par_iter_mut()
            .enumerate()
            .zip(decryption_parts.par_iter())
            .for_each(|((i, b), c1)| {
                let vi = ciphertext.c2[i] - c1;

                for ki in 0u8..=255 {
                    let si = Self::Scalar::from(ki as u64);
                    if vi == Self::Point::generator() * si {
                        *b = ki;
                        break;
                    }
                }
            });
        Self::verifiable_encryption_bytes_to_scalar(&key_bytes)
    }

    /// Decrypt the ciphertext using the decryption key and unblind using the blinding factor
    fn decrypt_and_unblind(
        blinder: &Self::Scalar,
        decryption_key: &Self::Scalar,
        ciphertext: &Ciphertext<Self>,
    ) -> Result<Self::Scalar> {
        let blind_plaintext = Self::decrypt(decryption_key, ciphertext)?;
        Ok(blind_plaintext - blinder)
    }

    /// Decrypt the ciphertext given the decryption shares and unblind using the blinding factor
    fn decrypt_with_shares_and_unblind(
        blinder: &Self::Scalar,
        decryption_shares: &[DecryptionShare<Self>],
        ciphertext: &Ciphertext<Self>,
    ) -> Result<Self::Scalar> {
        let blind_plaintext = Self::decrypt_with_shares(decryption_shares, ciphertext)?;
        Ok(blind_plaintext - blinder)
    }

    /// Convert the verifiable encryption bytes to a scalar
    fn verifiable_encryption_bytes_to_scalar(bytes: &[u8]) -> Result<Self::Scalar> {
        let mut repr = <Self::Scalar as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(bytes);
        Option::<Self::Scalar>::from(Self::Scalar::from_repr(repr)).ok_or(Error::InvalidKey)
    }
}

impl VerifiableEncryption for bulletproofs::k256::Secp256k1 {}

impl VerifiableEncryptionDecryptor for bulletproofs::k256::Secp256k1 {}

impl VerifiableEncryption for bulletproofs::p256::NistP256 {}

impl VerifiableEncryptionDecryptor for bulletproofs::p256::NistP256 {}

impl VerifiableEncryption for bulletproofs::Curve25519 {}

impl VerifiableEncryptionDecryptor for bulletproofs::Curve25519 {}

impl VerifiableEncryption for bulletproofs::bls12_381_plus::Bls12381G1 {}

impl VerifiableEncryptionDecryptor for bulletproofs::bls12_381_plus::Bls12381G1 {}

impl VerifiableEncryption for bulletproofs::blstrs_plus::Bls12381G1 {}

impl VerifiableEncryptionDecryptor for bulletproofs::blstrs_plus::Bls12381G1 {}

impl VerifiableEncryption for bulletproofs::p384::NistP384 {
    fn scalar_to_verifiable_encryption_bytes(scalar: &Self::Scalar) -> Vec<u8> {
        let mut bytes = vec![0u8; 64];
        bytes[16..].copy_from_slice(scalar.to_repr().as_ref());
        bytes
    }
}

impl VerifiableEncryptionDecryptor for bulletproofs::p384::NistP384 {
    fn verifiable_encryption_bytes_to_scalar(bytes: &[u8]) -> Result<Self::Scalar> {
        let mut repr = <Self::Scalar as PrimeField>::Repr::default();
        repr.copy_from_slice(&bytes[16..]);
        Option::<Self::Scalar>::from(Self::Scalar::from_repr(repr)).ok_or(Error::InvalidKey)
    }
}

impl VerifiableEncryption for bulletproofs::ed448::Ed448 {
    fn scalar_to_verifiable_encryption_bytes(scalar: &Self::Scalar) -> Vec<u8> {
        let mut bytes = vec![0u8; 64];
        bytes[..57].copy_from_slice(scalar.to_repr().as_ref());
        bytes
    }
}

impl VerifiableEncryptionDecryptor for bulletproofs::ed448::Ed448 {
    fn verifiable_encryption_bytes_to_scalar(bytes: &[u8]) -> Result<Self::Scalar> {
        let mut repr = <Self::Scalar as PrimeField>::Repr::default();
        repr.copy_from_slice(&bytes[..57]);
        Option::<Self::Scalar>::from(Self::Scalar::from_repr(repr)).ok_or(Error::InvalidKey)
    }
}

pub trait KeyToScalar {
    type Curve: BulletproofCurveArithmetic;

    fn key_to_scalar(&self) -> <Self::Curve as BulletproofCurveArithmetic>::Scalar;
}

pub trait KeyToPoint {
    type Curve: BulletproofCurveArithmetic;

    fn key_to_point(&self) -> <Self::Curve as BulletproofCurveArithmetic>::Point;
}

impl KeyToScalar for bulletproofs::k256::SecretKey {
    type Curve = bulletproofs::k256::Secp256k1;

    fn key_to_scalar(&self) -> bulletproofs::k256::Scalar {
        *self.to_nonzero_scalar().deref()
    }
}

impl KeyToPoint for bulletproofs::k256::PublicKey {
    type Curve = bulletproofs::k256::Secp256k1;

    fn key_to_point(&self) -> bulletproofs::k256::ProjectivePoint {
        self.to_projective()
    }
}

impl KeyToScalar for bulletproofs::p256::SecretKey {
    type Curve = bulletproofs::p256::NistP256;

    fn key_to_scalar(&self) -> bulletproofs::p256::Scalar {
        *self.to_nonzero_scalar().deref()
    }
}

impl KeyToPoint for bulletproofs::p256::PublicKey {
    type Curve = bulletproofs::p256::NistP256;

    fn key_to_point(&self) -> bulletproofs::p256::ProjectivePoint {
        self.to_projective()
    }
}

#[test]
fn blind_encrypt_and_prove_k256_works() {
    use bulletproofs::k256::{Secp256k1, SecretKey};

    let mut rng = rand::thread_rng();
    let signing_key = SecretKey::random(&mut rng);
    let verification_key = signing_key.public_key();

    blind_encrypt_and_prove_works::<Secp256k1>(
        signing_key.key_to_scalar(),
        verification_key.key_to_point(),
    );
}

#[test]
fn blind_encrypt_and_prove_p256_works() {
    use bulletproofs::p256::{NistP256, SecretKey};

    let mut rng = rand::thread_rng();
    let signing_key = SecretKey::random(&mut rng);
    let verification_key = signing_key.public_key();

    blind_encrypt_and_prove_works::<NistP256>(
        signing_key.key_to_scalar(),
        verification_key.key_to_point(),
    );
}

#[test]
fn blind_encrypt_and_prove_curve25519_works() {
    use bulletproofs::{
        vsss_rs::curve25519::{WrappedRistretto, WrappedScalar},
        Curve25519,
    };

    let mut rng = rand::thread_rng();
    let signing_key = WrappedScalar::random(&mut rng);
    let verification_key = WrappedRistretto::generator() * signing_key;

    blind_encrypt_and_prove_works::<Curve25519>(signing_key, verification_key);
}

#[test]
fn blind_encrypt_and_prove_bls12381_works() {
    use bulletproofs::bls12_381_plus::{Bls12381G1, G1Projective, Scalar};

    let mut rng = rand::thread_rng();
    let signing_key = Scalar::random(&mut rng);
    let verification_key = G1Projective::generator() * signing_key;

    blind_encrypt_and_prove_works::<Bls12381G1>(signing_key, verification_key);
}

#[test]
fn blind_encrypt_and_prove_blst12381_works() {
    use bulletproofs::blstrs_plus::{Bls12381G1, G1Projective, Scalar};

    let mut rng = rand::thread_rng();
    let signing_key = Scalar::random(&mut rng);
    let verification_key = G1Projective::generator() * signing_key;

    blind_encrypt_and_prove_works::<Bls12381G1>(signing_key, verification_key);
}

#[cfg(test)]
fn blind_encrypt_and_prove_works<C: VerifiableEncryption + VerifiableEncryptionDecryptor>(
    signing_key: C::Scalar,
    _verification_key: C::Point,
) {
    use bulletproofs::vsss_rs::{shamir, DefaultShare, IdentifierPrimeField};

    let sk = IdentifierPrimeField(signing_key);

    let mut rng = rand::thread_rng();
    let shares = shamir::split_secret::<
        DefaultShare<IdentifierPrimeField<C::Scalar>, IdentifierPrimeField<C::Scalar>>,
    >(2, 3, &sk, &mut rng)
    .unwrap();
    let decryption_key = C::Scalar::random(&mut rng);
    let encryption_key = C::Point::generator() * decryption_key;
    let blinder = C::Scalar::random(&mut rng);

    let share1 = shares[0].value.0;
    let (ciphertext, proof) =
        C::blind_encrypt_and_prove(encryption_key, &share1, &blinder, &[], &mut rng);
    let share_verification_key = C::Point::generator() * share1;

    let res = C::verify(
        encryption_key,
        share_verification_key,
        &ciphertext,
        &proof,
        &[],
    );
    assert!(res.is_err());
    let share_verification_key = C::Point::generator() * (share1 + blinder);
    let res = C::verify(
        encryption_key,
        share_verification_key,
        &ciphertext,
        &proof,
        &[],
    );
    assert!(res.is_ok());

    let res = C::decrypt(&decryption_key, &ciphertext);
    assert!(res.is_ok());
    assert_ne!(res.unwrap(), share1);

    let res = C::decrypt_and_verify(&decryption_key, &ciphertext, &proof);
    assert!(res.is_ok());
    assert_ne!(res.unwrap(), share1);

    let res = C::decrypt_and_unblind(&blinder, &decryption_key, &ciphertext);
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), share1);
}

#[test]
fn encrypt_and_prove_k256_works() {
    use bulletproofs::k256::{Secp256k1, SecretKey};

    let mut rng = rand::thread_rng();
    let signing_key = SecretKey::random(&mut rng);
    let verification_key = signing_key.public_key();

    encrypt_and_prove_works::<Secp256k1>(
        signing_key.key_to_scalar(),
        verification_key.key_to_point(),
    );
}

#[test]
fn encrypt_and_prove_p256_works() {
    use bulletproofs::p256::{NistP256, SecretKey};

    let mut rng = rand::thread_rng();
    let signing_key = SecretKey::random(&mut rng);
    let verification_key = signing_key.public_key();

    encrypt_and_prove_works::<NistP256>(
        signing_key.key_to_scalar(),
        verification_key.key_to_point(),
    );
}

#[test]
fn encrypt_and_prove_curve25519_works() {
    use bulletproofs::{
        vsss_rs::curve25519::{WrappedRistretto, WrappedScalar},
        Curve25519,
    };

    let mut rng = rand::thread_rng();
    let signing_key = WrappedScalar::random(&mut rng);
    let verification_key = WrappedRistretto::generator() * signing_key;

    encrypt_and_prove_works::<Curve25519>(signing_key, verification_key);
}

#[test]
fn encrypt_and_prove_bls12381_works() {
    use bulletproofs::bls12_381_plus::{Bls12381G1, G1Projective, Scalar};

    let mut rng = rand::thread_rng();
    let signing_key = Scalar::random(&mut rng);
    let verification_key = G1Projective::generator() * signing_key;

    encrypt_and_prove_works::<Bls12381G1>(signing_key, verification_key);
}

#[test]
fn encrypt_and_prove_blst12381_works() {
    use bulletproofs::blstrs_plus::{Bls12381G1, G1Projective, Scalar};

    let mut rng = rand::thread_rng();
    let signing_key = Scalar::random(&mut rng);
    let verification_key = G1Projective::generator() * signing_key;

    encrypt_and_prove_works::<Bls12381G1>(signing_key, verification_key);
}

#[test]
fn encrypt_and_prove_p384_works() {
    use bulletproofs::p384::{NistP384, ProjectivePoint, Scalar};

    let mut rng = rand::thread_rng();
    let signing_key = Scalar::random(&mut rng);
    let verification_key = ProjectivePoint::GENERATOR * signing_key;

    encrypt_and_prove_works::<NistP384>(signing_key, verification_key);
}

#[test]
fn encrypt_and_prove_ed448_works() {
    use bulletproofs::ed448::{Ed448, EdwardsPoint, Scalar};

    let mut rng = rand::thread_rng();
    let signing_key = Scalar::random(&mut rng);
    let verification_key = EdwardsPoint::GENERATOR * signing_key;

    encrypt_and_prove_works::<Ed448>(signing_key, verification_key);
}

#[cfg(test)]
fn encrypt_and_prove_works<C: VerifiableEncryption + VerifiableEncryptionDecryptor>(
    signing_key: C::Scalar,
    _verification_key: C::Point,
) {
    use bulletproofs::vsss_rs::{shamir, DefaultShare, IdentifierPrimeField};

    let mut rng = rand::thread_rng();
    let sk = IdentifierPrimeField(signing_key);
    let shares = shamir::split_secret::<
        DefaultShare<IdentifierPrimeField<C::Scalar>, IdentifierPrimeField<C::Scalar>>,
    >(2, 3, &sk, &mut rng)
    .unwrap();
    let decryption_key = C::Scalar::random(&mut rng);
    let encryption_key = C::Point::generator() * decryption_key;

    let share1 = shares[0].value.0;
    let (ciphertext, proof) = C::encrypt_and_prove(encryption_key, &share1, &[], &mut rng);
    let share_verification_key = C::Point::generator() * share1;

    let res = C::verify(
        encryption_key,
        share_verification_key,
        &ciphertext,
        &proof,
        &[],
    );
    assert!(res.is_ok());

    let res = C::decrypt(&decryption_key, &ciphertext);
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), share1);

    let res = C::decrypt_and_verify(&decryption_key, &ciphertext, &proof);
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), share1);
}

#[test]
fn k256_proof_serde_works() {
    ciphertext_proof_serde_works::<bulletproofs::k256::Secp256k1>();
}

#[test]
fn p256_proof_serde_works() {
    ciphertext_proof_serde_works::<bulletproofs::p256::NistP256>();
}

#[test]
fn curve25519_proof_serde_works() {
    ciphertext_proof_serde_works::<bulletproofs::Curve25519>();
}

#[test]
fn bls12381_proof_serde_works() {
    ciphertext_proof_serde_works::<bulletproofs::bls12_381_plus::Bls12381G1>();
}

#[test]
fn blst12381_proof_serde_works() {
    ciphertext_proof_serde_works::<bulletproofs::blstrs_plus::Bls12381G1>();
}

#[test]
fn ed448_proof_serde_works() {
    ciphertext_proof_serde_works::<bulletproofs::ed448::Ed448>();
}

#[cfg(test)]
fn ciphertext_proof_serde_works<
    C: VerifiableEncryption + VerifiableEncryptionDecryptor + Eq + PartialEq,
>() {
    let mut rng = rand::thread_rng();
    let signing_key = C::Scalar::random(&mut rng);

    let decryption_key = C::Scalar::random(&mut rng);
    let encryption_key = C::Point::generator() * decryption_key;

    let (ciphertext, proof) = C::encrypt_and_prove(encryption_key, &signing_key, &[], &mut rng);

    let bytes = serde_bare::to_vec(&ciphertext).unwrap();
    let ciphertext2: Ciphertext<C> = serde_bare::from_slice(&bytes).unwrap();
    assert_eq!(ciphertext.c1, ciphertext2.c1);
    assert_eq!(ciphertext.c2, ciphertext2.c2);

    let json = serde_json::to_string(&ciphertext).unwrap();
    let ciphertext2: Ciphertext<C> = serde_json::from_str(&json).unwrap();
    assert_eq!(ciphertext.c1, ciphertext2.c1);
    assert_eq!(ciphertext.c2, ciphertext2.c2);

    let bytes = serde_bare::to_vec(&proof).unwrap();
    let proof2: Proof<C> = serde_bare::from_slice(&bytes).unwrap();
    assert_eq!(proof.dlog_proof, proof2.dlog_proof);
    assert_eq!(proof.challenge, proof2.challenge);

    let json = serde_json::to_string(&proof).unwrap();
    let proof2: Proof<C> = serde_json::from_str(&json).unwrap();
    assert_eq!(proof.dlog_proof, proof2.dlog_proof);
    assert_eq!(proof.challenge, proof2.challenge);
}

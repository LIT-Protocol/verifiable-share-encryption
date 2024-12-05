mod byte_proof;
mod ciphertext;
mod decryption_share;
mod dlog_proof;
mod proof;
mod serdes;

pub use byte_proof::*;
pub use ciphertext::*;
pub use decryption_share::*;
pub use dlog_proof::*;
pub use proof::*;

use bulletproofs::{
    group::{
        ff::{Field, PrimeField},
        Group,
    },
    merlin::Transcript,
    BulletproofCurveArithmetic, BulletproofGens, PedersenGens, RangeProof, TranscriptProtocol,
};
use legacy_vsss_rs::Share;
use rand_core::{CryptoRng, RngCore};

use crate::{Error, Result};

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
        let key_repr = key_share.to_repr();
        let key_bytes = key_repr.as_ref();
        let mut key_segments = [0u64; 32];
        key_segments
            .iter_mut()
            .zip(key_bytes.iter())
            .for_each(|(segment, byte)| {
                *segment = *byte as u64;
            });
        let mut blinders = [Self::Scalar::ZERO; 32];
        blinders.iter_mut().for_each(|blinder| {
            *blinder = Self::Scalar::random(&mut rng);
        });
        let bp_gens = BulletproofGens::new(8, 32);
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
        let mut c1s = [Self::Point::identity(); 32];
        c1s.iter_mut()
            .zip(blinders.iter())
            .for_each(|(c1, r)| *c1 = Self::Point::generator() * r);

        let mut blinder_blinders = [Self::Scalar::ZERO; 32];
        blinder_blinders
            .iter_mut()
            .for_each(|s| *s = Self::Scalar::random(&mut rng));

        transcript.append_message(b"elgamal_segment_proofs", &[32]);
        for i in 0..32 {
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

        let mut byte_proofs = [ByteProof::<Self>::default(); 32];
        byte_proofs.iter_mut().enumerate().for_each(|(i, p)| {
            p.message = blinders[i] - challenge * Self::Scalar::from(key_bytes[i] as u64);
            p.blinder = blinder_blinders[i] - challenge * blinders[i];
        });

        let mut c2 = [Self::Point::identity(); 32];
        c2.iter_mut().zip(c2s.iter()).for_each(|(c2, i)| *c2 = *i);

        (
            Ciphertext { c1: c1s, c2 },
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
        let mut transcript = Transcript::new(b"ElGamalVerifiableEncryption");
        let bp_gens = BulletproofGens::new(8, 32);
        let pc_gens = PedersenGens {
            B: Self::Point::generator(),
            B_blinding: encryption_key,
        };
        proof
            .range_proof
            .verify_multiple(&bp_gens, &pc_gens, &mut transcript, &ciphertext.c2, 8)
            .map_err(|_e| Error::InvalidRangeProof)?;

        transcript.append_message(b"elgamal_segment_proofs", &[32]);
        for i in 0..32 {
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
}

/// A trait for types that can use ElGamal decryption scheme for a scalar
pub trait VerifiableEncryptionDecryptor: BulletproofCurveArithmetic {
    /// Decrypt the ciphertext using the decryption key
    fn decrypt(
        decryption_key: &Self::Scalar,
        ciphertext: &Ciphertext<Self>,
    ) -> Result<Self::Scalar> {
        use rayon::prelude::*;

        let mut repr = <Self::Scalar as PrimeField>::Repr::default();

        repr.as_mut().par_iter_mut().enumerate().for_each(|(i, b)| {
            let vi = ciphertext.c2[i] - ciphertext.c1[i] * *decryption_key;

            for ki in 0u8..=255 {
                let si = Self::Scalar::from(ki as u64);
                if vi == Self::Point::generator() * si {
                    *b = ki;
                    break;
                }
            }
        });
        Option::<Self::Scalar>::from(Self::Scalar::from_repr(repr)).ok_or(Error::InvalidKey)
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
    fn decrypt_with_shares<P: Share<Identifier = u8>>(
        decryption_shares: &[DecryptionShare<P, Self>],
        ciphertext: &Ciphertext<Self>,
    ) -> Result<Self::Scalar> {
        use rayon::prelude::*;

        let mut repr = <Self::Scalar as PrimeField>::Repr::default();
        let mut decryption_parts = Vec::with_capacity(32);
        for i in 0..32 {
            let parts = decryption_shares
                .iter()
                .map(|s| s.inner[i].clone())
                .collect::<Vec<_>>();
            let share = legacy_vsss_rs::combine_shares_group::<Self::Point, u8, P>(&parts)
                .map_err(|_| Error::InvalidDecryptionShare)?;
            decryption_parts.push(share);
        }

        repr.as_mut()
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
        Option::<Self::Scalar>::from(Self::Scalar::from_repr(repr)).ok_or(Error::InvalidKey)
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
    fn decrypt_with_shares_and_unblind<P: Share<Identifier = u8>>(
        blinder: &Self::Scalar,
        decryption_shares: &[DecryptionShare<P, Self>],
        ciphertext: &Ciphertext<Self>,
    ) -> Result<Self::Scalar> {
        let blind_plaintext = Self::decrypt_with_shares(decryption_shares, ciphertext)?;
        Ok(blind_plaintext - blinder)
    }
}

impl VerifiableEncryption for bulletproofs::k256::Secp256k1 {}

impl VerifiableEncryptionDecryptor for bulletproofs::k256::Secp256k1 {}

impl VerifiableEncryption for bulletproofs::p256::NistP256 {}

impl VerifiableEncryptionDecryptor for bulletproofs::p256::NistP256 {}

impl VerifiableEncryption for bulletproofs::Ristretto25519 {}

impl VerifiableEncryptionDecryptor for bulletproofs::Ristretto25519 {}

impl VerifiableEncryption for bulletproofs::Ed25519 {}

impl VerifiableEncryptionDecryptor for bulletproofs::Ed25519 {}

impl VerifiableEncryption for bulletproofs::bls12_381_plus::Bls12381G1 {}

impl VerifiableEncryptionDecryptor for bulletproofs::bls12_381_plus::Bls12381G1 {}

impl VerifiableEncryption for bulletproofs::blstrs_plus::Bls12381G1 {}

impl VerifiableEncryptionDecryptor for bulletproofs::blstrs_plus::Bls12381G1 {}

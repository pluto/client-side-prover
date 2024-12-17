//! This module defines a collection of traits that define the behavior of a
//! `zkSNARK` for `RelaxedR1CS`
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{
    errors::NovaError,
    r1cs::{R1CSShape, RelaxedR1CSInstance, RelaxedR1CSWitness},
    traits::Engine,
    CommitmentKey,
};

// NOTES: This function seems heavily reliant on dynamic allocation all to
// return 0 in the end...

/// Public parameter creation takes a size hint. This size hint carries the
/// particular requirements of the final compressing SNARK the user expected to
/// use with these public parameters, and the below is a sensible default, which
/// is to not require any more bases then the usual (maximum of the number of
/// variables and constraints of the involved R1CS circuit).
pub fn default_ck_hint<E: Engine>() -> Box<dyn for<'a> Fn(&'a R1CSShape<E>) -> usize> {
    // The default is to not put an additional floor on the size of the commitment
    // key
    Box::new(|_shape: &R1CSShape<E>| 0)
}

// NOTES: I'm not sure having a trait here is really necessary unless you're
// wanting to have a much larger abstraction. I'd consider just gutting this and
// forming one SNARK that we use.

/// A trait that defines the behavior of a `zkSNARK`
pub trait RelaxedR1CSSNARKTrait<E: Engine>:
    Send + Sync + Serialize + for<'de> Deserialize<'de>
{
    /// A type that represents the prover's key
    type ProverKey: Send + Sync;

    /// A type that represents the verifier's key
    type VerifierKey: Send + Sync + Serialize;

    /// This associated function (not a method) provides a hint that offers
    /// a minimum sizing cue for the commitment key used by this SNARK
    /// implementation. The commitment key passed in setup should then
    /// be at least as large as this hint.
    fn ck_floor() -> Box<dyn for<'a> Fn(&'a R1CSShape<E>) -> usize> {
        // The default is to not put an additional floor on the size of the commitment
        // key
        default_ck_hint()
    }

    /// Initialize a ProvingKey directly from a CommitmentKey and a
    /// already known vk_digest.
    fn initialize_pk(
        ck: Arc<CommitmentKey<E>>,
        vk_digest: E::Scalar,
    ) -> Result<Self::ProverKey, NovaError>;

    /// Produces the keys for the prover and the verifier
    fn setup(
        ck: Arc<CommitmentKey<E>>,
        S: &R1CSShape<E>,
    ) -> Result<(Self::ProverKey, Self::VerifierKey), NovaError>;

    /// Produces a new SNARK for a relaxed R1CS
    fn prove(
        ck: &CommitmentKey<E>,
        pk: &Self::ProverKey,
        S: &R1CSShape<E>,
        U: &RelaxedR1CSInstance<E>,
        W: &RelaxedR1CSWitness<E>,
    ) -> Result<Self, NovaError>;

    /// Verifies a SNARK for a relaxed R1CS
    fn verify(&self, vk: &Self::VerifierKey, U: &RelaxedR1CSInstance<E>) -> Result<(), NovaError>;
}

/// A trait that defines the behavior of a `zkSNARK` to prove knowledge of
/// satisfying witness to batches of relaxed R1CS instances.
pub trait BatchedRelaxedR1CSSNARKTrait<E: Engine>:
    Send + Sync + Serialize + for<'de> Deserialize<'de>
{
    /// A type that represents the prover's key
    type ProverKey: Send + Sync + Serialize + for<'de> Deserialize<'de>;

    /// A type that represents the verifier's key
    type VerifierKey: Send + Sync + DigestHelperTrait<E> + Serialize + for<'de> Deserialize<'de>;

    // NOTES: If we don't need something more general here, this is just an odd
    // thing to have defined generically since it just calls the weird function
    // above.

    /// This associated function (not a method) provides a hint that offers
    /// a minimum sizing cue for the commitment key used by this SNARK
    /// implementation. The commitment key passed in setup should then
    /// be at least as large as this hint.
    fn ck_floor() -> Box<dyn for<'a> Fn(&'a R1CSShape<E>) -> usize> {
        default_ck_hint()
    }

    /// Initialize a ProvingKey directly from a CommitmentKey and a
    /// already known vk_digest.
    fn initialize_pk(
        ck: Arc<CommitmentKey<E>>,
        vk_digest: E::Scalar,
    ) -> Result<Self::ProverKey, NovaError>;

    /// Produces the keys for the prover and the verifier
    ///
    /// **Note:** This method should be cheap and should not copy most of the
    /// commitment key. Look at `CommitmentEngineTrait::setup` for generating
    /// SRS data.
    fn setup(
        ck: Arc<CommitmentKey<E>>, // NOTES: Why `Arc` this?
        S: Vec<&R1CSShape<E>>,     /* NOTES: Why not a &[R1CSShape] here?, would get the same
                                    * thing across as an iter i think */
    ) -> Result<(Self::ProverKey, Self::VerifierKey), NovaError>;

    /// Produces a new SNARK for a batch of relaxed R1CS
    fn prove(
        ck: &CommitmentKey<E>,
        pk: &Self::ProverKey,
        S: Vec<&R1CSShape<E>>,
        U: &[RelaxedR1CSInstance<E>],
        W: &[RelaxedR1CSWitness<E>],
    ) -> Result<Self, NovaError>;

    /// Verifies a SNARK for a batch of relaxed R1CS
    fn verify(&self, vk: &Self::VerifierKey, U: &[RelaxedR1CSInstance<E>])
        -> Result<(), NovaError>;
}

/// A helper trait that defines the behavior of a verifier key of `zkSNARK`
pub trait DigestHelperTrait<E: Engine> {
    /// Returns the digest of the verifier's key
    fn digest(&self) -> E::Scalar;
}

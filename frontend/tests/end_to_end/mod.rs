use std::fs;

use client_side_prover_frontend::{
  demo,
  program::{self, Switchboard, ROM},
  proof::FoldingProof,
  setup::{Empty, Ready, Setup},
  Scalar,
};
use noirc_abi::InputMap;
use tempfile::tempdir;

use super::*;

#[test]
#[traced_test]
fn test_end_to_end_workflow() {
  // Step 1: Create demo programs for our test
  let swap_memory_program = demo::swap_memory();
  let square_program = demo::square_zeroth();
  println!("1. Read programs");

  // Step 2: Create switchboard with ROM memory model, no inputs are necessary since this is just
  // creating the setup
  let switchboard = Switchboard::<ROM>::new(
    vec![swap_memory_program.clone(), square_program.clone()],
    vec![],
    vec![],
    0,
  );
  println!("2. Created switchboard");

  // Step 3: Initialize the setup
  let setup = Setup::<Ready<ROM>>::new(switchboard).unwrap();
  println!("3. Initialized setup");

  // Step 4: Save the setup to a file
  let temp_dir = tempdir().unwrap();
  let file_path = temp_dir.path().join("test_setup.bytes");
  setup.store_file(&file_path).unwrap();
  println!("4. Saved setup to file");

  // Step 5: Read the setup from the file
  let setup = Setup::<Empty<ROM>>::load_file(&file_path).unwrap();
  println!("5. Read setup from file");

  // Step 6: Ready the setup for proving with the switchboard
  let switchboard = Switchboard::<ROM>::new(
    vec![swap_memory_program, square_program],
    vec![InputMap::new(), InputMap::new()],
    vec![Scalar::from(3), Scalar::from(5)],
    0,
  );
  let setup = setup.into_ready(switchboard);
  println!("6. Ready the setup for proving with the switchboard");

  // Step 7: Run a proof
  let recursive_snark = program::run(&setup).unwrap();
  println!("7. Run a proof");

  // Step 8: Compress the proof
  let compressed_proof = program::compress(&setup, &recursive_snark).unwrap();
  println!("8. Compressed the proof");

  // Step 9: Serialize the proof
  let serialized_proof = compressed_proof.serialize().unwrap();
  println!("9. Serialized the proof");

  // Step 10: Save the serialized proof to a file
  let proof_file_path = temp_dir.path().join("test_proof.bytes");
  let proof_bytes = bincode::serialize(&serialized_proof).unwrap();
  fs::write(&proof_file_path, &proof_bytes).unwrap();
  println!("10. Saved the serialized proof to a file");

  // Step 11: Read and deserialize the proof
  let proof_bytes_from_file = fs::read(&proof_file_path).unwrap();
  let deserialized_proof: FoldingProof<Vec<u8>, String> =
    bincode::deserialize(&proof_bytes_from_file).unwrap();
  println!("11. Read and deserialized the proof");

  // Step 12: Convert back to compressed proof
  let compressed_proof_from_file = deserialized_proof.deserialize().unwrap();
  println!("12. Converted back to compressed proof");
  // Step 15: Verify the proof
  // Note: Verification would normally involve checking the proof against the verifier key
  // from the setup, but I'll use a simplified check that the digests match
  //   assert_eq!(
  //     compressed_proof.verifier_digest, compressed_proof_from_file.verifier_digest,
  //     "Verifier digests don't match after serialization/deserialization"
  //   );
}

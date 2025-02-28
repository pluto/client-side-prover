use std::collections::HashMap;

use acvm::{
  acir::{
    acir_field::GenericFieldElement,
    circuit::{brillig::BrilligBytecode, Circuit, Opcode, Program},
    native_types::{Witness, WitnessMap},
  },
  blackbox_solver::StubbedBlackBoxSolver,
  pwg::ACVM,
  AcirField,
};
use ark_bn254::Fr;
use bellpepper_core::{
  num::AllocatedNum, ConstraintSystem, Index, LinearCombination, SynthesisError, Variable,
};
use client_side_prover::supernova::StepCircuit;
use ff::PrimeField;
use tracing::trace;

use super::*;
use crate::program::SwitchboardWitness;

// TODO: If we deserialize more here and get metadata, we could more easily look at witnesses, etc.
// Especially if we want to output a constraint to the PC. Using the abi would be handy for
// assigning inputs.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NoirProgram {
  #[serde(rename = "noir_version")]
  pub version:       String,
  pub hash:          u64,
  pub abi:           NoirAbi,
  #[serde(
    serialize_with = "Program::serialize_program_base64",
    deserialize_with = "Program::deserialize_program_base64"
  )]
  pub bytecode:      Program<GenericFieldElement<Fr>>,
  pub debug_symbols: String,
  pub file_map:      HashMap<String, String>,
  pub names:         Vec<String>,
  pub brillig_names: Vec<String>,
  #[serde(skip)]
  pub witness:       Option<SwitchboardWitness>,
  #[serde(skip)]
  pub index:         usize,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NoirAbi {
  pub parameters:  Vec<NoirParameter>,
  pub return_type: NoirReturnType,
  pub error_types: HashMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NoirParameter {
  pub name:           String,
  #[serde(rename = "type")]
  pub parameter_type: NoirType,
  pub visibility:     String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NoirReturnType {
  pub abi_type:   NoirType,
  pub visibility: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum NoirType {
  Simple {
    kind: String,
  },
  Array {
    kind:         String,
    length:       usize,
    #[serde(rename = "type")]
    element_type: Box<NoirType>,
  },
  Tuple {
    kind:   String,
    fields: Vec<NoirType>,
  },
}

impl NoirProgram {
  pub fn new(bin: &[u8]) -> Self { serde_json::from_slice(bin).unwrap() }

  pub fn arity(&self) -> usize { self.circuit().public_parameters.0.len() }

  pub fn circuit(&self) -> &Circuit<GenericFieldElement<Fr>> { &self.bytecode.functions[0] }

  pub fn unconstrained_functions(&self) -> &Vec<BrilligBytecode<GenericFieldElement<Fr>>> {
    &self.bytecode.unconstrained_functions
  }

  pub fn set_inputs(&mut self, switchboard_witness: SwitchboardWitness) {
    self.witness = Some(switchboard_witness);
  }
}

impl StepCircuit<F<G1>> for NoirProgram {
  // NOTE: +1 for the PC
  fn arity(&self) -> usize { self.arity() + 1 }

  fn circuit_index(&self) -> usize { self.index }

  // TODO: we now need to shift this to use the `z` values as the sole public inputs, the struct
  // should only hold witness
  // TODO: We should check if the constraints for z are actually done properly
  // tell clippy to shut up
  #[allow(clippy::too_many_lines)]
  fn synthesize<CS: ConstraintSystem<F<G1>>>(
    &self,
    cs: &mut CS,
    pc: Option<&AllocatedNum<F<G1>>>,
    z: &[AllocatedNum<F<G1>>],
  ) -> Result<(Option<AllocatedNum<F<G1>>>, Vec<AllocatedNum<F<G1>>>), SynthesisError> {
    dbg!(z);
    let mut acvm = if self.witness.is_some() {
      Some(ACVM::new(
        &StubbedBlackBoxSolver(false),
        &self.circuit().opcodes,
        WitnessMap::new(),
        self.unconstrained_functions(),
        &[],
      ))
    } else {
      None
    };

    // TODO: This is a bit hacky. For NIVC folding in particular:
    assert_eq!(self.circuit().return_values.0.len() - 1, self.circuit().public_parameters.0.len());

    // TODO: we could probably avoid this but i'm lazy
    // Create a map to track allocated variables for the cs
    let mut allocated_vars: HashMap<Witness, AllocatedNum<F<G1>>> = HashMap::new();

    // TODO: Hacking here to get the first index of public, assuming the come in a block. This is
    // really dirty too
    let num_private_inputs = dbg!(self.circuit().private_parameters.len());

    // Set up public inputs
    self.circuit().public_parameters.0.iter().for_each(|witness| {
      println!("public instance: {witness:?}");
      let var = z[witness.as_usize() - num_private_inputs].clone();
      if self.witness.is_some() {
        trace!("overwriting public {witness:?} with {var:?}");
        // TODO: This is a bit hacky and assumes private inputs come first. I don't like that
        acvm
          .as_mut()
          .unwrap()
          .overwrite_witness(*witness, convert_to_acir_field(var.get_value().unwrap()));
      }
      // TODO: Fix unwrap
      // Alloc 1 for now and update later as needed
      // let var = AllocatedNum::alloc(&mut *cs, || Ok(F::<G1>::ONE)).unwrap();
      // println!("AllocatedNum pub input: {var:?}");

      allocated_vars.insert(*witness, var);
    });

    // Set up private inputs
    self.circuit().private_parameters.iter().for_each(|witness| {
      let f = self.witness.as_ref().map(|inputs| {
        let f = convert_to_acir_field(inputs.witness[witness.as_usize()]);
        acvm.as_mut().unwrap().overwrite_witness(*witness, f);
        f
      });
      let var = AllocatedNum::alloc(&mut *cs, || Ok(convert_to_halo2_field(f.unwrap_or_default())))
        .unwrap();
      allocated_vars.insert(*witness, var);
    });

    let acir_witness_map = if self.witness.is_some() {
      let _status = acvm.as_mut().unwrap().solve();
      Some(acvm.unwrap().finalize())
    } else {
      None
    };

    let get_witness_value = |witness: &Witness| -> F<G1> {
      acir_witness_map.as_ref().map_or(F::<G1>::ONE, |map| {
        map.get(witness).map_or(F::<G1>::ONE, |value| convert_to_halo2_field(*value))
      })
    };

    // Helper to get or create a variable for a witness
    let get_var = |witness: &Witness,
                   allocated_vars: &mut HashMap<Witness, AllocatedNum<F<G1>>>,
                   cs: &mut CS,
                   gate_idx: usize|
     -> Result<Variable, SynthesisError> {
      if let Some(var) = allocated_vars.get(witness) {
        Ok(var.get_variable())
      } else {
        let var = AllocatedNum::alloc(cs.namespace(|| format!("aux_{gate_idx}")), || {
          Ok(get_witness_value(witness))
        })?;
        allocated_vars.insert(*witness, var.clone());
        Ok(var.get_variable())
      }
    };

    // Process gates
    for (gate_idx, opcode) in self.circuit().opcodes.iter().enumerate() {
      if let Opcode::AssertZero(gate) = opcode {
        // Initialize empty linear combinations for each part of our R1CS constraint
        let mut left_terms = LinearCombination::zero();
        let mut right_terms = LinearCombination::zero();
        let mut final_terms = LinearCombination::zero();

        // Process multiplication terms (these form the A and B matrices in R1CS)
        for mul_term in &gate.mul_terms {
          let coeff = convert_to_halo2_field(mul_term.0);
          let left_var = get_var(&mul_term.1, &mut allocated_vars, cs, gate_idx)?;
          let right_var = get_var(&mul_term.2, &mut allocated_vars, cs, gate_idx)?;

          // Build Az (left terms) with coefficient
          left_terms = left_terms + (coeff, left_var);
          // Build Bz (right terms) with coefficient 1
          right_terms = right_terms + (F::<G1>::one(), right_var);
        }

        // Process addition terms (these contribute to the C matrix in R1CS)
        for add_term in &gate.linear_combinations {
          let coeff = convert_to_halo2_field(add_term.0);
          let var = get_var(&add_term.1, &mut allocated_vars, cs, gate_idx)?;
          final_terms = final_terms + (coeff, var);
        }

        // Handle constant term if present
        if !gate.q_c.is_zero() {
          let const_coeff = convert_to_halo2_field(gate.q_c);
          // Negate the constant term since we're moving it to the other side of the equation
          final_terms = final_terms - (const_coeff, Variable::new_unchecked(Index::Input(0)));
        }

        // Enforce the R1CS constraint: Az ∘ Bz = Cz
        cs.enforce(
          || format!("gate_{gate_idx}"),
          |_| left_terms.clone(),
          |_| right_terms.clone(),
          |_| final_terms,
        );
      }
    }

    let mut z_out = vec![];
    for ret in &self.circuit().return_values.0 {
      z_out.push(allocated_vars.get(ret).unwrap().clone());
    }

    // TODO: fix the pc
    Ok((z_out.last().cloned(), z_out))
  }
  // TODO: fix the pc
  // fn synthesize<CS: ConstraintSystem<F<G1>>>(
  //   &self,
  //   cs: &mut CS,
  //   pc: Option<&AllocatedNum<F<G1>>>,
  //   z: &[AllocatedNum<F<G1>>],
  // ) -> Result<(Option<AllocatedNum<F<G1>>>, Vec<AllocatedNum<F<G1>>>), SynthesisError> {
  //   let rom_index = &z[self.arity()]; // jump to where we pushed pc data into CS
  //   let allocated_rom = &z[self.arity() + 1..]; // jump to where we pushed rom data into C
  //   let mut circuit_constraints = self.vanilla_synthesize(cs, z)?;
  //   circuit_constraints.push(rom_index_next);
  //   circuit_constraints.extend(z[self.arity() + 1..].iter().cloned());
  //   Ok((Some(pc_next), circuit_constraints))
  // }
}

fn convert_to_halo2_field(f: GenericFieldElement<Fr>) -> F<G1> {
  let bytes = f.to_be_bytes();
  let mut arr = [0u8; 32];
  arr.copy_from_slice(&bytes[..32]);
  arr.reverse();
  F::<G1>::from_repr(arr).unwrap()
}

fn convert_to_acir_field(f: F<G1>) -> GenericFieldElement<Fr> {
  let mut bytes = f.to_bytes();
  bytes.reverse();
  GenericFieldElement::from_be_bytes_reduce(&bytes)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_conversions() {
    let f = F::<G1>::from(5);
    let acir_f = convert_to_acir_field(f);
    assert_eq!(acir_f, GenericFieldElement::from_repr(Fr::from(5)));

    let f = GenericFieldElement::from_repr(Fr::from(3));
    let halo2_f = convert_to_halo2_field(f);
    assert_eq!(halo2_f, F::<G1>::from(3));
  }
}

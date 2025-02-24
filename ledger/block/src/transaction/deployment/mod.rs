// Copyright 2024 Aleo Network Foundation
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(clippy::type_complexity)]

mod bytes;
mod serialize;
mod string;

use crate::Transaction;
use console::{
    network::prelude::*,
    program::{Identifier, ProgramID},
    types::Field,
};
use synthesizer_program::Program;
use synthesizer_snark::{Certificate, VerifyingKey};

#[derive(Clone, PartialEq, Eq)]
pub struct Deployment<N: Network> {
    /// The edition.
    edition: u16,
    /// The program.
    program: Program<N>,
    /// The mapping of function names to their verifying key and certificate.
    verifying_keys: Vec<(Identifier<N>, (VerifyingKey<N>, Certificate<N>))>,
}

impl<N: Network> Deployment<N> {
    /// Initializes a new deployment.
    pub fn new(
        edition: u16,
        program: Program<N>,
        verifying_keys: Vec<(Identifier<N>, (VerifyingKey<N>, Certificate<N>))>,
    ) -> Result<Self> {
        // Construct the deployment.
        let deployment = Self { edition, program, verifying_keys };
        // Ensure the deployment is ordered.
        deployment.check_is_ordered()?;
        // Return the deployment.
        Ok(deployment)
    }

    /// Checks that the deployment is ordered.
    pub fn check_is_ordered(&self) -> Result<()> {
        let program_id = self.program.id();

        // Ensure the edition matches.
        ensure!(
            self.edition == N::EDITION,
            "Deployed the wrong edition (expected '{}', found '{}').",
            N::EDITION,
            self.edition
        );
        // Ensure the program contains functions.
        ensure!(
            !self.program.functions().is_empty(),
            "No functions present in the deployment for program '{program_id}'"
        );
        // Ensure the deployment contains verifying keys.
        ensure!(
            !self.verifying_keys.is_empty(),
            "No verifying keys present in the deployment for program '{program_id}'"
        );

        // Ensure the number of functions matches the number of verifying keys.
        if self.program.functions().len() != self.verifying_keys.len() {
            bail!("Deployment has an incorrect number of verifying keys, according to the program.");
        }

        // Ensure the function and verifying keys correspond.
        for ((function_name, function), (name, _)) in self.program.functions().iter().zip_eq(&self.verifying_keys) {
            // Ensure the function name is correct.
            if function_name != function.name() {
                bail!("The function key is '{function_name}', but the function name is '{}'", function.name())
            }
            // Ensure the function name with the verifying key is correct.
            if name != function.name() {
                bail!("The verifier key is '{name}', but the function name is '{}'", function.name())
            }
        }

        ensure!(
            !has_duplicates(self.verifying_keys.iter().map(|(name, ..)| name)),
            "A duplicate function name was found"
        );

        Ok(())
    }

    /// Returns the size in bytes.
    pub fn size_in_bytes(&self) -> Result<u64> {
        Ok(u64::try_from(self.to_bytes_le()?.len())?)
    }

    /// Returns the edition.
    pub const fn edition(&self) -> u16 {
        self.edition
    }

    /// Returns the program.
    pub const fn program(&self) -> &Program<N> {
        &self.program
    }

    /// Returns the program.
    pub const fn program_id(&self) -> &ProgramID<N> {
        self.program.id()
    }

    /// Returns the verifying keys.
    pub const fn verifying_keys(&self) -> &Vec<(Identifier<N>, (VerifyingKey<N>, Certificate<N>))> {
        &self.verifying_keys
    }

    /// Returns the sum of the variable counts for all functions in this deployment.
    pub fn num_combined_variables(&self) -> Result<u64> {
        // Initialize the accumulator.
        let mut num_combined_variables = 0u64;
        // Iterate over the functions.
        for (_, (vk, _)) in &self.verifying_keys {
            // Add the number of variables.
            // Note: This method must be *checked* because the claimed variable count
            // is from the user, not the synthesizer.
            num_combined_variables = num_combined_variables
                .checked_add(vk.num_variables())
                .ok_or_else(|| anyhow!("Overflow when counting variables for '{}'", self.program_id()))?;
        }
        // Return the number of combined variables.
        Ok(num_combined_variables)
    }

    /// Returns the sum of the constraint counts for all functions in this deployment.
    pub fn num_combined_constraints(&self) -> Result<u64> {
        // Initialize the accumulator.
        let mut num_combined_constraints = 0u64;
        // Iterate over the functions.
        for (_, (vk, _)) in &self.verifying_keys {
            // Add the number of constraints.
            // Note: This method must be *checked* because the claimed constraint count
            // is from the user, not the synthesizer.
            num_combined_constraints = num_combined_constraints
                .checked_add(vk.circuit_info.num_constraints as u64)
                .ok_or_else(|| anyhow!("Overflow when counting constraints for '{}'", self.program_id()))?;
        }
        // Return the number of combined constraints.
        Ok(num_combined_constraints)
    }

    /// Returns the deployment ID.
    pub fn to_deployment_id(&self) -> Result<Field<N>> {
        Ok(*Transaction::deployment_tree(self, None)?.root())
    }
}

#[cfg(test)]
pub mod test_helpers {
    use super::*;
    use console::network::MainnetV0;
    use synthesizer_process::Process;

    use once_cell::sync::OnceCell;

    type CurrentNetwork = MainnetV0;
    type CurrentAleo = circuit::network::AleoV0;

    pub(crate) fn sample_deployment(rng: &mut TestRng) -> Deployment<CurrentNetwork> {
        static INSTANCE: OnceCell<Deployment<CurrentNetwork>> = OnceCell::new();
        INSTANCE
            .get_or_init(|| {
                // Initialize a new program.
                let (string, program) = Program::<CurrentNetwork>::parse(
                    r"
program testing.aleo;

mapping store:
    key as u32.public;
    value as u32.public;

function compute:
    input r0 as u32.private;
    add r0 r0 into r1;
    output r1 as u32.public;",
                )
                .unwrap();
                assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

                // Construct the process.
                let process = Process::load().unwrap();
                // Compute the deployment.
                let deployment = process.deploy::<CurrentAleo, _>(&program, rng).unwrap();
                // Return the deployment.
                // Note: This is a testing-only hack to adhere to Rust's dependency cycle rules.
                Deployment::from_str(&deployment.to_string()).unwrap()
            })
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use synthesizer_snark::VerifyingKey;
    use console::network::MainnetV0; // or your current network type

    #[test]
    fn test_parse_verifying_key() {
        // Hardcoded verifying key string (replace with your actual string)
        let verifying_key_str = "verifier1qygqqqqqqqqqqqr32gqqqqqqqqq825sqqqqqqqqqcmzqqqqqqqqqpkhqqqqqqqqqqrj8kqqqqqqqqqqvqqqqqqqqqqqd3x9mq9mdtvqp3ee4udmxtny6rnwsm2aueuhhtwsn7dqvsw8sns0rajz94ckxnud0rlr6q6ptzzuqwecemjfsh9nu28u87krfts8ynsea8agrsdf9gegcvfe5eu7zrxwcc74q8t3vt4xz8uur4tjv7hzcq5676m26nnajgntrlejh5a5yme2l4rq870ltqyysh6ks3tjqxqgfy953rvxck3unay2yqxekgwt0q9ngm4hwar04d3l0r48lxhd57qzd8y2alfsr75puqlps2kxjda82muh95z89m7hgrwn7gt8prwjahq8z2t5g7tg9ac2ytyln5nc8fdevfl49w5fu75ygn4r99jtj6y339m2whdutuxyj2knxehll2qpc0gqwla30x9rglr3lkyfrn26qu6q9x2ms0jp4anuacx8uyx35pam6f53tcru86h6vv58rhrxft69ugrvq056ucwde3pswpkr35qtgggzgaczq60judrv7gk43uj3ayhtzkmh945ljh4x6x9annw5z7w662emsznlwqhajqgj30pvuafedx25h7552utfpqskt4jauqxgg079tu50q7fmlaljk05n0v8h9cw7fnx7tqqc3lm2nfxy2zlwaqy447fnexle4jdq35096chtjy3lkwshmqx37mwn7dxl8ljm88xns6te4k9nxmq9v8tkeyzn39rflamhxx5pwyfdaq3mnnuvjhehh8t328r338nya9f8fs3wqnr0tyzltrg2pn630xzqjllzk25zdergrlrx0yqld3gemv89afxa0qmuzqpw3e9zchd2st2ksm8tk62tmugusfe2pxc3v6gspwsavgmvkf0jh70qsnpyqasgzfjw3rax2z630zp7ez6qmrhxeemdjvwrekaa02uwj6xapz28reqjcrffm0f4fa5hnemzxjwu022xhrtsdp27p9zqy24zy8mgx5pxagp4t93hsqqqqqqqqqeqz2nz";

        // Deserialize the verifying key.
        let vk = VerifyingKey::<MainnetV0>::from_str(verifying_key_str)
            .expect("Failed to parse verifying key");

        // Retrieve the number of variables.
        let num_variables = vk.num_variables();
        // Retrieve the number of constraints.
        let num_constraints = vk.circuit_info.num_constraints;

        // Print the results.
        println!("Number of variables: {}", num_variables);
        println!("Number of constraints: {}", num_constraints);
    }
}
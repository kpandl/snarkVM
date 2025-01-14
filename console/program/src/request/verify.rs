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

use super::*;

impl<N: Network> Request<N> {
    /// Returns `true` if the request is valid, and `false` otherwise.
    ///
    /// Verifies (challenge == challenge') && (address == address') && (serial_numbers == serial_numbers') where:
    ///     challenge' := HashToScalar(r * G, pk_sig, pr_sig, signer, \[tvk, tcm, function ID, input IDs\])
    pub fn verify(&self, input_types: &[ValueType<N>], is_root: bool) -> bool {
        eprintln!("\n[DEBUG][request.verify] Starting verify. program_id = {:?}, function_name = {:?}",
                  self.program_id, self.function_name);
        eprintln!("[DEBUG][request.verify] is_root = {is_root}, #input_types = {}",
                  input_types.len());
        eprintln!("[DEBUG][request.verify] self.tvk = {:?}", self.tvk);
        eprintln!("[DEBUG][request.verify] self.tcm = {:?}", self.tcm);

        // 1) Verify the transition public key, transition view key, and transition commitment are well-formed.
        {
            match N::hash_psd2(&[self.tvk]) {
                Ok(tcm) => {
                    if tcm != self.tcm {
                        eprintln!("[DEBUG][request.verify] Invalid transition commitment. Computed = {:?}, in request = {:?}", tcm, self.tcm);
                        return false;
                    }
                }
                Err(error) => {
                    eprintln!("[DEBUG][request.verify] Failed to compute transition commitment: {error}");
                    return false;
                }
            }
        }

        // 2) Retrieve the challenge and response from the signature.
        let challenge = self.signature.challenge();
        let response = self.signature.response();
        eprintln!("[DEBUG][request.verify] signature.challenge() = {:?}", challenge);
        eprintln!("[DEBUG][request.verify] signature.response() = {:?}", response);

        // 3) Compute the function ID.
        let function_id = match compute_function_id(&self.network_id, &self.program_id, &self.function_name) {
            Ok(function_id) => function_id,
            Err(error) => {
                eprintln!("[DEBUG][request.verify] Failed to construct function ID: {error}");
                return false;
            }
        };
        eprintln!("[DEBUG][request.verify] Computed function_id = {:?}", function_id);

        // 4) Convert `is_root` into a field: 1 if root, else 0.
        let is_root_field = if is_root {
            Field::<N>::one()
        } else {
            Field::<N>::zero()
        };

        // 5) Construct the signature message as `[tvk, tcm, function_id, is_root, input IDs...]`.
        let mut message = Vec::with_capacity(4 + self.input_ids.len());
        message.push(self.tvk);
        message.push(self.tcm);
        message.push(function_id);
        message.push(is_root_field);

        eprintln!("[DEBUG][request.verify] #input_ids = {}, #inputs = {}, #input_types = {}",
                  self.input_ids.len(), self.inputs.len(), input_types.len());

        // 6) Check each input ID against the corresponding input and input type.
        let result = self
            .input_ids
            .iter()
            .zip_eq(&self.inputs)
            .zip_eq(input_types)
            .enumerate()
            .try_for_each(|(index, ((input_id, input), input_type))| {
                // We'll add logs around each match arm.

                eprintln!("[DEBUG][request.verify] Checking input #{} => id={:?}, input={:?}, input_type={:?}",
                          index, input_id, input, input_type);

                match input_id {
                    // ====================
                    // A) Constant input
                    // ====================
                    InputID::Constant(input_hash) => {
                        eprintln!("[DEBUG][request.verify] => Found InputID::Constant, verifying input hash");
                        ensure!(matches!(input, Value::Plaintext(..)), "[DEBUG][request.verify] Expected a plaintext input for Constant ID");

                        // Build the preimage.
                        let index_field = Field::from_u16(u16::try_from(index).or_halt_with::<N>("Input index exceeds u16"));
                        let mut preimage = Vec::new();
                        preimage.push(function_id);
                        preimage.extend(input.to_fields()?);
                        preimage.push(self.tcm);
                        preimage.push(index_field);

                        // Hash the input to a field element.
                        let candidate_hash = N::hash_psd8(&preimage)?;
                        ensure!(*input_hash == candidate_hash, "[DEBUG][request.verify] Constant input mismatch in hash");
                        message.push(candidate_hash);
                    }

                    // ====================
                    // B) Public input
                    // ====================
                    InputID::Public(input_hash) => {
                        eprintln!("[DEBUG][request.verify] => Found InputID::Public, verifying input hash");
                        ensure!(matches!(input, Value::Plaintext(..)), "[DEBUG][request.verify] Expected a plaintext input for Public ID");

                        // Build the preimage.
                        let index_field = Field::from_u16(u16::try_from(index).or_halt_with::<N>("Input index exceeds u16"));
                        let mut preimage = Vec::new();
                        preimage.push(function_id);
                        preimage.extend(input.to_fields()?);
                        preimage.push(self.tcm);
                        preimage.push(index_field);

                        let candidate_hash = N::hash_psd8(&preimage)?;
                        ensure!(*input_hash == candidate_hash, "[DEBUG][request.verify] Public input mismatch in hash");
                        message.push(candidate_hash);
                    }

                    // ====================
                    // C) Private input
                    // ====================
                    InputID::Private(input_hash) => {
                        eprintln!("[DEBUG][request.verify] => Found InputID::Private, verifying input encryption & hash");
                        ensure!(matches!(input, Value::Plaintext(..)), "[DEBUG][request.verify] Expected a plaintext input for Private ID");

                        let index_field = Field::from_u16(u16::try_from(index).or_halt_with::<N>("Input index exceeds u16"));
                        let input_view_key = N::hash_psd4(&[function_id, self.tvk, index_field])?;
                        let ciphertext = match &input {
                            Value::Plaintext(plaintext) => plaintext.encrypt_symmetric(input_view_key)?,
                            _ => bail!("[DEBUG][request.verify] Expected a plaintext input, found something else"),
                        };
                        let candidate_hash = N::hash_psd8(&ciphertext.to_fields()?)?;
                        ensure!(*input_hash == candidate_hash, "[DEBUG][request.verify] Private input mismatch in hash");
                        message.push(candidate_hash);
                    }

                    // ====================
                    // D) Record input
                    // ====================
                    InputID::Record(commitment, gamma, serial_number, tag) => {
                        eprintln!("[DEBUG][request.verify] => Found InputID::Record, verifying record commitment & serial number");
                        let record = match &input {
                            Value::Record(r) => r,
                            _ => bail!("[DEBUG][request.verify] Expected a record input, found something else"),
                        };
                        let record_name = match input_type {
                            ValueType::Record(rn) => rn,
                            _ => bail!("[DEBUG][request.verify] Mismatch: function input type was not 'record'"),
                        };
                        ensure!(**record.owner() == self.signer, "[DEBUG][request.verify] Input record does not belong to the signer");

                        // Commitment check
                        let candidate_cm = record.to_commitment(&self.program_id, record_name)?;
                        ensure!(*commitment == candidate_cm, "[DEBUG][request.verify] record commitment mismatch");

                        // Serial number check
                        let candidate_sn = Record::<N, Plaintext<N>>::serial_number_from_gamma(gamma, *commitment)?;
                        ensure!(*serial_number == candidate_sn, "[DEBUG][request.verify] record SN mismatch");

                        // Tag check
                        let h = N::hash_to_group_psd2(&[N::serial_number_domain(), *commitment])?;
                        let h_r = (*gamma * challenge) + (h * response);

                        let candidate_tag = N::hash_psd2(&[self.sk_tag, *commitment])?;
                        ensure!(*tag == candidate_tag, "[DEBUG][request.verify] record input tag mismatch");

                        // Add (H, h_r, gamma, tag) x-coordinates
                        message.extend([h, h_r, *gamma].iter().map(|point| point.to_x_coordinate()));
                        message.push(*tag);
                    }

                    // ====================
                    // E) External record
                    // ====================
                    InputID::ExternalRecord(input_hash) => {
                        eprintln!("[DEBUG][request.verify] => Found InputID::ExternalRecord, verifying locator hash");
                        ensure!(matches!(input, Value::Record(..)), "[DEBUG][request.verify] Expected a record input for external record ID");

                        let index_field = Field::from_u16(u16::try_from(index).or_halt_with::<N>("Input index exceeds u16"));
                        let mut preimage = Vec::new();
                        preimage.push(function_id);
                        preimage.extend(input.to_fields()?);
                        preimage.push(self.tvk);
                        preimage.push(index_field);

                        let candidate_hash = N::hash_psd8(&preimage)?;
                        ensure!(*input_hash == candidate_hash, "[DEBUG][request.verify] external record mismatch in hash");
                        message.push(candidate_hash);
                    }
                }
                Ok(())
            });

        // If any check failed:
        if let Err(error) = result {
            eprintln!("[DEBUG][request.verify] => Input check failed: {error}");
            return false;
        }

        eprintln!("[DEBUG][request.verify] All inputs passed checks. Now verifying signature with message len = {}", message.len());
        eprintln!("[DEBUG][request.verify] signer = {:?}", self.signer);

        // 7) Finally, verify the signature with the signer + message.
        let sig_ok = self.signature.verify(&self.signer, &message);
        eprintln!("[DEBUG][request.verify] signature.verify(...) = {}", sig_ok);
        if !sig_ok {
            eprintln!("[DEBUG][request.verify] => signature check failed!");
        }
        sig_ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_account::PrivateKey;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    pub(crate) const ITERATIONS: usize = 1000;

    #[test]
    fn test_sign_and_verify() {
        let rng = &mut TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a random private key and address.
            let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
            let address = Address::try_from(&private_key).unwrap();

            // Construct a program ID and function name.
            let program_id = ProgramID::from_str("token.aleo").unwrap();
            let function_name = Identifier::from_str("transfer").unwrap();

            // Prepare a record belonging to the address.
            let record_string = format!(
                "{{ owner: {address}.private, token_amount: 100u64.private, _nonce: 2293253577170800572742339369209137467208538700597121244293392265726446806023group.public }}"
            );

            // Construct four inputs.
            let input_constant = Value::from_str("{ token_amount: 9876543210u128 }").unwrap();
            let input_public = Value::from_str("{ token_amount: 9876543210u128 }").unwrap();
            let input_private = Value::from_str("{ token_amount: 9876543210u128 }").unwrap();
            let input_record = Value::from_str(&record_string).unwrap();
            let input_external_record = Value::from_str(&record_string).unwrap();
            let inputs = [input_constant, input_public, input_private, input_record, input_external_record];

            // Construct the input types.
            let input_types = vec![
                ValueType::from_str("amount.constant").unwrap(),
                ValueType::from_str("amount.public").unwrap(),
                ValueType::from_str("amount.private").unwrap(),
                ValueType::from_str("token.record").unwrap(),
                ValueType::from_str("token.aleo/token.record").unwrap(),
            ];

            // Sample 'root_tvk'.
            let root_tvk = None;
            // Sample 'is_root'.
            let is_root = Uniform::rand(rng);

            // Compute the signed request.
            let request = Request::sign(
                &private_key,
                program_id,
                function_name,
                inputs.into_iter(),
                &input_types,
                root_tvk,
                is_root,
                rng,
            )
            .unwrap();
            assert!(request.verify(&input_types, is_root));
        }
    }
}

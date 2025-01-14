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

impl<N: Network> Signature<N> {
    /// Verifies (challenge == candidate_challenge) && (address == candidate_address), where:
    ///     candidate_challenge := HashToScalar(G^response pk_sig^challenge, pk_sig, pr_sig, address, message).
    pub fn verify(&self, address: &Address<N>, message: &[Field<N>]) -> bool {
        // 1) Ensure the number of field elements does not exceed the maximum allowed size.
        if message.len() > N::MAX_DATA_SIZE_IN_FIELDS as usize {
            eprintln!("[DEBUG][signature.verify] The message has {} field elements, exceeding N::MAX_DATA_SIZE_IN_FIELDS = {}",
                message.len(),
                N::MAX_DATA_SIZE_IN_FIELDS
            );
            return false;
        }

        // 2) Retrieve pk_sig and pr_sig from the compute key.
        let pk_sig = self.compute_key.pk_sig();
        let pr_sig = self.compute_key.pr_sig();

        eprintln!("\n[DEBUG][signature.verify] Starting verify.");
        eprintln!("[DEBUG][signature.verify] self.challenge() = {:?}", self.challenge);
        eprintln!("[DEBUG][signature.verify] self.response()  = {:?}", self.response);
        eprintln!("[DEBUG][signature.verify] pk_sig           = {:?}", pk_sig);
        eprintln!("[DEBUG][signature.verify] pr_sig           = {:?}", pr_sig);
        eprintln!("[DEBUG][signature.verify] provided address = {:?}", address);
        eprintln!("[DEBUG][signature.verify] message length   = {} field elements", message.len());

        // 3) Compute `g_r` := (response * G) + (challenge * pk_sig).
        //    This is the ephemeral R used in the challenge hash.
        let g_r = N::g_scalar_multiply(&self.response) + (pk_sig * self.challenge);
        eprintln!("[DEBUG][signature.verify] computed ephemeral g_r = {:?}", g_r);

        // 4) Construct the hash input as [g_r, pk_sig, pr_sig, address, message].
        let mut preimage = Vec::with_capacity(4 + message.len());
        preimage.extend([g_r, pk_sig, pr_sig, **address].map(|point| point.to_x_coordinate()));
        preimage.extend(message);

        // 5) Hash to derive the verifier challenge, and return `false` if this operation fails.
        let candidate_challenge = match N::hash_to_scalar_psd8(&preimage) {
            Ok(ch) => {
                eprintln!("[DEBUG][signature.verify] candidate_challenge = {:?}", ch);
                ch
            }
            Err(error) => {
                eprintln!("[DEBUG][signature.verify] Failed to compute candidate challenge: {error}");
                return false;
            }
        };

        // 6) Derive the candidate address from the compute key.
        let candidate_address = match Address::try_from(self.compute_key) {
            Ok(addr) => {
                eprintln!("[DEBUG][signature.verify] candidate_address   = {:?}", addr);
                addr
            }
            Err(error) => {
                eprintln!("[DEBUG][signature.verify] Failed to derive address from compute key: {error}");
                return false;
            }
        };

        // 7) Check if challenge == candidate_challenge, and address == candidate_address.
        let challenge_match = (self.challenge == candidate_challenge);
        let address_match   = (*address == candidate_address);

        eprintln!("[DEBUG][signature.verify] => challenge match? {challenge_match}, address match? {address_match}");

        if !challenge_match {
            eprintln!(
                "[DEBUG][signature.verify] challenge mismatch: self.challenge = {:?}, candidate_challenge = {:?}",
                self.challenge, candidate_challenge
            );
        }
        if !address_match {
            eprintln!(
                "[DEBUG][signature.verify] address mismatch: *address = {:?}, candidate_address = {:?}",
                address, candidate_address
            );
        }

        let passed = challenge_match && address_match;
        if passed {
            eprintln!("[DEBUG][signature.verify] => signature check succeeded!");
        } else {
            eprintln!("[DEBUG][signature.verify] => signature check failed!");
        }
        passed
    }

    /// Verifies a signature for the given address and message (as bytes).
    pub fn verify_bytes(&self, address: &Address<N>, message: &[u8]) -> bool {
        // Convert the message into bits, and verify the signature.
        self.verify_bits(address, &message.to_bits_le())
    }

    /// Verifies a signature for the given address and message (as bits).
    pub fn verify_bits(&self, address: &Address<N>, message: &[bool]) -> bool {
        // Pack the bits into field elements, and then verify.
        match message
            .chunks(Field::<N>::size_in_data_bits())
            .map(Field::from_bits_le)
            .collect::<Result<Vec<_>>>()
        {
            Ok(fields) => self.verify(address, &fields),
            Err(error) => {
                eprintln!(
                    "[DEBUG][signature.verify_bits] Failed to convert bits to fields: {error}"
                );
                false
            }
        }
    }
}

#[cfg(test)]
#[cfg(feature = "private_key")]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    const ITERATIONS: u64 = 100;

    #[test]
    fn test_sign_and_verify() -> Result<()> {
        let rng = &mut TestRng::default();

        for i in 0..ITERATIONS {
            // Sample an address and a private key.
            let private_key = PrivateKey::<CurrentNetwork>::new(rng)?;
            let address = Address::try_from(&private_key)?;

            // Check that the signature is valid for the message.
            let message: Vec<_> = (0..i).map(|_| Uniform::rand(rng)).collect();
            let signature = Signature::sign(&private_key, &message, rng)?;
            assert!(signature.verify(&address, &message));

            // Check that the signature is invalid for an incorrect message.
            let failure_message: Vec<_> = (0..i).map(|_| Uniform::rand(rng)).collect();
            if message != failure_message {
                assert!(!signature.verify(&address, &failure_message));
            }
        }
        Ok(())
    }

    #[test]
    fn test_sign_and_verify_bytes() -> Result<()> {
        let rng = &mut TestRng::default();

        for i in 0..ITERATIONS {
            // Sample an address and a private key.
            let private_key = PrivateKey::<CurrentNetwork>::new(rng)?;
            let address = Address::try_from(&private_key)?;

            // Check that the signature is valid for the message.
            let message: Vec<_> = (0..i).map(|_| Uniform::rand(rng)).collect();
            let signature = Signature::sign_bytes(&private_key, &message, rng)?;
            assert!(signature.verify_bytes(&address, &message));

            // Check that the signature is invalid for an incorrect message.
            let failure_message: Vec<_> = (0..i).map(|_| Uniform::rand(rng)).collect();
            if message != failure_message {
                assert!(!signature.verify_bytes(&address, &failure_message));
            }
        }
        Ok(())
    }

    #[test]
    fn test_sign_and_verify_bits() -> Result<()> {
        let rng = &mut TestRng::default();

        for i in 0..ITERATIONS {
            // Sample an address and a private key.
            let private_key = PrivateKey::<CurrentNetwork>::new(rng)?;
            let address = Address::try_from(&private_key)?;

            // Check that the signature is valid for the message.
            let message: Vec<_> = (0..i).map(|_| Uniform::rand(rng)).collect();
            let signature = Signature::sign_bits(&private_key, &message, rng)?;
            assert!(signature.verify_bits(&address, &message));

            // Check that the signature is invalid for an incorrect message.
            let failure_message: Vec<_> = (0..i).map(|_| Uniform::rand(rng)).collect();
            if message != failure_message {
                assert!(!signature.verify_bits(&address, &failure_message));
            }
        }
        Ok(())
    }
}

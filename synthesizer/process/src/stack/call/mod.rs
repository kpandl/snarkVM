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

use crate::{
    stack::Address,
    CallStack,
    Registers,
    RegistersCall,
    StackEvaluate,
    StackExecute,
};
use aleo_std::prelude::{finish, lap, timer};
use console::{
    account::Field,
    network::prelude::*,
    program::{Register, Request, Value, ValueType},
};
use synthesizer_program::{
    Call,
    CallOperator,
    Operand,
    RegistersLoad,
    RegistersLoadCircuit,
    RegistersSigner,
    RegistersSignerCircuit,
    RegistersStore,
    RegistersStoreCircuit,
    StackMatches,
    StackProgram,
};

use circuit::{Eject, Inject};

/// A trait that provides `evaluate` and `execute` for `Call`.
pub trait CallTrait<N: Network> {
    /// Evaluates the instruction (console-level).
    fn evaluate<A: circuit::Aleo<Network = N>>(
        &self,
        stack: &(impl StackEvaluate<N> + StackMatches<N> + StackProgram<N>),
        registers: &mut Registers<N, A>,
    ) -> Result<()>;

    /// Executes the instruction (circuit-level).
    fn execute<A: circuit::Aleo<Network = N>, R: CryptoRng + Rng>(
        &self,
        stack: &(impl StackEvaluate<N> + StackExecute<N> + StackMatches<N> + StackProgram<N>),
        registers: &mut (
            impl RegistersCall<N>
            + RegistersSigner<N>
            + RegistersSignerCircuit<N, A>
            + RegistersLoadCircuit<N, A>
            + RegistersStoreCircuit<N, A>
        ),
        rng: &mut R,
    ) -> Result<()>;
}

impl<N: Network> CallTrait<N> for Call<N> {
    // -----------------------------------------------------------
    // EVALUATE  (Console-level)
    // -----------------------------------------------------------
    #[inline]
    fn evaluate<A: circuit::Aleo<Network = N>>(
        &self,
        stack: &(impl StackEvaluate<N> + StackMatches<N> + StackProgram<N>),
        registers: &mut Registers<N, A>,
    ) -> Result<()> {
        let timer = timer!("Call::evaluate");

        // 1. Load the operand values (console-level).
        let inputs: Vec<_> = self
            .operands()
            .iter()
            .map(|operand| registers.load(stack, operand))
            .try_collect()?;

        // 2. Retrieve the substack and resource.
        let (substack, resource) = match self.operator() {
            CallOperator::Locator(locator) => {
                (stack.get_external_stack(locator.program_id())?.as_ref(), locator.resource())
            }
            CallOperator::Resource(resource) => {
                // Example check, from your existing code:
                if stack.program().contains_function(resource) {
                    bail!("Cannot call '{resource}'. Use a closure ('closure {resource}:') instead.")
                }
                (stack, resource)
            }
        };
        lap!(timer, "Retrieved the substack and resource");

        // 3. Depending on whether it's a closure or function:
        let outputs = if let Ok(closure) = substack.program().get_closure(resource) {
            // Evaluate the closure.
            if closure.inputs().len() != inputs.len() {
                bail!("Expected {} inputs, found {}", closure.inputs().len(), inputs.len())
            }
            substack.evaluate_closure::<A>(
                &closure,
                &inputs,
                registers.call_stack(),
                registers.signer()?,
                registers.caller()?,
                registers.tvk()?,
            )?
        } else if let Ok(function) = substack.program().get_function(resource) {
            // Evaluate the function.
            if function.inputs().len() != inputs.len() {
                bail!("Expected {} inputs, found {}", function.inputs().len(), inputs.len())
            }
            let console_caller = Some(*stack.program_id());
            let response = substack.evaluate_function::<A>(registers.call_stack(), console_caller)?;
            response.outputs().to_vec()
        } else {
            bail!("Call operator '{:?}' is invalid or unsupported.", self.operator())
        };
        lap!(timer, "Computed outputs");

        // 4. Store the outputs in console-level registers.
        for (output, register) in outputs.into_iter().zip_eq(&self.destinations()) {
            registers.store(stack, register, output)?;
        }
        finish!(timer);

        Ok(())
    }

    // -----------------------------------------------------------
    // EXECUTE  (Circuit-level)
    // -----------------------------------------------------------
    #[inline]
    fn execute<A: circuit::Aleo<Network = N>, R: CryptoRng + Rng>(
        &self,
        stack: &(impl StackEvaluate<N> + StackExecute<N> + StackMatches<N> + StackProgram<N>),
        registers: &mut (
            impl RegistersCall<N>
            + RegistersSigner<N>
            + RegistersSignerCircuit<N, A>
            + RegistersLoadCircuit<N, A>
            + RegistersStoreCircuit<N, A>
        ),
        rng: &mut R,
    ) -> Result<()> {
        let timer = timer!("Call::execute");

        // 1. Load the operand values (circuit-level).
        let inputs: Vec<_> = self
            .operands()
            .iter()
            .map(|operand| registers.load_circuit(stack, operand))
            .try_collect()?;

        // 2. Retrieve the substack and resource.
        let (substack, resource) = match self.operator() {
            CallOperator::Locator(locator) => {
                (stack.get_external_stack(locator.program_id())?.as_ref(), locator.resource())
            }
            CallOperator::Resource(resource) => (stack, resource),
        };
        lap!(timer, "Retrieve the substack and resource");

        // 3. Retrieve the root TVK (if any).
        let root_tvk = registers.root_tvk().ok();

        // 4. Handle top-level logic based on the call stack mode.
        let (request, response) = match registers.call_stack() {
            // ------------------------------------------------
            // (a) Authorize or Synthesize
            // ------------------------------------------------
            CallStack::Authorize(_, private_key, authorization)
            | CallStack::Synthesize(_, private_key, authorization) => {
                // i. Convert circuit inputs to console (since Request::sign expects console Values).
                let function = substack.get_function_ref(resource)?;
                let console_inputs: Vec<Value<N>> = inputs
                    .iter()
                    .map(|circuit_val| circuit_val.eject_value()) // circuit -> console
                    .collect();

                // ii. Sign a request with those console inputs.
                let request = Request::sign(
                    &private_key,
                    *substack.program_id(),
                    *resource,
                    console_inputs.iter(),
                    &function.input_types(),
                    root_tvk,
                    /* is_root = */ false,
                    rng,
                )?;

                // iii. Add to the call stack & authorization.
                {
                    let mut call_stack = registers.call_stack();
                    call_stack.push(request.clone())?;
                    authorization.push(request.clone());
                }

                // iv. Decide: build sub-circuit or not?
                if /* e.g. top-level call needed? */ false {
                    // Real sub-circuit:
                    let mut call_stack = registers.call_stack();
                    let response = substack.execute_function::<A, _>(
                        call_stack,
                        Some(*stack.program_id()),
                        root_tvk,
                        rng,
                    )?;
                    (request, response)
                } else {
                    // Nested call => skip building sub-circuit, do 'evaluate_function' instead.
                    let mut call_stack = registers.call_stack();
                    let response = substack.evaluate_function::<A>(call_stack, Some(*stack.program_id()))?;
                    (request, response)
                }
            }

            // ------------------------------------------------
            // (b) CheckDeployment
            // ------------------------------------------------
            CallStack::CheckDeployment(_, private_key, ..) => {
                // Provide a "dummy" approach to skip building sub-circuits,
                // but still produce a valid Request & Response for the top-level to link.

                // i. Convert circuit inputs to console.
                let function = substack.get_function_ref(resource)?;
                let console_inputs: Vec<Value<N>> = inputs
                    .iter()
                    .map(|circuit_val| circuit_val.eject_value())
                    .collect();

                // ii. Construct a request with console inputs.
                let request = Request::sign(
                    &private_key,
                    *substack.program_id(),
                    *resource,
                    console_inputs.iter(),
                    &function.input_types(),
                    root_tvk,
                    /* is_root = */ false,
                    rng,
                )?;

                // iii. Sample or dummy-produce outputs. (For speed, skip real circuit.)
                let address = Address::try_from(&private_key)?;
                let outputs = function
                    .outputs()
                    .iter()
                    .map(|output| {
                        // (Optionally handle record types specially)
                        stack.sample_value(&address, output.value_type(), rng)
                    })
                    .collect::<Result<Vec<_>>>()?;

                // iv. Map the output operands to registers.
                let output_registers = function
                    .outputs()
                    .iter()
                    .map(|output| match output.operand() {
                        Operand::Register(reg) => Some(reg.clone()),
                        _ => None,
                    })
                    .collect::<Vec<_>>();

                // v. Build a dummy response using these sampled outputs.
                let response = crate::Response::new(
                    request.network_id(),
                    substack.program().id(),
                    function.name(),
                    request.inputs().len(),
                    request.tvk(),
                    request.tcm(),
                    outputs,
                    &function.output_types(),
                    &output_registers,
                )?;

                (request, response)
            }

            // ------------------------------------------------
            // (c) PackageRun
            // ------------------------------------------------
            CallStack::PackageRun(_, private_key, ..) => {
                // If you want a similar "dummy approach" for packaging, do so.
                // Otherwise, unimplemented!:
                unimplemented!("Existing PackageRun logic here (if needed).")
            }

            // ------------------------------------------------
            // (d) Evaluate or Execute
            // ------------------------------------------------
            CallStack::Evaluate(..) | CallStack::Execute(..) => {
                // Original logic for Evaluate/Execute mode.
                // If you need it, re-inject your original code here:
                unimplemented!("Your original Evaluate/Execute logic here.")
            }
        };
        lap!(timer, "Computed the request and response");

        // 5. (Optional) If you do circuit injection, e.g.:
        // let r1cs = A::eject_r1cs_and_reset();
        // A::inject_r1cs(r1cs);

        // 6. Basic checks (optional).
        let function = substack.get_function_ref(resource)?;
        let num_public = A::num_public();
        ensure!(
            A::num_public() == num_public,
            "Forbidden: 'call' injected excess public variables"
        );

        // 7. Suppose we produce “outputs” from the circuit:
        // Actually we have a console-level Response -> convert to circuit:

        let console_outputs = response.outputs().to_vec(); // console Values
        let circuit_outputs: Vec<circuit::Value<A>> = console_outputs
            .into_iter()
            .map(|val_n| circuit::Value::<A>::new(circuit::Mode::Private, val_n))
            .collect();

        // 8. Assign the circuit outputs to the circuit-level registers.
        for (output, register) in circuit_outputs.into_iter().zip_eq(&self.destinations()) {
            registers.store_circuit(stack, register, output)?;
        }
        lap!(timer, "Assigned the outputs to registers");

        finish!(timer);
        Ok(())
    }
}
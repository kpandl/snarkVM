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

use crate::{CallStack, Registers, RegistersCall, StackEvaluate, StackExecute, stack::Address};
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

use circuit::Eject;

pub trait CallTrait<N: Network> {
    /// Evaluates the instruction.
    fn evaluate<A: circuit::Aleo<Network = N>>(
        &self,
        stack: &(impl StackEvaluate<N> + StackMatches<N> + StackProgram<N>),
        registers: &mut Registers<N, A>,
    ) -> Result<()>;

    /// Executes the instruction.
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
    // EVALUATE
    // -----------------------------------------------------------
    #[inline]
    fn evaluate<A: circuit::Aleo<Network = N>>(
        &self,
        stack: &(impl StackEvaluate<N> + StackMatches<N> + StackProgram<N>),
        registers: &mut Registers<N, A>,
    ) -> Result<()> {
        let timer = timer!("Call::evaluate");

        // 1. Load the operand values.
        let inputs: Vec<_> = self.operands().iter().map(|operand| registers.load(stack, operand)).try_collect()?;

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
            bail!("Call operator '{}' is invalid or unsupported.", self.operator())
        };
        lap!(timer, "Computed outputs");

        // 4. Store the outputs.
        for (output, register) in outputs.into_iter().zip_eq(&self.destinations()) {
            registers.store(stack, register, output)?;
        }
        finish!(timer);

        Ok(())
    }

    // -----------------------------------------------------------
    // EXECUTE
    // -----------------------------------------------------------
    #[inline]
    fn execute<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(
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

        // 1. Load the operand values.
        let inputs: Vec<_> =
            self.operands().iter().map(|operand| registers.load_circuit(stack, operand)).try_collect()?;

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
            // ----------------------------------------
            // (a) Authorize or Synthesize mode
            // ----------------------------------------
            CallStack::Authorize(_, private_key, authorization)
            | CallStack::Synthesize(_, private_key, authorization) => {
                // i. Construct a Request.
                let function = substack.get_function_ref(resource)?;
                let console_inputs: Vec<Value<N>> = inputs
                .iter()
                .map(|circuit_val| circuit_val.eject_value())
                .collect();
                
                let request = Request::sign(
                    &private_key,
                    *substack.program_id(),
                    *resource,
                    console_inputs.iter(),
                    &function.input_types(),
                    root_tvk,
                    false,
                    rng,
                )?;
                
                // ii. Push the request onto the stack & authorization.
                {
                    let mut call_stack = registers.call_stack();
                    call_stack.push(request.clone())?;
                    authorization.push(request.clone());
                }
                // iii. Decide if we do a “real” sub-circuit or just evaluate/dummy:
                if /* e.g. top-level call needed? */ false {
                    // Real sub-circuit:
                    let mut call_stack = registers.call_stack();
                    let response = substack.execute_function::<A, _>(call_stack, Some(*stack.program_id()), root_tvk, rng)?;
                    (request, response)
                } else {
                    // For nested calls, skip the full circuit:
                    let mut call_stack = registers.call_stack();
                    let response = substack.evaluate_function::<A>(call_stack, Some(*stack.program_id()))?;
                    (request, response)
                }
            }

            // ----------------------------------------
            // (b) CheckDeployment or PackageRun mode
            // ----------------------------------------
            CallStack::CheckDeployment(_, private_key, ..) => {
                // (Your “dummy outputs” approach from previous PRs)
                unimplemented!("Existing CheckDeployment dummy logic from PR #1/#2")
            }
            CallStack::PackageRun(_, private_key, ..) => {
                unimplemented!("Existing PackageRun logic from PR #1/#2")
            }

            // ----------------------------------------
            // (c) Evaluate or Execute mode
            // ----------------------------------------
            CallStack::Evaluate(authorization) | CallStack::Execute(authorization, ..) => {
                unimplemented!("Your original Evaluate/Execute logic here")
            }
        };
        lap!(timer, "Computed the request and response");

        // 5. [Optional] If you do circuit injection, define r1cs or remove:
        //    e.g. let r1cs = A::eject_r1cs_and_reset();
        //    A::inject_r1cs(r1cs);

        // 6. For demonstration, let’s define `function` & do the standard “public var check” etc.
        let function = substack.get_function_ref(resource)?;
        let num_public = A::num_public();
        ensure!(A::num_public() == num_public, "Forbidden: 'call' injected excess public variables");

        // 7. E.g. do your TCM checks:
        // ...
        // (Omitted in this snippet — you can paste your final logic here.)

        // 8. Suppose we produce “outputs” from the circuit:

        // 3. Suppose you eventually build `response` which is also console-level `Response<N>`.
let console_outputs = response.outputs().to_vec(); // Vec<console::Value<N>>

// 4. Convert console -> circuit, if you want to store_circuit:
use circuit::Inject; // for circuit::Value::<A>::new(...)
let circuit_outputs: Vec<circuit::Value<A>> = console_outputs
    .into_iter()
    .map(|val_n| circuit::Value::<A>::new(circuit::Mode::Private, val_n))
    .collect();


        // 9. Assign the outputs to the destination registers.
        for (output, register) in circuit_outputs.into_iter().zip_eq(&self.destinations()) {
            registers.store_circuit(stack, register, output)?;
        }
        lap!(timer, "Assigned the outputs to registers");

        finish!(timer);
        Ok(())
    }
}
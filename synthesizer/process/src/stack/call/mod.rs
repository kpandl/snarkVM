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

        eprintln!(
            "\n[Call::evaluate] operator = {:?}, call stack mode (?) = (no direct info, but stack below)\n\
             [Call::evaluate] We have request_count = {}",
            self.operator(),
            registers.call_stack().request_count()
        );

        // 1. Load the operand values (console-level).
        let inputs: Vec<_> = self
            .operands()
            .iter()
            .map(|operand| registers.load(stack, operand))
            .try_collect()?;

        // 2. Retrieve the substack and resource.
        let (substack, resource) = match self.operator() {
            CallOperator::Locator(locator) => {
                eprintln!("  [Call::evaluate] Using locator => substack = {}, resource = {}", locator.program_id(), locator.resource());
                (stack.get_external_stack(locator.program_id())?.as_ref(), locator.resource())
            }
            CallOperator::Resource(resource) => {
                eprintln!("  [Call::evaluate] Using resource => {resource}");
                if stack.program().contains_function(resource) {
                    bail!("Cannot call '{resource}'. Use a closure ('closure {resource}:') instead.")
                }
                (stack, resource)
            }
        };
        lap!(timer, "Retrieved the substack and resource");

        // 3. Depending on whether it's a closure or function:
        let outputs = if let Ok(closure) = substack.program().get_closure(resource) {
            eprintln!("  [Call::evaluate] Found closure => evaluating closure");
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
            eprintln!("  [Call::evaluate] Found function => evaluating function: {}", function.name());
            if function.inputs().len() != inputs.len() {
                bail!("Expected {} inputs, found {}", function.inputs().len(), inputs.len())
            }
            let console_caller = Some(*stack.program_id());
            // [EXTRA LOG] or we patch evaluate_function to add logs. 
            let response = substack.evaluate_function::<A>(registers.call_stack(), console_caller)?;
            response.outputs().to_vec()
        } else {
            bail!("  [Call::evaluate] Operator '{:?}' is invalid or unsupported.", self.operator())
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

        eprintln!(
            "\n[Call::execute] operator = {:?}, call stack request_count = {}",
            self.operator(),
            registers.call_stack().request_count()
        );

        // 1. Load the operand values (circuit-level).
        let inputs: Vec<_> = self
            .operands()
            .iter()
            .map(|operand| registers.load_circuit(stack, operand))
            .try_collect()?;

        // 2. Retrieve the substack and resource.
        let (substack, resource) = match self.operator() {
            CallOperator::Locator(locator) => {
                eprintln!(
                    "  [Call::execute] Found a locator => substack = {}, resource = {}",
                    locator.program_id(),
                    locator.resource()
                );
                (stack.get_external_stack(locator.program_id())?.as_ref(), locator.resource())
            }
            CallOperator::Resource(resource) => {
                eprintln!("  [Call::execute] Found a resource => resource = {resource}");
                (stack, resource)
            }
        };
        lap!(timer, "Retrieve the substack and resource");

        // 3. Retrieve the root TVK (if any).
        let root_tvk = registers.root_tvk().ok();
        eprintln!("  [Call::execute] root_tvk = {root_tvk:?}");

        // 4. Handle top-level logic based on the call stack mode.
        let (request, response) = match registers.call_stack() {
            // ------------------------------------------------
            // (a) Authorize or Synthesize
            // ------------------------------------------------
            CallStack::Authorize(_, private_key, authorization)
            | CallStack::Synthesize(_, private_key, authorization) => {
                eprintln!("  [Call::execute] => in Authorize or Synthesize branch");
                let function = substack.get_function_ref(resource)?;
                let console_inputs: Vec<Value<N>> = inputs
                    .iter()
                    .map(|circuit_val| circuit_val.eject_value()) // circuit -> console
                    .collect();

                eprintln!(
                    "  [Call::execute] Building request for function '{}' with {} console inputs",
                    function.name(),
                    console_inputs.len()
                );
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

                eprintln!("  [Call::execute] Pushing request onto call stack => {request:?}");
                {
                    let mut call_stack = registers.call_stack();
                    call_stack.push(request.clone())?;
                    authorization.push(request.clone());
                }

                // If you want a real sub-circuit for top-level calls:
                let is_top_level = false; // or true, if you prefer
                if is_top_level {
                    eprintln!("  [Call::execute] Building real sub-circuit => call substack.execute_function");
                    let mut call_stack = registers.call_stack();
                    let response = substack.execute_function::<A, _>(
                        call_stack,
                        Some(*stack.program_id()),
                        root_tvk,
                        rng,
                    )?;
                    (request, response)
                } else {
                    eprintln!("  [Call::execute] Skipping sub-circuit => replicate call_stack & call evaluate_function");
                    // IMPORTANT: we replicate and also ensure the request is present.
                    let mut sub_call_stack = registers.call_stack().replicate();
                    sub_call_stack.push(request.clone())?;  
                    
                    let response = substack.evaluate_function::<A>(sub_call_stack, Some(*stack.program_id()))?;
                    (request, response)
                }
            }

            // ------------------------------------------------
            // (b) CheckDeployment
            // ------------------------------------------------
            CallStack::CheckDeployment(_, private_key, ..) => {
                eprintln!("  [Call::execute] => in CheckDeployment branch");
                let function = substack.get_function_ref(resource)?;

                // Convert circuit inputs to console.
                let console_inputs: Vec<Value<N>> = inputs
                    .iter()
                    .map(|circuit_val| circuit_val.eject_value())
                    .collect();

                eprintln!(
                    "  [Call::execute] Building dummy request for function '{}' with {} console inputs",
                    function.name(),
                    console_inputs.len()
                );
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
                eprintln!("  [Call::execute] pushing dummy request => {request:?}");

                {
                    // *** push the request so if substack calls pop/peek it can find it ***
                    let mut call_stack = registers.call_stack();
                    call_stack.push(request.clone())?;
                }

                // Sample or dummy-produce outputs.
                let address = Address::try_from(&private_key)?;
                let outputs = function
                    .outputs()
                    .iter()
                    .map(|output| {
                        eprintln!("  [Call::execute] sampling dummy value for output operand = {:?}", output.operand());
                        stack.sample_value(&address, output.value_type(), rng)
                    })
                    .collect::<Result<Vec<_>>>()?;

                // Map the output operands to registers.
                let output_registers = function
                    .outputs()
                    .iter()
                    .map(|output| match output.operand() {
                        Operand::Register(reg) => Some(reg.clone()),
                        _ => None,
                    })
                    .collect::<Vec<_>>();

                let response = crate::Response::new(
                    request.network_id(),
                    substack.program().id(),
                    function.name(),
                    request.inputs().len(),
                    request.tvk(),
                    request.tcm(),
                    outputs,
                    &function.input_types(),
                    &output_registers,
                )?;

                eprintln!("  [Call::execute] Built dummy response => {response:?}");
                (request, response)
            }

            // ------------------------------------------------
            // (c) PackageRun
            // ------------------------------------------------
            CallStack::PackageRun(_, private_key, ..) => {
                eprintln!("  [Call::execute] => in PackageRun branch");
                unimplemented!("If needed, add your logic or push a request here as well.")
            }

            // ------------------------------------------------
            // (d) Evaluate or Execute
            // ------------------------------------------------
            CallStack::Evaluate(..) | CallStack::Execute(..) => {
                eprintln!("  [Call::execute] => in Evaluate/Execute branch");
                // Possibly do your original logic or push a request if you need it.
                unimplemented!("Your original Evaluate/Execute logic here.")
            }
        };
        lap!(timer, "Computed the request and response");

        // 5. [Optional] Circuit injection:
        // let r1cs = A::eject_r1cs_and_reset();
        // A::inject_r1cs(r1cs);

        // 6. Basic checks (optional).
        let function = substack.get_function_ref(resource)?;
        let num_public = A::num_public();
        ensure!(
            A::num_public() == num_public,
            "Forbidden: 'call' injected excess public variables"
        );

        // 7. Convert console-level response to circuit-level outputs:
        let console_outputs = response.outputs().to_vec();
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
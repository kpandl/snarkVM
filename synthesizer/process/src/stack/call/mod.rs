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
use crate::ProgramID;

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
    // EVALUATE (Console-level)
    // -----------------------------------------------------------
    #[inline]
    fn evaluate<A: circuit::Aleo<Network = N>>(
        &self,
        stack: &(impl StackEvaluate<N> + StackMatches<N> + StackProgram<N>),
        registers: &mut Registers<N, A>,
    ) -> Result<()> {
        let timer = timer!("Call::evaluate");

        eprintln!("\n[Call::evaluate] operator = {:?}, request_count = {}",
                  self.operator(), registers.call_stack().request_count());

        // 1. Load the operand values (console-level).
        let inputs: Vec<_> = self.operands()
            .iter()
            .map(|operand| registers.load(stack, operand))
            .try_collect()?;

        // 2. Retrieve the substack and resource.
        let (substack, resource) = match self.operator() {
            CallOperator::Locator(locator) => {
                eprintln!("  [Call::evaluate] Using locator => substack = {}, resource = {}",
                          locator.program_id(), locator.resource());
                (stack.get_external_stack(locator.program_id())?.as_ref(), locator.resource())
            }
            CallOperator::Resource(resource) => {
                eprintln!("  [Call::evaluate] Using resource => {resource}");
                // If it's an internal function, require closure usage.
                if stack.program().contains_function(resource) {
                    bail!("Cannot call '{resource}'. Use a closure ('closure {resource}:') instead.");
                }
                (stack, resource)
            }
        };
        lap!(timer, "Retrieved substack & resource");

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
            eprintln!("  [Call::evaluate] Found function => evaluating function '{}'", function.name());
            if function.inputs().len() != inputs.len() {
                bail!("Expected {} inputs, found {}", function.inputs().len(), inputs.len())
            }
            let console_caller = Some(*stack.program_id());

            eprintln!("  [Call::evaluate] => calling substack.evaluate_function");
            let response = substack.evaluate_function::<A>(registers.call_stack(), console_caller)?;
            response.outputs().to_vec()
        } else {
            bail!("  [Call::evaluate] Operator '{:?}' is invalid or unsupported.", self.operator());
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
    // EXECUTE (Circuit-level)
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

        eprintln!("\n[Call::execute] operator = {:?}, request_count = {}",
                  self.operator(), registers.call_stack().request_count());

        // 1. Load the operand values (circuit-level).
        let inputs: Vec<_> = self.operands()
            .iter()
            .map(|operand| registers.load_circuit(stack, operand))
            .try_collect()?;

        // 2. Retrieve the substack and resource.
        let (substack, resource) = match self.operator() {
            CallOperator::Locator(locator) => {
                eprintln!("  [Call::execute] Found locator => substack = {}, resource = {}",
                          locator.program_id(), locator.resource());
                (stack.get_external_stack(locator.program_id())?.as_ref(), locator.resource())
            }
            CallOperator::Resource(resource) => {
                eprintln!("  [Call::execute] Found resource => {resource}");
                (stack, resource)
            }
        };
        lap!(timer, "Retrieved substack & resource");

        // 3. Retrieve the root TVK (if any).
        let root_tvk = registers.root_tvk().ok();
        eprintln!("  [Call::execute] root_tvk = {root_tvk:?}");

        // 4. Based on call stack mode, build a request & either do a real sub-circuit or a dummy approach.
        let (request, response) = match registers.call_stack() {
// In the "Authorize or Synthesize" branch:
// (a) Authorize or Synthesize mode
CallStack::Authorize(_, private_key, authorization)
| CallStack::Synthesize(_, private_key, authorization) => {
    eprintln!("  [Call::execute] => in Authorize or Synthesize branch");
    let function = substack.get_function_ref(resource)?;
    let console_inputs: Vec<Value<N>> = inputs
        .iter()
        .map(|circuit_val| circuit_val.eject_value())
        .collect();

    // 1) Look at how many requests are on the stack *before* we sign the new one.
    let old_count = registers.call_stack().request_count();
    let is_root_call = (old_count == 0); // 0 means no existing request => top-level
    eprintln!("  [Call::execute] is_root_call? {} (old_count={})", is_root_call, old_count);

    // 2) Build (sign) the request with that `is_root_call`.
    let request = Request::sign(
        &private_key,
        *substack.program_id(),
        *resource,
        console_inputs.iter(),
        &function.input_types(),
        root_tvk,
        is_root_call,
        rng,
    )?;
    eprintln!("  [Call::execute] Signed new request => {request:?}");

    // 3) Now push it onto the call stack.
    {
        let mut call_stack = registers.call_stack();
        call_stack.push(request.clone())?;
        authorization.push(request.clone());
    }

    // 4) Decide if we do a real sub-circuit or skip for speed, using `is_root_call`.
    let mut call_stack = registers.call_stack().replicate();
    call_stack.push(request.clone())?;

    let response = if is_root_call {
        eprintln!("  [Call::execute] => top-level => building real sub-circuit => substack.execute_function");
        substack.execute_function::<A, _>(call_stack, None, root_tvk, rng)? 
    } else {
        eprintln!("  [Call::execute] => nested => skipping => substack.evaluate_function");
        substack.evaluate_function::<A>(call_stack, Some(*stack.program_id()))?
    };
    
    (request, response)
}
            // (b) CheckDeployment => Dummy approach
            CallStack::CheckDeployment(_, private_key, ..) => {
                eprintln!("  [Call::execute] => in CheckDeployment branch");
                let function = substack.get_function_ref(resource)?;

                let console_inputs: Vec<Value<N>> = inputs
                    .iter()
                    .map(|circuit_val| circuit_val.eject_value())
                    .collect();

                    eprintln!("  [Call::execute] function input_types = {:?}", function.input_types());
                    eprintln!("  [Call::execute] console_inputs = {:#?}", console_inputs);

                eprintln!("  [Call::execute] Building dummy request => function '{}'; #console_inputs = {}",
                          function.name(), console_inputs.len());
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

                {
                    eprintln!("  [Call::execute] Pushing dummy request => {request:?}");
                    let mut call_stack = registers.call_stack();
                    call_stack.push(request.clone())?;
                }

                // Sample or dummy-produce outputs for speed.
                let address = Address::try_from(&private_key)?;
                let outputs = function.outputs()
                    .iter()
                    .map(|output| {
                        eprintln!("    [CheckDeployment] sampling dummy for output operand={:?}", output.operand());
                        stack.sample_value(&address, output.value_type(), rng)
                    })
                    .collect::<Result<Vec<_>>>()?;

                // Map the output operands
                let output_registers = function.outputs()
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

                eprintln!("  [Call::execute] Dummy response => {response:?}");
                (request, response)
            }

            // (c) PackageRun
            CallStack::PackageRun(_, private_key, ..) => {
                eprintln!("  [Call::execute] => in PackageRun branch");
                unimplemented!("Add logic or push a request if needed.")
            }

            // (d) Evaluate or Execute
            CallStack::Evaluate(..) | CallStack::Execute(..) => {
                eprintln!("  [Call::execute] => in Evaluate/Execute branch (unimplemented).");
                unimplemented!("Your original Evaluate/Execute logic here.")
            }
        };
        lap!(timer, "Computed the request & response");

        // 5. Print some circuit stats (maybe it helps to see constraints).
        eprintln!("  [Call::execute] circuit constraints so far: {}", A::num_constraints());

        // 6. Basic checks:
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
        lap!(timer, "Assigned circuit outputs to registers");

        finish!(timer);
        Ok(())
    }
}
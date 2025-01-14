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

impl<N: Network> StackEvaluate<N> for Stack<N> {
    /// Evaluates a program closure on the given inputs.
    ///
    /// # Errors
    /// This method will halt if the given inputs are not the same length as the input statements.
    #[inline]
    fn evaluate_closure<A: circuit::Aleo<Network = N>>(
        &self,
        closure: &Closure<N>,
        inputs: &[Value<N>],
        call_stack: CallStack<N>,
        signer: Address<N>,
        caller: Address<N>,
        tvk: Field<N>,
    ) -> Result<Vec<Value<N>>> {
        let timer = timer!("Stack::evaluate_closure");

        // Ensure the number of inputs matches the number of input statements.
        if closure.inputs().len() != inputs.len() {
            bail!("Expected {} inputs, found {}", closure.inputs().len(), inputs.len())
        }

        // Initialize the registers.
        let mut registers = Registers::<N, A>::new(call_stack, self.get_register_types(closure.name())?.clone());
        // Set the transition signer.
        registers.set_signer(signer);
        // Set the transition caller.
        registers.set_caller(caller);
        // Set the transition view key.
        registers.set_tvk(tvk);
        lap!(timer, "Initialize the registers");

        // Store the inputs.
        closure.inputs().iter().map(|i| i.register()).zip_eq(inputs).try_for_each(|(register, input)| {
            // Assign the input value to the register.
            registers.store(self, register, input.clone())
        })?;
        lap!(timer, "Store the inputs");

        // Evaluate the instructions.
        for instruction in closure.instructions() {
            // If the evaluation fails, bail and return the error.
            if let Err(error) = instruction.evaluate(self, &mut registers) {
                bail!("Failed to evaluate instruction ({instruction}): {error}");
            }
        }
        lap!(timer, "Evaluate the instructions");

        // Load the outputs.
        let outputs = closure
            .outputs()
            .iter()
            .map(|output| {
                match output.operand() {
                    // If the operand is a literal, use the literal directly.
                    Operand::Literal(literal) => Ok(Value::Plaintext(Plaintext::from(literal))),
                    // If the operand is a register, retrieve the stack value from the register.
                    Operand::Register(register) => registers.load(self, &Operand::Register(register.clone())),
                    // If the operand is the program ID, convert the program ID into an address.
                    Operand::ProgramID(program_id) => {
                        Ok(Value::Plaintext(Plaintext::from(Literal::Address(program_id.to_address()?))))
                    }
                    // If the operand is the signer, retrieve the signer from the registers.
                    Operand::Signer => Ok(Value::Plaintext(Plaintext::from(Literal::Address(registers.signer()?)))),
                    // If the operand is the caller, retrieve the caller from the registers.
                    Operand::Caller => Ok(Value::Plaintext(Plaintext::from(Literal::Address(registers.caller()?)))),
                    // If the operand is the block height, throw an error.
                    Operand::BlockHeight => bail!("Cannot retrieve the block height from a closure scope."),
                    // If the operand is the network id, throw an error.
                    Operand::NetworkID => bail!("Cannot retrieve the network ID from a closure scope."),
                }
            })
            .collect();
        lap!(timer, "Load the outputs");

        finish!(timer);
        outputs
    }

    /// Evaluates a program function on the given inputs.
    ///
    /// # Errors
    /// This method will halt if the given inputs are not the same length as the input statements.
    #[inline]
    fn evaluate_function<A: circuit::Aleo<Network = N>>(
        &self,
        mut call_stack: CallStack<N>,
        console_caller: Option<ProgramID<N>>,
    ) -> Result<Response<N>> {
        let timer = timer!("Stack::evaluate_function");
    
        eprintln!("\n[DEBUG][evaluate_function] Starting evaluate_function");
        eprintln!("[DEBUG][evaluate_function] console_caller = {:?}", console_caller);
    
        // Ensure the global constants for the Aleo environment are initialized.
        A::initialize_global_constants();
        // Ensure the circuit environment is clean.
        A::reset();
    
        // Match on the call stack.
        let (request, call_stack) = match &mut call_stack {
            CallStack::Evaluate(authorization) | CallStack::Execute(authorization, ..) => {
                let request = authorization.peek_next()?;
                (request, call_stack)
            },
            // The 'CheckDeployment' or 'PackageRun' branches retrieve the *last* request, etc.
            CallStack::CheckDeployment(requests, _, _, ..)
            | CallStack::PackageRun(requests, _, _) => {
                let last_request = requests.last().ok_or(anyhow!("CallStack does not contain request"))?.clone();
                (last_request, call_stack)
            },
            // Now allow Synthesize too, by retrieving the last request.
            CallStack::Synthesize(requests, _, _) => {
                let last_request = requests.last().ok_or(anyhow!("CallStack does not contain request"))?.clone();
                (last_request, call_stack)
            },
            // Otherwise, bail:
            _ => bail!("Illegal operation: call stack must not be `Authorize` in `evaluate_function`."),
        };
    
        lap!(timer, "Prepared for evaluation");
    
        // 1) Ensure the network ID matches.
        ensure!(
            **request.network_id() == N::ID,
            "Network ID mismatch. Expected {}, but found {}",
            N::ID,
            request.network_id()
        );
    
        // 2) Retrieve the function, inputs, and transition view key.
        let function = self.get_function(request.function_name())?;
        let inputs = request.inputs();
        let signer = *request.signer();
        let (is_root, actual_caller) = match console_caller {
            Some(caller_id) => (false, caller_id.to_address()?),
            None => (true, signer),
        };
    
        // Print debug info about the function inputs vs. request inputs.
        eprintln!("[DEBUG][evaluate_function] is_root = {}, function.input_types() = {:?}", is_root, function.input_types());
        eprintln!("[DEBUG][evaluate_function] request has {} inputs => {:#?}", inputs.len(), inputs);
    
        let tvk = *request.tvk();
    
        // 3) Check input length.
        if function.inputs().len() != inputs.len() {
            bail!(
                "Function '{}' in the program '{}' expects {} inputs, but {} were provided.",
                function.name(),
                self.program.id(),
                function.inputs().len(),
                inputs.len()
            )
        }
        lap!(timer, "Perform input checks");
    
        // 4) Initialize the registers.
        let mut registers = Registers::<N, A>::new(call_stack, self.get_register_types(function.name())?.clone());
        registers.set_signer(signer);
        registers.set_caller(actual_caller);
        registers.set_tvk(tvk);
        lap!(timer, "Initialize the registers");
    
        eprintln!("[DEBUG][evaluate_function] verifying request now...");
    
        // 5) Actually verify the request. If it fails, print a bunch of data.
        let verified = request.verify(&function.input_types(), is_root);
        if !verified {
            eprintln!("[DEBUG][evaluate_function] => request.verify(...) returned FALSE!");
            eprintln!("[DEBUG][evaluate_function] => Dumping request + function info...");
    
            // Print details of the function input types vs. the request input IDs or values.
            for (i, ftype) in function.input_types().iter().enumerate() {
                eprintln!("  function.input_types()[{}] = {:?}", i, ftype);
            }
            eprintln!("  request.inputs() = {:#?}", request.inputs());
            eprintln!("  request.is_root  = ??? (the request was built with is_root = ???) -- not stored unless debug printing in request");
            eprintln!("  Our local is_root = {}", is_root);
    
            return Err(anyhow!("Request is invalid (See debug logs above)"));
        }
        ensure!(verified, "Request is invalid");
        lap!(timer, "Verify the request");
    
        // 6) Store the inputs.
        function.inputs().iter().map(|i| i.register()).zip_eq(inputs).try_for_each(|(register, input)| {
            registers.store(self, register, input.clone())
        })?;
        lap!(timer, "Store the inputs");
    
        // 7) Evaluate the instructions (call instructions, etc.).
        for instruction in function.instructions() {
            let result = match instruction {
                Instruction::Call(call) => CallTrait::evaluate(call, self, &mut registers),
                _ => instruction.evaluate(self, &mut registers),
            };
            if let Err(error) = result {
                bail!("Failed to evaluate instruction ({instruction}): {error}");
            }
        }
        lap!(timer, "Evaluate the instructions");
    
        // 8) Retrieve the output operands & load them.
        let output_operands = &function.outputs().iter().map(|output| output.operand()).collect::<Vec<_>>();
        lap!(timer, "Retrieve the output operands");
    
        let outputs = output_operands
            .iter()
            .map(|operand| {
                match operand {
                    Operand::Literal(literal) => Ok(Value::Plaintext(Plaintext::from(literal))),
                    Operand::Register(register) => registers.load(self, &Operand::Register(register.clone())),
                    Operand::ProgramID(program_id) => {
                        Ok(Value::Plaintext(Plaintext::from(Literal::Address(program_id.to_address()?))))
                    }
                    Operand::Signer => Ok(Value::Plaintext(Plaintext::from(Literal::Address(registers.signer()?)))),
                    Operand::Caller => Ok(Value::Plaintext(Plaintext::from(Literal::Address(registers.caller()?)))),
                    Operand::BlockHeight => bail!("Cannot retrieve the block height from a function scope."),
                    Operand::NetworkID => bail!("Cannot retrieve the network ID from a function scope."),
                }
            })
            .collect::<Result<Vec<_>>>()?;
        lap!(timer, "Load the outputs");
    
        // 9) Map the output operands to registers.
        let output_registers = output_operands
            .iter()
            .map(|operand| match operand {
                Operand::Register(register) => Some(register.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        lap!(timer, "Loaded the output registers");
    
        // 10) Compute the response.
        let response = Response::new(
            request.network_id(),
            self.program.id(),
            function.name(),
            request.inputs().len(),
            request.tvk(),
            request.tcm(),
            outputs,
            &function.output_types(),
            &output_registers,
        );
        finish!(timer);
    
        response
    }
}

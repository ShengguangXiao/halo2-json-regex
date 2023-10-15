use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Assigned, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};
use lazy_static::lazy_static;
use std::sync::Mutex;

// This circuit checks that the values witnessed in the given cells are matching the json regex.
//
//        value1  |  selector1  |  value2  |  selector2  |  value3  |  selector3
//       -------------------------------------------------------------------------------
//          v     |      1      |          |             |          |
//                |             |     v    |      1      |          |
//                |             |     v    |      1      |          |
//                |             |          |             |     v    |      1
//                |             |          |             |     v    |      1

#[derive(Debug, Clone)]
/// A json-regex-constrained value in the circuit produced by the RegexCheckConfig.
struct RegexConstrained<F: FieldExt>(AssignedCell<Assigned<F>, F>);

#[derive(Debug, Clone)]
struct RegexCheckConfig<F: FieldExt> {
    value_advice_array: Vec<Column<Advice>>,
    value_selector_array: Vec<Selector>,
    _marker: PhantomData<F>,
}

#[derive(Debug)]
pub struct RegexCheckConfigParams {
    pub regex: String,
}

lazy_static! {
    static ref REGEX_CHECK_CONFIG_PARAMS: Mutex<RegexCheckConfigParams> =
        Mutex::new(RegexCheckConfigParams {
            regex: "".to_string(),
        });
}

pub fn set_regex_check_config_params(regex: String) {
    let mut params = REGEX_CHECK_CONFIG_PARAMS.lock().unwrap();
    params.regex = regex;
}

impl<F: FieldExt> RegexCheckConfig<F> {
    fn split_regex(regex: String) -> Vec<Vec<u8>> {
        let mut results: Vec<Vec<u8>> = vec![];
        let mut current: Vec<u8> = vec![];
        let bytes = regex.as_bytes();
        for index in 0..bytes.len() {
            let ch = bytes[index];

            if ch == b'{' || ch == b'\"' || ch == b'}' || ch == b':' {
                results.push(vec![ch]);
            } else if ch == b'[' {
                current.clear();
            } else if ch == b']' {
                results.push(current.clone());
            } else if ch == b'-' {
                for sub_ch in bytes[index - 1] + 1..bytes[index + 1] {
                    current.push(sub_ch);
                }
            } else {
                current.push(ch);
            }
        }
        results
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let params = REGEX_CHECK_CONFIG_PARAMS.lock().unwrap();
        let splitted_sections = Self::split_regex(params.regex.clone());
        let mut value_advice_array: Vec<Column<Advice>> = vec![];
        let mut value_selector_array: Vec<Selector> = vec![];
        for section in splitted_sections {
            let selector = meta.selector();
            let value = meta.advice_column();

            meta.create_gate("range check", |meta| {
                // create a new pair of value and selector
                //        value     |    selector
                //       ------------------------------
                //          v       |         1

                let q = meta.query_selector(selector);
                let value = meta.query_advice(value, Rotation::cur());

                // Given a vector of possible values and a value v, returns the expression
                // This is to constraint the value must be one from a to z.
                // (v) * (a - v) * (b - v) * ... * (z - v)
                let range_check = |value: Expression<F>| {
                    section.iter().fold(value.clone(), |expr, i| {
                        expr * (Expression::Constant(F::from(*i as u64)) - value.clone())
                    })
                };

                Constraints::with_selector(q, [("range check", range_check(value))])
            });
            value_advice_array.push(value);
            value_selector_array.push(selector);
        }

        Self {
            value_advice_array,
            value_selector_array,
            _marker: PhantomData,
        }
    }

    pub fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        converted_input: Vec<Vec<Value<Assigned<F>>>>,
    ) -> Result<RegexConstrained<F>, Error> {
        let mut result: Result<RegexConstrained<F>, Error> = Err(Error::Synthesis);
        let mut offset = 0;
        if converted_input.is_empty() {
            for section_index in 0..self.value_selector_array.len() {
                result = layouter.assign_region(
                    || "Assign value",
                    |mut region| {
                        // Enable selector
                        self.value_selector_array[section_index].enable(&mut region, offset)?;

                        // Assign value
                        region
                            .assign_advice(
                                || "value".to_owned() + &offset.to_string(),
                                self.value_advice_array[section_index],
                                offset,
                                || Value::<Assigned<F>>::default(),
                            )
                            .map(RegexConstrained::<F>)
                    },
                );

                offset += 1;
            }
        } else {
            let mut section_index: usize = 0;
            for section_input in converted_input {
                // If the input section larger than the regex section, should stop assign region earlier.
                if section_index >= self.value_selector_array.len() {
                    break;
                }

                result = layouter.assign_region(
                    || "Assign value",
                    |mut region| {
                        let mut result: Result<RegexConstrained<F>, Error> = Err(Error::Synthesis);
                        for value in section_input.clone() {
                            // Enable selector
                            self.value_selector_array[section_index].enable(&mut region, offset)?;

                            // Assign value
                            result = region
                                .assign_advice(
                                    || "value".to_owned() + &offset.to_string(),
                                    self.value_advice_array[section_index],
                                    offset,
                                    || value,
                                )
                                .map(RegexConstrained::<F>);

                            offset += 1;
                        }
                        result
                    },
                );

                section_index += 1;
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        circuit::floor_planner::V1,
        dev::{FailureLocation, MockProver, VerifyFailure},
        pasta::Fp,
        plonk::{Any, Circuit},
    };

    use super::*;

    #[derive(Default)]
    struct MyRegexCircuit<F: FieldExt> {
        data_to_verify: Vec<Vec<Value<Assigned<F>>>>,
    }

    impl<F: FieldExt> MyRegexCircuit<F> {
        fn convert_input_to_verify_format(input: String) -> Vec<Vec<Value<Assigned<F>>>> {
            let mut results: Vec<Vec<Value<Assigned<F>>>> = vec![];
            let mut current: Vec<Value<Assigned<F>>> = vec![];
            for ch in input.as_bytes() {
                if *ch == b'{' || *ch == b'}' || *ch == b':' {
                    let value = Value::known(F::from(*ch as u64).into());
                    results.push(vec![value]);
                } else if *ch == b'\"' {
                    let value = Value::known(F::from(*ch as u64).into());

                    if current.is_empty() {
                        results.push(vec![value]);
                    } else if !current.is_empty() {
                        results.push(current.clone());
                        current.clear();

                        results.push(vec![value]);
                    }
                } else {
                    let value = Value::known(F::from(*ch as u64).into());
                    current.push(value);
                }
            }
            results
        }
    }

    impl<F: FieldExt> Circuit<F> for MyRegexCircuit<F> {
        type Config = RegexCheckConfig<F>;
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            RegexCheckConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.assign(
                layouter.namespace(|| "Assign value"),
                self.data_to_verify.clone(),
            )?;

            Ok(())
        }
    }

    #[test]
    fn test_regex_check_1() {
        let k = 4;

        set_regex_check_config_params(String::from("{\"[a-z]+\"}"));

        // Successful cases
        {
            let circuit = MyRegexCircuit::<Fp> {
                data_to_verify: MyRegexCircuit::<Fp>::convert_input_to_verify_format(String::from(
                    "{\"abc\"}",
                )),
            };

            let run_result = MockProver::run(k, &circuit, vec![]);

            let prover = run_result.unwrap();
            prover.assert_satisfied();
        }

        // failed test case
        {
            let circuit = MyRegexCircuit::<Fp> {
                data_to_verify: MyRegexCircuit::<Fp>::convert_input_to_verify_format(String::from(
                    "{{\"abc\"}",
                )),
            };
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            let result = prover.verify();
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_regex_check_2() {
        let k = 6;

        set_regex_check_config_params(String::from("{\"[a-z]+\":\"[a-zA-Z0-9]+\"}"));

        // Successful cases
        {
            let circuit = MyRegexCircuit::<Fp> {
                data_to_verify: MyRegexCircuit::<Fp>::convert_input_to_verify_format(String::from(
                    "{\"abc\":\"abcDZ123\"}",
                )),
            };

            let run_result = MockProver::run(k, &circuit, vec![]);

            let prover = run_result.unwrap();
            prover.assert_satisfied();
        }

        // failed test case
        {
            let circuit = MyRegexCircuit::<Fp> {
                data_to_verify: MyRegexCircuit::<Fp>::convert_input_to_verify_format(String::from(
                    "{\"abc7\":\"abc\"}",
                )),
            };
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            let result = prover.verify();
            assert!(result.is_err());
        }
    }
}

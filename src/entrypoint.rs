/* This file is part of DarkFi (https://dark.fi)
 *
 * Copyright (C) 2020-2023 Dyne.org foundation
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 */

use crate::{
    error::MapError, ContractFunction, MAP_CONTRACT_ENTRIES_TREE, MAP_CONTRACT_ZKAS_SET_NS,
};

use darkfi_sdk::{
    crypto::{poseidon_hash, ContractId, PublicKey},
    db::{db_get, db_init, db_lookup, db_set, zkas_db_set},
    error::{ContractError, ContractResult},
    msg,
    pasta::pallas,
    util::set_return_data,
    ContractCall,
};

use darkfi_serial::{deserialize, serialize, Encodable, WriteExt};

use crate::model::{SetParamsV1, SetUpdateV1};

// A macro defining the 4 entrypoints
// init:     called during (re)deployment
// metadata: called during contract message call, first
// exec:     second
// apply:    last
darkfi_sdk::define_contract!(
    init:     init_contract,
    exec:     process_instruction,
    apply:    process_update,
    metadata: get_metadata
);

// init takes:
// - the contract ID given by the runtime
// - a payload in the form of a slice of bytes
// then:
// - initializes all the databases
// - and bundle zkas circuits that will gate this contract's functions
fn init_contract(cid: ContractId, _ix: &[u8]) -> ContractResult {
    // Hardcode the `set` circuit's binary into the wasm binary
    // during the wasm module's compilation.
    // TODO: do we need to update for non-native deployment?
    let set_v1_bincode = include_bytes!("../proof/set_v1.zk.bin");

    // When init is called, create a verifying key for this circuit.
    // The verifying key will later be used to verify proofs that are
    // supposedly constrained by the `set` circuit.
    zkas_db_set(&set_v1_bincode[..])?;

    // If this is a redeployment, skip the databsae initialization,
    // initialize otherwise.
    // We want MAP_CONTRACT_ENTRIES_TREE to store the key-value pairs of the
    // name registries.
    if db_lookup(cid, MAP_CONTRACT_ENTRIES_TREE).is_err() {
        // "Under the hood" are comments for the studious ones about how
        // something works in its implementation.
        //
        // Under the hood: db_init is only allowed callable inside init.
        // https://github.com/darkrenaissance/darkfi/blob/35405831e366eaa74522ab14645a5a05ce5cfa1e/src/runtime/import/db.rs#L55-L58
        //
        // Under the hood: cid must match the contract ID of this contract
        // https://github.com/darkrenaissance/darkfi/blob/35405831e366eaa74522ab14645a5a05ce5cfa1e/src/runtime/import/db.rs#L105-L108
        db_init(cid, MAP_CONTRACT_ENTRIES_TREE)?;
    }

    Ok(())
}

// The `metadata` entrypoint takes 1) its contract ID and 2) payload,
// but the payload is this call's index, and the calls themselves
// then it is supposed to return the public keys and public inputs, for
// verifying the signatures and zero knowledge proofs, respectively.
fn get_metadata(_cid: ContractId, ix: &[u8]) -> ContractResult {
    // Parse the index and calls from the payload
    let (call_idx, calls): (u32, Vec<ContractCall>) = deserialize(ix)?;
    if call_idx >= calls.len() as u32 {
        msg!("Error: call_idx >= calls.len()");
        return Err(ContractError::Internal);
    }

    // Selects this contract call struct
    let self_ = &calls[call_idx as usize];

    // Match on the first byte to select the function
    match ContractFunction::try_from(self_.data[0])? {
        // When the first byte is matched as `Set`
        ContractFunction::Set => {
            // Deserialize contract call, excluding the first byte
            let params: SetParamsV1 = deserialize(&self_.data[1..])?;

            // Initialize two vectors to store
            // a vector of public keys and
            // a vector of (zkas namespace, public inputs)
            let signature_pubkeys: Vec<PublicKey> = vec![];
            let mut zk_public_inputs: Vec<(String, Vec<pallas::Base>)> = vec![];

            zk_public_inputs.push((MAP_CONTRACT_ZKAS_SET_NS.to_string(), params.to_vec()));

            // Encode the two vectors into one vector
            let mut metadata = vec![];
            zk_public_inputs.encode(&mut metadata)?;
            signature_pubkeys.encode(&mut metadata)?;

            // Return data to the host using an import
            //
            // Under the hood: metadata is invoked here
            // https://github.com/darkrenaissance/darkfi/blob/35405831e366eaa74522ab14645a5a05ce5cfa1e/src/consensus/validator.rs#L1045C1-L1045C1
            //
            // Under the hood: The metadata is returned here
            // https://github.com/darkrenaissance/darkfi/blob/35405831e366eaa74522ab14645a5a05ce5cfa1e/src/runtime/import/util.rs#L43
            set_return_data(&metadata)?;

            Ok(())
        }
    }
}

/// Taking call_idx and calls, `set_return_data` a state update to
/// return to the host **to be applied in `process_update()`.
fn process_instruction(cid: ContractId, ix: &[u8]) -> ContractResult {
    let (call_idx, calls): (u32, Vec<ContractCall>) = deserialize(ix)?;
    if call_idx >= calls.len() as u32 {
        msg!("Error: call_idx >= calls.len()");
        return Err(ContractError::Internal);
    }

    match ContractFunction::try_from(ix[0])? {
        ContractFunction::Set => {
            let params: SetParamsV1 = deserialize(&calls[call_idx as usize].data[1..])?;

            // Calculating the slot
            // If the prover wants to set a top-level name,
            // i.e. in the canonical root name registry,
            // then slot = poseidon_hash(0, key)
            let slot = if params.car == pallas::Base::one() {
                poseidon_hash([pallas::Base::zero(), params.key])
            // else slot = poseidon_hash(account, key).
            // That is, if you don't have the account's secret,
            // you cannot write to the same slot assuming second preimage
            // resistance.
            } else {
                poseidon_hash([params.account, params.key])
            };

            // Check if this slot is locked.
            // Allow only setting unlocked slot.
            let db = db_lookup(cid, MAP_CONTRACT_ENTRIES_TREE)?;
            match db_get(db, &serialize(&slot))? {
                None => {}
                Some(lock) => {
                    if deserialize(&lock)? {
                        return Err(MapError::Locked.into());
                    }
                }
            };

            msg!("[SET] slot  = {:?}", slot);
            msg!("[SET] car   = {:?}", params.car);
            msg!("[SET] lock  = {:?}", params.lock);
            msg!("[SET] value = {:?}", params.value);

            // Prepare the return data for the host.
            let update = SetUpdateV1 {
                slot,
                lock: params.lock,
                value: params.value,
            };
            let mut update_data = vec![];
            update_data.write_u8(ContractFunction::Set as u8)?;
            let _ = update.encode(&mut update_data)?;

            // Setting the return data for the host.
            // Under the hood: https://github.com/darkrenaissance/darkfi/blob/35405831e366eaa74522ab14645a5a05ce5cfa1e/src/runtime/import/util.rs#L43
            set_return_data(&update_data)?;

            Ok(())
        }
    }
}

/// Taking the cid and the update data set in `process_instruction`,
/// write to the relevant databases.
/// In particular, set in db MAP_CONTRACT_ENTRIES_TREE:
/// * slot     = lock
/// * slot + 1 = value
fn process_update(cid: ContractId, update_data: &[u8]) -> ContractResult {
    match ContractFunction::try_from(update_data[0])? {
        ContractFunction::Set => {
            let update: SetUpdateV1 = deserialize(&update_data[1..])?;

            // key(slot)     = lock
            // key(slot + 1) = value
            let db = db_lookup(cid, MAP_CONTRACT_ENTRIES_TREE)?;
            db_set(db, &serialize(&update.slot), &serialize(&update.lock)).unwrap();
            db_set(
                db,
                &serialize(&(update.slot.add(&pallas::Base::one()))),
                &serialize(&update.value),
            )
            .unwrap();

            Ok(())
        }
    }
}

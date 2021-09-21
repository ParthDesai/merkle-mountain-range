use super::{NumberHash};
use crate::helper::{get_peaks, parent_offset, pos_height_in_tree, sibling_offset};
use crate::mmr::{bagging_peaks_hashes, calculate_peak_root};
use crate::{leaf_index_to_mmr_size, leaf_index_to_pos, util::MemStore, Error, Merge, MMR, MerkleProof};
use faster_hex::{hex_string, hex_decode};
use proptest::prelude::*;
use rand::{seq::SliceRandom, thread_rng};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use sha3::{Keccak256, Digest};
use bytes::Bytes;
use hex::{decode, encode};

struct SimplifiedProof {
    merkle_proof_items: Vec<NumberHash>,
    merkle_proof_order: u64,
    leave: NumberHash,
    mmr_right_bagged_peak: Option<NumberHash>,
    rest_of_the_peaks: Vec<NumberHash>,
    mmr_root: NumberHash,
    simplified_merkle_proof_items: Vec<NumberHash>,
    simplified_merkle_proof_order: u64
}

impl SimplifiedProof {
    fn convert_to_go_proof(&self) -> SimplifiedProofGo {
        SimplifiedProofGo {
            merkle_proof_items: self
                .merkle_proof_items
                .clone()
                .iter()
                .map(|x| x.0.to_vec())
                .collect(),
            merkle_proof_order: self.merkle_proof_order,
            leave: self.leave.clone().0.to_vec(),
            has_right_bagged_peak: self.mmr_right_bagged_peak.is_some(),
            mmr_right_bagged_peak: self
                .mmr_right_bagged_peak
                .clone()
                .and_then(|x| Some(x.0.to_vec()))
                .unwrap_or([0u8; 32].to_vec()),
            mmr_rest_of_the_peaks: self
                .rest_of_the_peaks
                .clone()
                .iter()
                .map(|x| x.0.to_vec())
                .collect(),
            simplified_merkle_proof_order: self.simplified_merkle_proof_order,
            simplified_merkle_proof_items: self.simplified_merkle_proof_items.clone().iter().map(|x| x.0.to_vec()).collect()
        }
    }
}

/// Only used to generate go test data
#[derive(Serialize, Deserialize)]
struct SimplifiedProofGo {
    #[serde(rename = "MerkleProofItems")]
    merkle_proof_items: Vec<Vec<u8>>,
    #[serde(rename = "MerkleProofOrder")]
    merkle_proof_order: u64,
    #[serde(rename = "Leave")]
    leave: Vec<u8>,
    #[serde(rename = "HasRightBaggedPeak")]
    has_right_bagged_peak: bool,
    #[serde(rename = "MMRRightBaggedPeak")]
    mmr_right_bagged_peak: Vec<u8>,
    #[serde(rename = "MMRRestOfThePeaks")]
    mmr_rest_of_the_peaks: Vec<Vec<u8>>,
    #[serde(skip)]
    simplified_merkle_proof_items: Vec<Vec<u8>>,
    #[serde(skip)]
    simplified_merkle_proof_order: u64,
}

/// Only used to generate go test data
#[derive(Serialize, Deserialize)]
struct SimplifiedProofTestGo {
    #[serde(rename = "ReferenceSimplifiedProof")]
    reference_simplified_proof: SimplifiedProofGo,
    #[serde(rename = "ReferenceMMRRoot")]
    reference_mmr_root: Vec<u8>,
    #[serde(rename = "LeafHash")]
    leaf_hash: Vec<u8>,
    #[serde(rename = "LeafIndex")]
    leaf_index: u64,
    #[serde(rename = "LeafCount")]
    leaf_count: u64,
    #[serde(rename = "MMRProof")]
    mmr_proof: Vec<Vec<u8>>,
    #[serde(rename = "SimplifiedMerkleProofItems")]
    simplified_merkle_proof_items: Vec<Vec<u8>>,
    #[serde(rename = "SimplifiedMerkleProofOrder")]
    simplified_merkle_proof_order: u64,
}

struct MergeNumberHash;

impl Merge for MergeNumberHash {
    type Item = NumberHash;
    fn merge(lhs: &Self::Item, rhs: &Self::Item) -> Self::Item {
        NumberHash(Keccak256::new().chain(&lhs.0).chain(&rhs.0).finalize().to_vec().into())
    }
}

/// Simple Merkle root calculation in Solidity
fn calculate_merkle_root_in_solidity(
    leave: NumberHash,
    proof_items: Vec<NumberHash>,
    proof_order: u64,
) -> NumberHash {
    let mut proof_items_iter = proof_items.iter();
    let mut queue: VecDeque<NumberHash> = VecDeque::new();
    queue.push_back(leave);

    let mut bit_field_position = 0;

    while let Some(hash) = queue.pop_front() {
        let potential_sibling_hash = proof_items_iter.next();
        if potential_sibling_hash.is_none() {
            // We have reached the end
            return hash;
        }

        let is_left = (proof_order >> bit_field_position & 1) == 1;
        bit_field_position += 1;

        let sibling = potential_sibling_hash.unwrap();

        let parent_hash = if is_left {
            println!("Left merging: {:?} {:?}", hex_string(&hash.0.to_vec()).unwrap(), hex_string(&sibling.0.to_vec()).unwrap());
            MergeNumberHash::merge(sibling, &hash)
        } else {
            println!("Right merging: {:?} {:?}", hex_string(&hash.0.to_vec()).unwrap(), hex_string(&sibling.0.to_vec()).unwrap());
            MergeNumberHash::merge(&hash, sibling)
        };

        println!("Parent hash: {:?}", hex_string(&parent_hash.0.to_vec()).unwrap());

        queue.push_back(parent_hash);
    }

    panic!("Corrupted proof")
}

/// This is what we will translate in golang
/// Difference between `calculate_merkle_root_as_mmr` function
/// and this function is this function considers proof and leave
/// to be part of normal merkle tree.
fn calculate_merkle_root_in_go(
    leave: (u64, NumberHash),
    proof_items: Vec<NumberHash>,
) -> (NumberHash, u64) {
    let mut proof_items_iter = proof_items.iter();
    let mut proof_order = 0;
    let mut proof_order_bit_field_position = 0;
    let mut queue: VecDeque<(u32, u64, NumberHash)> = VecDeque::new();
    queue.push_back((0, leave.0, leave.1));

    while let Some((height, pos, hash)) = queue.pop_front() {
        let potential_sibling_hash = proof_items_iter.next();
        if potential_sibling_hash.is_none() {
            // We have reached the end
            return (hash, proof_order);
        }

        let next_height = pos_height_in_tree(pos + 1);
        let (is_sibling_left, sibling_height, sibling_pos) = if next_height > height {
            // Sibling is left
            proof_order = proof_order | 1 << proof_order_bit_field_position;
            (true, height, pos - sibling_offset(height))
        } else {
            // Sibling is right
            (false, height, pos + sibling_offset(height))
        };
        proof_order_bit_field_position += 1;

        let sibling = (sibling_height, sibling_pos, potential_sibling_hash.unwrap());

        let (parent_pos, parent_hash) = if is_sibling_left {
            (
                sibling_pos + parent_offset(height),
                MergeNumberHash::merge(sibling.2, &hash),
            )
        } else {
            (sibling_pos + 1, MergeNumberHash::merge(&hash, sibling.2))
        };

        queue.push_back((height + 1, parent_pos, parent_hash));
    }

    panic!("Corrupted proof")
}

/// Only used for sanity check
fn calculate_merkle_root_as_mmr(
    root_pos: u64,
    leave: (u64, NumberHash),
    proof_items: Vec<NumberHash>,
) -> NumberHash {
    let mut proof_items_iter = proof_items.iter();
    let mut queue: VecDeque<(u32, u64, NumberHash)> = VecDeque::new();
    queue.push_back((0, leave.0, leave.1));

    while let Some((height, pos, hash)) = queue.pop_front() {
        if pos == root_pos {
            return hash;
        }

        let next_height = pos_height_in_tree(pos + 1);
        let (is_sibling_left, sibling_height, sibling_pos) = if next_height > height {
            // Sibling is left
            (true, height, pos - sibling_offset(height))
        } else {
            // Sibling is right
            (false, height, pos + sibling_offset(height))
        };

        let sibling = (
            sibling_height,
            sibling_pos,
            proof_items_iter
                .next()
                .expect("We need to have proper proof"),
        );

        let (parent_pos, parent_hash) = if is_sibling_left {
            (
                sibling_pos + parent_offset(height),
                MergeNumberHash::merge(sibling.2, &hash),
            )
        } else {
            (sibling_pos + 1, MergeNumberHash::merge(&hash, sibling.2))
        };

        queue.push_back((height + 1, parent_pos, parent_hash));
    }

    panic!("Corrupted proof")
}

fn convert_to_simplified_proof(
    mmr_size: u64,
    root: NumberHash,
    proof_items: Vec<NumberHash>,
    leave: (u64, NumberHash),
) -> SimplifiedProof {
    let peaks = get_peaks(mmr_size);
    let mut readymade_peak_hashes = vec![];
    let mut right_bagged_peak: Option<NumberHash> = None;
    let mut proof_item_position = 0;

    let mut merkle_root_pos: u64 = 0;
    let mut merkle_root_peak_index = 0;
    let mut merkle_proof: Vec<NumberHash> = vec![];
    for i in 0..peaks.len() {
        if (i == 0 || leave.0 > peaks[i - 1]) && leave.0 <= peaks[i] {
            merkle_root_pos = peaks[i];
            merkle_root_peak_index = i;
            if i == peaks.len() - 1 {
                for i in proof_item_position..proof_items.len() {
                    merkle_proof.push(proof_items[i].clone());
                }
            } else {
                for i in proof_item_position..(proof_items.len() - 1) {
                    merkle_proof.push(proof_items[i].clone());
                }
                right_bagged_peak = Some(proof_items.last().expect("Last should be there").clone());
                break;
            }
        } else {
            readymade_peak_hashes.push(proof_items[proof_item_position].clone());
            proof_item_position += 1;
        }
    }

    let merkle_tree_position = if merkle_root_peak_index == 0 {
        leave.0
    } else {
        leave.0 - peaks[merkle_root_peak_index - 1] - 1
    };
    let (merkle_root, proof_order) = calculate_merkle_root_in_go(
        (merkle_tree_position, leave.1.clone()),
        merkle_proof.clone(),
    );

    let mut simplified_mmr_proof_items = vec![];
    let mut simplified_mmr_proof_order: u64 = 0;

    {
        // This checks are only for sanity check and will not be a part of actual algorithm
        let merkle_root_mmr_based =
            calculate_merkle_root_as_mmr(merkle_root_pos, leave.clone(), merkle_proof.clone());
        let reference = calculate_peak_root::<_, MergeNumberHash, _>(
            vec![leave.clone()],
            merkle_root_pos,
            &mut merkle_proof.clone().iter(),
        )
        .expect("The proof items must be valid");
        let merkle_root_solidity = calculate_merkle_root_in_solidity(
            leave.1.clone(),
            merkle_proof.clone(),
            proof_order,
        );
        assert_eq!(reference, merkle_root);
        assert_eq!(reference, merkle_root_mmr_based);
        assert_eq!(reference, merkle_root_solidity);

        let mut traditional_peaks = vec![];
        for readymade_peak in &readymade_peak_hashes {
            traditional_peaks.push(readymade_peak.clone());
        }
        traditional_peaks.push(merkle_root.clone());
        if right_bagged_peak.is_some() {
            traditional_peaks.push(right_bagged_peak.clone().unwrap());
        }

        let calculated_mmr_root = bagging_peaks_hashes::<_, MergeNumberHash>(traditional_peaks)
            .expect("mmr root calculation should not fail");
        println!("Calculated: {:?}", hex_string(&*calculated_mmr_root.0.to_vec()).unwrap());
        println!("Reference: {:?}", hex_string(&*root.0.to_vec()).unwrap());
        //assert_eq!(calculated_mmr_root, root);

        for mproof in &merkle_proof {
            simplified_mmr_proof_items.push(mproof.clone());
        }
        simplified_mmr_proof_order = proof_order;
        let mut proof_bit_position = if simplified_mmr_proof_items.len() == 0 {
            0
        } else {
            simplified_mmr_proof_items.len() - 1
        };
        if right_bagged_peak.is_some() {
            proof_bit_position += 1;
            simplified_mmr_proof_order = simplified_mmr_proof_order | 1 << proof_bit_position;
            simplified_mmr_proof_items.push(right_bagged_peak.clone().unwrap());
        }
        for i in 0..readymade_peak_hashes.len() {
            simplified_mmr_proof_items.push(readymade_peak_hashes[readymade_peak_hashes.len() - i - 1].clone());
        }

        let simplified_root = calculate_merkle_root_in_solidity(leave.1.clone(), simplified_mmr_proof_items.clone(), simplified_mmr_proof_order);
        assert_eq!(calculated_mmr_root, simplified_root);
    }

    SimplifiedProof {
        merkle_proof_items: merkle_proof,
        leave: leave.1,
        merkle_proof_order: proof_order,
        rest_of_the_peaks: readymade_peak_hashes,
        mmr_root: root,
        mmr_right_bagged_peak: right_bagged_peak,
        simplified_merkle_proof_items: simplified_mmr_proof_items,
        simplified_merkle_proof_order: simplified_mmr_proof_order
    }
}

fn is_valid_simplified_proof(simplified_proof: SimplifiedProof) -> bool {
    let mut peaks = vec![];
    for peak in &simplified_proof.rest_of_the_peaks {
        peaks.push(peak.clone());
    }

    let merkle_root = calculate_merkle_root_in_solidity(
        simplified_proof.leave,
        simplified_proof.merkle_proof_items.clone(),
        simplified_proof.merkle_proof_order,
    );
    peaks.push(merkle_root.clone());

    if peaks.is_empty() {
        if !merkle_root.eq(&simplified_proof.mmr_root.clone()) {
            return false;
        }
    } else {
        if simplified_proof.mmr_right_bagged_peak.is_some() {
            let last_peak_hash = simplified_proof.mmr_right_bagged_peak.unwrap();
            peaks.push(last_peak_hash.clone());
        }
        let caclulated_mmr_root = bagging_peaks_hashes::<_, MergeNumberHash>(peaks)
            .expect("Bagging should be successful");
        if !caclulated_mmr_root.eq(&simplified_proof.mmr_root) {
            return false;
        }
    }

    true
}

fn test_mmr_simplified(count: u32) -> Vec<SimplifiedProofTestGo> {
    let peaks = get_peaks(leaf_index_to_mmr_size(count as u64 - 1));
    let mut simplified_proof_test_data = vec![];
    println!("Peaks: {:?}", peaks);
    println!("Leaves:");
    let store = MemStore::default();
    let mut mmr = MMR::<_, MergeNumberHash, _>::new(0, &store);
    let _positions: Vec<u64> = (0u32..count)
        .map(|i| {
            let hash = NumberHash::from(i);
            println!("0x{}", hex_string(&hash.0).unwrap());
            mmr.push(hash).unwrap()
        })
        .collect();
    let root = mmr.get_root().expect("get root");


    // // "_beefyMMRLeafIndex": 70,
    // //     "_beefyLeafCount": 73,
    // //     "_beefyMMRProof": [
    // //"0xa244ae2c1d1ad04bbb307ce418d84980aa656c6818516f019364df29c1a37224",
    // //"0x1acbd16b3dab0a66914fbff7cbaa15f2c4a37db6d3552ff1a466cc51cb2cbb8b",
    // //"0x58059c5ee4970ecc8491209c64dae9b5b850dce7e983bcf982079a6423d74ef4",
    // //"0x6aafdb1600e3233eb7cf374a438b64a11e8387b9cd0145557634c013e670c9c8",
    // //"0xee29f67540b840ec61825261182b7a8e73d1a1e548271b18e619ea87e0d1963e"
    //  //    ]
    // let proof_items_string = vec!["a244ae2c1d1ad04bbb307ce418d84980aa656c6818516f019364df29c1a37224",
    //                               "1acbd16b3dab0a66914fbff7cbaa15f2c4a37db6d3552ff1a466cc51cb2cbb8b",
    //                               "58059c5ee4970ecc8491209c64dae9b5b850dce7e983bcf982079a6423d74ef4",
    //                               "6aafdb1600e3233eb7cf374a438b64a11e8387b9cd0145557634c013e670c9c8",
    //                               "ee29f67540b840ec61825261182b7a8e73d1a1e548271b18e619ea87e0d1963e"];
    // let proof_items: Vec<NumberHash> = proof_items_string.iter().map(|x| {
    //    let input_bytes = x.as_bytes();
    //     NumberHash(Bytes::from(decode(input_bytes).unwrap()))
    // }).collect();
    //
    // let leaf_input_bytes = "9b0e63ce0de444dd57fac7701e4d333a1dd810b2aea6ca895235f8929125adc1";
    // let mut leaf: Vec<u8> = decode(leaf_input_bytes).unwrap();
    //
    // let h = calculate_merkle_root_in_solidity(NumberHash(Bytes::from(leaf.clone())), proof_items.clone(), 14);
    // println!("h is: {}", hex_string(&*h.0.to_vec()).unwrap());
    //
    // let proof_items_string = vec!["ee29f67540b840ec61825261182b7a8e73d1a1e548271b18e619ea87e0d1963e",
    //                               "a244ae2c1d1ad04bbb307ce418d84980aa656c6818516f019364df29c1a37224",
    //                               "1acbd16b3dab0a66914fbff7cbaa15f2c4a37db6d3552ff1a466cc51cb2cbb8b",
    //                               "58059c5ee4970ecc8491209c64dae9b5b850dce7e983bcf982079a6423d74ef4",
    //                               "6aafdb1600e3233eb7cf374a438b64a11e8387b9cd0145557634c013e670c9c8"];
    // let proof_items: Vec<NumberHash> = proof_items_string.iter().map(|x| {
    //     let input_bytes = x.as_bytes();
    //     NumberHash(Bytes::from(decode(input_bytes).unwrap()))
    // }).collect();
    //
    // let leaf_input_bytes = "9b0e63ce0de444dd57fac7701e4d333a1dd810b2aea6ca895235f8929125adc1";
    // let mut leaf: Vec<u8> = decode(leaf_input_bytes).unwrap();
    //
    // let root_input_bytes = "e629bdf7e7cdbc80579960b549ff94b66e43f911b10e9e2b56da64d767e3d0f4";
    // let mut test_root = decode(root_input_bytes).unwrap();
    //
    // let calculated_root_bytes = "746c8981b23e7e9525a8084adfe2fe05600c789fe373787308afd188e2972244";
    // let mut calculated_root: Vec<u8> = decode(calculated_root_bytes).unwrap();
    //
    // let ref_proof: MerkleProof<NumberHash, MergeNumberHash> = MerkleProof::new(leaf_index_to_mmr_size(73 - 1), proof_items.clone());
    // let ref_root = ref_proof.calculate_root(vec![(leaf_index_to_pos(70), NumberHash(Bytes::from(leaf.clone())))]).unwrap();
    // println!("Calculated root is: {:?}", hex_string(&*ref_root.0.to_vec()).unwrap());
    //
    // let ref_output = ref_proof.verify(NumberHash(Bytes::from(test_root.clone())), vec![(leaf_index_to_pos(70), NumberHash(Bytes::from(leaf.clone())))]).clone();
    // let output = ref_proof.verify(NumberHash(Bytes::from(calculated_root.clone())), vec![(leaf_index_to_pos(70), NumberHash(Bytes::from(leaf.clone())))]).clone();
    // println!("Output from ref proof is: {:?}", ref_output);
    // println!("Output from calculated proof is: {:?}", output);
    //
    // let simplified_proof = convert_to_simplified_proof(
    //     leaf_index_to_mmr_size(73 - 1),
    //     NumberHash(Bytes::from(test_root.clone())),
    //     proof_items.clone(),
    //     (leaf_index_to_pos(71), NumberHash(Bytes::from(leaf.clone()))),
    // );

    for i in 0u32..count {
        let proof = mmr
            .gen_proof(vec![leaf_index_to_pos(i as u64)])
            .expect("gen proof");
        assert!(proof
            .verify(root.clone(), vec![(leaf_index_to_pos(i as u64), i.into())])
            .unwrap());
        let simplified_proof = convert_to_simplified_proof(
            leaf_index_to_mmr_size(count as u64 - 1),
            root.clone(),
            proof.proof_items().to_vec(),
            (leaf_index_to_pos(i as u64), i.into()),
        );

        let simplified_proof_in_go = simplified_proof.convert_to_go_proof();
        let simplified_merkle_proof_order = simplified_proof_in_go.simplified_merkle_proof_order;
        let simplified_merkle_proof_items = simplified_proof_in_go.simplified_merkle_proof_items.clone();
        simplified_proof_test_data.push(SimplifiedProofTestGo {
            reference_simplified_proof: simplified_proof_in_go,
            leaf_hash: NumberHash::from(i).0.to_vec(),
            leaf_index: i as u64,
            leaf_count: count as u64,
            reference_mmr_root: root.0.to_vec(),
            mmr_proof: proof
                .proof_items()
                .clone()
                .iter()
                .map(|x| x.0.to_vec())
                .collect(),
            simplified_merkle_proof_items,
            simplified_merkle_proof_order
        });

        // Testing for invalid leaf
        assert!(!is_valid_simplified_proof(SimplifiedProof{
            merkle_proof_items: simplified_proof.merkle_proof_items.clone(),
            merkle_proof_order: simplified_proof.merkle_proof_order,
            leave: Default::default(),
            mmr_right_bagged_peak: simplified_proof.mmr_right_bagged_peak.clone(),
            rest_of_the_peaks: simplified_proof.rest_of_the_peaks.clone(),
            mmr_root: simplified_proof.mmr_root.clone(),
            simplified_merkle_proof_items: simplified_proof.simplified_merkle_proof_items.clone(),
            simplified_merkle_proof_order
        }));

        assert!(is_valid_simplified_proof(simplified_proof));
    }

    simplified_proof_test_data
}

#[test]
fn test_simplified_mmr() {
    // 5 peaks example: [30, 45, 52, 55, 56]
    // 6 peaks example: [62, 93, 108, 115, 118, 119]
    // 7 peaks example: [126, 189, 220, 235, 242, 245, 246]

    let mut go_test_data = test_mmr_simplified(1);
    go_test_data.extend(test_mmr_simplified(2));
    go_test_data.extend(test_mmr_simplified(5));
    go_test_data.extend(test_mmr_simplified(7));
    go_test_data.extend(test_mmr_simplified(15));
    go_test_data.extend(test_mmr_simplified(60));

    println!("Reference test data");
    println!("{}", serde_json::to_string(&go_test_data).unwrap());

    // Heavy test. Uncomment if you want to test the simplified mmr thoroughly
    //for i in 0u32..100 {
    //    test_mmr_simplified(i);
    //}
}

fn test_mmr(count: u32, proof_elem: Vec<u32>) {
    let store = MemStore::default();
    let mut mmr = MMR::<_, MergeNumberHash, _>::new(0, &store);
    let positions: Vec<u64> = (0u32..count)
        .map(|i| mmr.push(NumberHash::from(i)).unwrap())
        .collect();
    let root = mmr.get_root().expect("get root");
    let proof = mmr
        .gen_proof(
            proof_elem
                .iter()
                .map(|elem| positions[*elem as usize])
                .collect(),
        )
        .expect("gen proof");
    mmr.commit().expect("commit changes");
    let result = proof
        .verify(
            root,
            proof_elem
                .iter()
                .map(|elem| (positions[*elem as usize], NumberHash::from(*elem)))
                .collect(),
        )
        .unwrap();
    assert!(result);
}

fn test_gen_new_root_from_proof(count: u32) {
    let store = MemStore::default();
    let mut mmr = MMR::<_, MergeNumberHash, _>::new(0, &store);
    let positions: Vec<u64> = (0u32..count)
        .map(|i| mmr.push(NumberHash::from(i)).unwrap())
        .collect();
    let elem = count - 1;
    let pos = positions[elem as usize];
    let proof = mmr.gen_proof(vec![pos]).expect("gen proof");
    let new_elem = count;
    let new_pos = mmr.push(NumberHash::from(new_elem)).unwrap();
    let root = mmr.get_root().expect("get root");
    mmr.commit().expect("commit changes");
    let calculated_root = proof
        .calculate_root_with_new_leaf(
            vec![(pos, NumberHash::from(elem))],
            new_pos,
            NumberHash::from(new_elem),
            leaf_index_to_mmr_size(new_elem.into()),
        )
        .unwrap();
    assert_eq!(calculated_root, root);
}

#[test]
fn test_mmr_root() {
    let store = MemStore::default();
    let mut mmr = MMR::<_, MergeNumberHash, _>::new(0, &store);
    (0u32..11).for_each(|i| {
        mmr.push(NumberHash::from(i)).unwrap();
    });
    let root = mmr.get_root().expect("get root");
    let hex_root = hex_string(&root.0).unwrap();
    assert_eq!(
        "f6794677f37a57df6a5ec36ce61036e43a36c1a009d05c81c9aa685dde1fd6e3",
        hex_root
    );
}

#[test]
fn test_empty_mmr_root() {
    let store = MemStore::<NumberHash>::default();
    let mmr = MMR::<_, MergeNumberHash, _>::new(0, &store);
    assert_eq!(Err(Error::GetRootOnEmpty), mmr.get_root());
}

#[test]
fn test_mmr_3_peaks() {
    test_mmr(11, vec![5]);
}

#[test]
fn test_mmr_2_peaks() {
    test_mmr(10, vec![5]);
}

#[test]
fn test_mmr_1_peak() {
    test_mmr(8, vec![5]);
}

#[test]
fn test_mmr_first_elem_proof() {
    test_mmr(11, vec![0]);
}

#[test]
fn test_mmr_last_elem_proof() {
    test_mmr(11, vec![10]);
}

#[test]
fn test_mmr_1_elem() {
    test_mmr(1, vec![0]);
}

#[test]
fn test_mmr_2_elems() {
    test_mmr(2, vec![0]);
    test_mmr(2, vec![1]);
}

#[test]
fn test_mmr_2_leaves_merkle_proof() {
    test_mmr(11, vec![3, 7]);
    test_mmr(11, vec![3, 4]);
}

#[test]
fn test_mmr_2_sibling_leaves_merkle_proof() {
    test_mmr(11, vec![4, 5]);
    test_mmr(11, vec![5, 6]);
    test_mmr(11, vec![6, 7]);
}

#[test]
fn test_mmr_3_leaves_merkle_proof() {
    test_mmr(11, vec![4, 5, 6]);
    test_mmr(11, vec![3, 5, 7]);
    test_mmr(11, vec![3, 4, 5]);
    test_mmr(100, vec![3, 5, 13]);
}

#[test]
fn test_gen_root_from_proof() {
    test_gen_new_root_from_proof(11);
}

prop_compose! {
    fn count_elem(count: u32)
                (elem in 0..count)
                -> (u32, u32) {
                    (count, elem)
    }
}

proptest! {
    #[test]
    fn test_random_mmr(count in 10u32..500u32) {
        let mut leaves: Vec<u32> = (0..count).collect();
        let mut rng = thread_rng();
        leaves.shuffle(&mut rng);
        let leaves_count = rng.gen_range(1, count - 1);
        leaves.truncate(leaves_count as usize);
        test_mmr(count, leaves);
    }

    #[test]
    fn test_random_gen_root_with_new_leaf(count in 1u32..500u32) {
        test_gen_new_root_from_proof(count);
    }
}

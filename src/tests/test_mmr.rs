use super::{MergeNumberHash, NumberHash};
use crate::helper::{get_peaks, parent_offset, pos_height_in_tree, sibling_offset};
use crate::mmr::{bagging_peaks_hashes, calculate_peak_root};
use crate::{leaf_index_to_mmr_size, leaf_index_to_pos, util::MemStore, Error, Merge, MMR};
use faster_hex::hex_string;
use proptest::prelude::*;
use rand::{seq::SliceRandom, thread_rng};
use std::collections::VecDeque;

struct SimplifiedProof {
    merkle_proof_items: Vec<NumberHash>,
    merkle_proof_order: Vec<bool>,
    leave: NumberHash,
    mmr_right_bagged_peak: Option<NumberHash>,
    rest_of_the_peaks: Vec<NumberHash>,
    mmr_root: NumberHash,
}

/// Simple Merkle root calculation in Solidity
fn calculate_merkle_root_in_solidity(
    leave: NumberHash,
    proof_items: Vec<NumberHash>,
    proof_order: Vec<bool>,
) -> NumberHash {
    let mut proof_items_iter = proof_items.iter();
    let mut proof_order_iter = proof_order.iter();
    let mut queue: VecDeque<NumberHash> = VecDeque::new();
    queue.push_back(leave);

    while let Some(hash) = queue.pop_front() {
        let potential_sibling_hash = proof_items_iter.next();
        if potential_sibling_hash.is_none() {
            // We have reached the end
            return hash;
        }

        let is_left = proof_order_iter.next().unwrap();
        let sibling = potential_sibling_hash.unwrap();

        let parent_hash = if *is_left {
            MergeNumberHash::merge(sibling, &hash)
        } else {
            MergeNumberHash::merge(&hash, sibling)
        };

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
) -> (NumberHash, Vec<bool>) {
    let mut proof_items_iter = proof_items.iter();
    let mut proof_order = vec![];
    let mut queue: VecDeque<(u32, u64, NumberHash)> = VecDeque::new();
    queue.push_back((0, leave.0, leave.1));

    while let Some((height, pos, hash)) = queue.pop_front() {
        let next_height = pos_height_in_tree(pos + 1);
        let (is_sibling_left, sibling_height, sibling_pos) = if next_height > height {
            // Sibling is left
            proof_order.push(true);
            (true, height, pos - sibling_offset(height))
        } else {
            // Sibling is right
            proof_order.push(false);
            (false, height, pos + sibling_offset(height))
        };

        let potential_sibling_hash = proof_items_iter.next();
        if potential_sibling_hash.is_none() {
            // We have reached the end
            return (hash, proof_order);
        }

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
            proof_order.clone(),
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
        assert_eq!(calculated_mmr_root, root);
    }

    SimplifiedProof {
        merkle_proof_items: merkle_proof,
        leave: leave.1,
        merkle_proof_order: proof_order,
        rest_of_the_peaks: readymade_peak_hashes,
        mmr_root: root,
        mmr_right_bagged_peak: right_bagged_peak,
    }
}

fn verify_simplified_proof(simplified_proof: SimplifiedProof) {
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
        assert_eq!(merkle_root, simplified_proof.mmr_root.clone());
    } else {
        if simplified_proof.mmr_right_bagged_peak.is_some() {
            let last_peak_hash = simplified_proof.mmr_right_bagged_peak.unwrap();
            peaks.push(last_peak_hash.clone());
        }
        let caclulated_mmr_root = bagging_peaks_hashes::<_, MergeNumberHash>(peaks)
            .expect("Bagging should be successful");
        assert_eq!(caclulated_mmr_root, simplified_proof.mmr_root);
    }
}

fn test_mmr_simplified(count: u32) -> bool {
    let peaks = get_peaks(leaf_index_to_mmr_size(count as u64 - 1));
    println!("Peaks: {:?}", peaks);
    let store = MemStore::default();
    let mut mmr = MMR::<_, MergeNumberHash, _>::new(0, &store);
    let _positions: Vec<u64> = (0u32..count)
        .map(|i| mmr.push(NumberHash::from(i)).unwrap())
        .collect();
    let root = mmr.get_root().expect("get root");

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
        verify_simplified_proof(simplified_proof);
    }

    true
}

#[test]
fn test_simplified_mmr() {
    test_mmr_simplified(1);
    test_mmr_simplified(2);
    test_mmr_simplified(5);
    test_mmr_simplified(15);

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

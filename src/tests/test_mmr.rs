use super::{MergeNumberHash, NumberHash};
use crate::{leaf_index_to_mmr_size, util::MemStore, Error, MMR};
use faster_hex::hex_string;
use proptest::prelude::*;
use rand::{seq::SliceRandom, thread_rng};

/*
test this:

mmrLeafOpaqueEncoded=0xc5010063000000d2657f7e0327d4a715d7848b8083de2c37e50f8c3797709f9da8a963b4de182a010000000000000002000000697ea2a8fe5b03468548a7a413424a6292ab44a82a6f5cc594c3fa7dda7ce402a35e7eedcf3097c9ca41785be850e6c67d94ac6379b9acc1449d0784a47011f5

hashedOpaqueLeaf=0xbb3726f1cd600a1e1aa273990ce3adfd326298c1c6bc4ba5059c35fb32116ea2

hashedLeaf=0x065191546a9ea776f9970c4007675b2f2a0543a067535981a92fe5ea749e8572

_beefyMMRLeafIndex: 99

_beefyLeafCount: 105

beefyMMRProof :[\"0x5547c8f3d63ba09401a8830aa6adefbc6ac5598687108e74729e01ab228a59be\",\"0x1735814e29795e86a7daa647f7d3bbe922cd71d6f7b67accfd529b1a12a24c9e\",\"0x2e745fa293eb5136a89bd64df57ec66b41ee7b9bdc83accfec7243a58265f8c3\",\"0xaa2d1872fb2ca86cd6450b9c335ced9aadded7e323c38b3a76b4ade946590b2c\",\"0x92a73b500b479595da060e4543f83c2becbcf7f685f449299a60162f54a8ac5a\",\"0x173d96b6a2a46e255cc793f1c346f98faf2fd036d8e959ba5bb454f64eedc19b\"]

mmrRootHash=0xb0e22d5808dfcbf277c71904b199a7d93c710c15e86b5f5882f8b11b8fe02858

*/

fn test_proof() {
    proof = MMR::MerkleProof::new(22, Vec::new());
    proof.push()
    assert!(true);
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

// #[test]
// fn test_mmr_3_peaks() {
//     test_mmr(11, vec![5]);
// }

// #[test]
// fn test_mmr_2_peaks() {
//     test_mmr(10, vec![5]);
// }

// #[test]
// fn test_mmr_1_peak() {
//     test_mmr(8, vec![5]);
// }

// #[test]
// fn test_mmr_first_elem_proof() {
//     test_mmr(11, vec![0]);
// }

// #[test]
// fn test_mmr_last_elem_proof() {
//     test_mmr(11, vec![10]);
// }

// #[test]
// fn test_mmr_1_elem() {
//     test_mmr(1, vec![0]);
// }

// #[test]
// fn test_mmr_2_elems() {
//     test_mmr(2, vec![0]);
//     test_mmr(2, vec![1]);
// }

// #[test]
// fn test_mmr_2_leaves_merkle_proof() {
//     test_mmr(11, vec![3, 7]);
//     test_mmr(11, vec![3, 4]);
// }

// #[test]
// fn test_mmr_2_sibling_leaves_merkle_proof() {
//     test_mmr(11, vec![4, 5]);
//     test_mmr(11, vec![5, 6]);
//     test_mmr(11, vec![6, 7]);
// }

// #[test]
// fn test_mmr_3_leaves_merkle_proof() {
//     test_mmr(11, vec![4, 5, 6]);
//     test_mmr(11, vec![3, 5, 7]);
//     test_mmr(11, vec![3, 4, 5]);
//     test_mmr(100, vec![3, 5, 13]);
// }

#[test]
fn test_gen_root_from_proof() {
    test_gen_new_root_from_proof(11);
}

// prop_compose! {
//     fn count_elem(count: u32)
//                 (elem in 0..count)
//                 -> (u32, u32) {
//                     (count, elem)
//     }
// }

// proptest! {
//     #[test]
//     fn test_random_mmr(count in 10u32..500u32) {
//         let mut leaves: Vec<u32> = (0..count).collect();
//         let mut rng = thread_rng();
//         leaves.shuffle(&mut rng);
//         let leaves_count = rng.gen_range(1, count - 1);
//         leaves.truncate(leaves_count as usize);
//         test_mmr(count, leaves);
//     }

//     #[test]
//     fn test_random_gen_root_with_new_leaf(count in 1u32..500u32) {
//         test_gen_new_root_from_proof(count);
//     }
// }

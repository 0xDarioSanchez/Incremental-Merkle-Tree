use merkle_tree::IncrementalMerkleTree;

fn main() {
    let mut tree = IncrementalMerkleTree::new(4);
    println!("depth {} holds {} leaves", tree.depth(), tree.capacity());
    println!("empty root: {}", tree.root());

    let leaves = ["alpha", "beta", "gamma", "delta"];
    for leaf in leaves {
        let index = tree.insert(leaf.as_bytes()).expect("tree has room");
        println!("inserted {leaf:?} at index {index}");
        println!("  root: {}", tree.root());
    }

    let proof = tree.prove(1).expect("beta was inserted");
    println!("\nproof for beta (index {})", proof.index);
    for (level, sibling) in proof.siblings.iter().enumerate() {
        println!("  sibling at level {level}: {sibling}");
    }

    let ok = proof.verify(&tree.root(), b"beta");
    println!("verify beta: {ok}");

    let mut tampered = proof.clone();
    tampered.siblings[0].0[0] ^= 0xff;
    let bad = tampered.verify(&tree.root(), b"beta");
    println!("verify beta with one sibling bit flipped: {bad}");
}

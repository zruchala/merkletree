
use std::io::{self, BufRead};
use std::path::Path;
use std::fs::File;
use sha3::{Digest, Keccak256};
use std::env;
use std::convert::TryInto;
use structopt::StructOpt;

// prefix hashed with leaves to protect against collisions between leaf and interior hashes
const LEAF: u8 = 0x00;
const INTERIOR: u8 = 0x01;

type NodeHash = [u8; 32];

struct MerkleTree {
    hasher: Keccak256,
    leaves: Vec<NodeHash>
}

impl MerkleTree {
    fn new() -> Self {
        let hasher = Keccak256::new();
        MerkleTree{
            hasher,
            leaves: Vec::new(),
        }
    }

    fn from_data(data: Vec<String>) -> Self {
        let hasher = Keccak256::new();
        let mut merkle_tree = MerkleTree{
            hasher,
            leaves: Vec::new(),
        };

        for value in data {
            let node_hash = merkle_tree.leaf_hash(&value);
            merkle_tree.leaves.push(node_hash);
        }
        merkle_tree
    }

    fn leaf_hash(&mut self, input: &str) -> NodeHash {
        self.hasher.update(&input);
        let input_hash = self.hasher.finalize_reset();

        self.hasher.update(&[LEAF]); 
        self.hasher.update(input_hash);
        self.hasher.finalize_reset()
            .as_slice()
            .try_into()
            .expect("An error occurred during conversion")
    }

    fn interior_hash(&mut self, left: NodeHash, right: NodeHash) -> NodeHash {
        self.hasher.update(&[INTERIOR]);
        for node_hash in self.sort_nodes(left, right).iter() {
            self.hasher.update(node_hash);
        }

        self.hasher.finalize_reset()
            .as_slice()
            .try_into()
            .expect("An error occurred during conversion")
    }

    fn sort_nodes(&self, left: NodeHash, right: NodeHash) -> [NodeHash; 2] {
        let mut i = 0;
        while i < 32 {
            if left[i] > right[i] {
                return [right, left];
            } else if left[i] < right[i] {
                return [left, right];
            }
            i += 1;
        }
        [left, right]
    }

    fn create_tree(&mut self, data: Vec<NodeHash>, proof: &mut Option<&mut Proof>) -> NodeHash {
        return match data.len() {
            1 => data[0],
            d if d > 1 => {
                let mut higher_level: Vec<NodeHash> = Vec::new();
                let mut index = 0;
                while index < data.len() {
                    if index + 1 < data.len() {
                        let hash = self.interior_hash(data[index], data[index+1]);
                        higher_level.push(hash);

                        if let Some(p) = proof {
                            if p.pair == index {
                                p.hashes.push(data[index+1]);
                                p.pair = p.pair / 2;
                            } else if p.pair == index + 1 {
                                p.hashes.push(data[index]);
                                p.pair = p.pair / 2;
                            }
                        }
                    } else {
                        // Unbalanced tree detected.
                        // In that case just elevate the current hash to the higher level
                        higher_level.push(data[index]);
                        if let Some(p) = proof {
                            p.pair = p.pair / 2;
                        }
                    }
                    index += 2;
                }
        
                return self.create_tree(higher_level, proof);
            },
            _ => panic!("Invalid data")
        }
    }

    fn root(&mut self) -> NodeHash {
        self.create_tree(self.leaves.clone(), &mut None)
    }

    fn proof(&mut self, item: usize) -> Vec<NodeHash> {
        let mut proof = Proof{
            pair: item,
            hashes: Vec::new()
        };
        self.create_tree(self.leaves.clone(), &mut Some(&mut proof));
        proof.hashes
    }

    fn validate(&mut self, input: &str, proof: Vec<NodeHash>) -> NodeHash {
        let mut hash = self.leaf_hash(&input);
        for p in proof {
            hash = self.interior_hash(hash, p);
        }
        hash
    }
}

struct Proof {
    pair: usize,
    hashes: Vec<NodeHash>
}

impl Proof {

}

fn read_items(filename: &String) -> Vec<String> {
    if !Path::new(filename).exists() {
        panic!("No such file '{}' exists", filename);
    }

    let mut leaves: Vec<String> = Vec::new();
    if let Ok(lines) = read_lines(filename) {
        for line in lines {
            if let Ok(entry) = line {
                let value = entry.trim();
                if value.trim().len() > 0 {
                    leaves.push(value.to_string());
                }
            }
        }
    }
    leaves
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn to_node_hash(input: &str) -> NodeHash {
    match hex::decode(input)
        .map(|r| r.try_into().expect("Cannot convert hex to NodeHash ([u8; 32])")) {
        Ok(v) => v,
        Err(er) => panic!("Argument: '{}' failed with '{}'", input, er)
    }
}

/// Examples:
/// 
/// merkletree file.txt # generates the merkle root 
/// 
/// merkletree --create_proof item_from_input_file file.txt # generates the proof for the line contained in the file
/// 
/// merkletree --check_proof item_from_input_file hash1 hash2 hash3 root_hash # check if the proof is valid
#[derive(StructOpt, Debug)]
#[structopt(name = "merkletree")]
struct Opt {

    /// Generate proof for a given line
    #[structopt(short = "p", long = "create_proof")]
    line: Option<String>,

    /// Validate if the proof is valid. Lemma layout: [line hash1 hash2 ... root]
    #[structopt(short = "c", long = "check_proof")]
    lemma_path: Option<Vec<String>>,

    /// Input file (format: item per line)
    #[structopt(name = "FILE")]
    file: Option<String>,
}

fn main() {
    
    if env::args().len() < 2 {
        println!("For more information try `merkletree --help`");
        return;
    }

    let opt = Opt::from_args();

    if let Some(line) = opt.line {
        match opt.file {
            None => println!("Please specify the input file, ex: `merkletree -p <line> file.txt`"),
            Some(file) => print_proof(line, &file)
        }
    } else if let Some(path) = opt.lemma_path {
        check_proof(path);
    } else if let Some(file) = opt.file {
        let mut merkle_tree = MerkleTree::from_data(read_items(&file));
        println!("Root: {}", hex::encode(merkle_tree.root()));
    }    
}

fn print_proof(line: String, file: &String) {
    let lines = read_items(&file);
    match lines.iter().position(|e| e.eq(&line)) {
        None => panic!("Line '{}' not found within file: '{}'", line, &file),
        Some(index) => {
            let prof_vec= (MerkleTree::from_data(lines)).proof(index);
            print!("Proof: ");
            for hash in prof_vec {
                print!("{} ", hex::encode(hash));
            }
            println!();
        }
    }
}

fn check_proof(path: Vec<String>) {
    if path.len() < 3 {
        println!("Invalid arguments number. Try `merkletree --help` to get some help");
    }
    let mut proof: Vec<NodeHash> = Vec::new();
    let root: NodeHash = to_node_hash(&path[path.len()-1]);
    for i in 1..path.len()-1 {
        proof.push(to_node_hash(&path[i]));
    }
    let result = (MerkleTree::new()).validate(&path[0], proof);
    println!("Is proof valid? {}", result == root);
}


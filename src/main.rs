use sha2::{Digest, Sha256};
use std::str;

fn main() {
    // Hex representation of the Bitcoin transaction
    let transaction_hex = "020000000001010ccc140e766b5dbc884ea2d780c5e91e4eb77597ae64288a42\
                            575228b79e234900000000000000000002bd37060000000000225120245091249f4f2\
                            9d30820e5f36e1e5d477dc3386144220bd6f35839e94de4b9cae81c00000000000016\
                            001416d31d7632aa17b3b316b813c0a3177f5b6150200140838a1f0f1ee607b54abf0a\
                            3f55792f6f8d09c3eb7a9fa46cd4976f2137ca2e3f4a901e314e1b827c3332d7e1865f\
                            fe1d7ff5f5d7576a9000f354487a09de44cd00000000";
    // let transaction_hex = "01000000012e1fe170afad0b7d6ae45605351a78d32dd8c8263cd79cb7b1d6e1\
    //                        44c3b20a04000000008a47304402205e2e2a9646849ee15ec6ba88b7fc3d4005\
    //                        b2d45c7e98c08c6078f0feec1f26b002200d911ed6f7d1d0d0d81b2357d4f99d\
    //                        05f20497a65f6d6654b21710d225d22e84014104b96f30d536defc9bf91b4c0dc\
    //                        b5c2cf4a82a5dcdb1d4c9c16cf2a0264e7f195231d1f98dbbc10f1527ef03bea7\
    //                        0eddf3a98f5b8e25cbf95e3c33bc04e4e22e7ffffffff0280969800000000001\
    //                        976a9146369a9c04d3e2f8e9f3655bfa8d245b2a925c92a88ac8096980000000\
    //                        001976a914b1eaa994fc2d1951505af84b5d7de7d59a25602288ac00000000";

    // Convert hex string to bytes
    let transaction_bytes = hex_to_bytes(transaction_hex);

    // Print the transaction details
    println!(
        "Transaction ID: {}",
        compute_transaction_id(&transaction_bytes)
    );
    println!("Version: {}", read_uint32_le(&transaction_bytes[0..4]));
    println!(
        "Lock Time: {}",
        read_uint32_le(&transaction_bytes[transaction_bytes.len() - 4..])
    );

    let input_count = read_varint(&transaction_bytes[4..]);
    let mut offset = 4 + input_count.1;
    let mut index = 0;
    while offset < transaction_bytes.len() - 4 {
        println!(
            "Input {}: Previous Output: {:?}",
            index,
            &transaction_bytes[offset..offset + 36]
        );
        offset += 36;
        let script_len = read_varint(&transaction_bytes[offset..]);
        offset += script_len.1;
        offset += 4; // Sequence
        index += 1;
    }

    // let output_count_offset = offset;
    let output_count = read_varint(&transaction_bytes[offset..]);
    offset += output_count.1;

    index = 0;
    while offset < transaction_bytes.len() {
        let value = read_uint64_le(&transaction_bytes[offset..offset + 8]);
        offset += 8;
        let script_len = read_varint(&transaction_bytes[offset..]);
        offset += script_len.1;
        println!(
            "Output {}: Value: {} Satoshis, ScriptPubKey: {:?}",
            index,
            value,
            &transaction_bytes[offset..offset + script_len.0 as usize]
        );
        offset += script_len.0 as usize;
        index += 1;
    }
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("Invalid hex string"))
        .collect()
}

fn read_uint32_le(slice: &[u8]) -> u32 {
    u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]])
}

fn read_uint64_le(slice: &[u8]) -> u64 {
    u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ])
}

fn read_varint(slice: &[u8]) -> (u64, usize) {
    match slice[0] {
        n if n < 0xFD => (n as u64, 1),
        0xFD => (read_uint16_le(&slice[1..]), 3),
        0xFE => (read_uint32_le(&slice[1..]).into(), 5),
        0xFF => (read_uint64_le(&slice[1..]), 9),
        _ => panic!("Invalid VarInt"),
    }
}

fn read_uint16_le(slice: &[u8]) -> u64 {
    u16::from_le_bytes([slice[0], slice[1]]) as u64
}

fn compute_transaction_id(bytes: &[u8]) -> String {
    let hash = sha256d_hash(&bytes);
    hash.iter()
        .rev()
        .map(|&byte| format!("{:02x}", byte))
        .collect()
}

fn sha256d_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let first_hash = hasher.finalize();

    let mut second_hasher = Sha256::new();
    second_hasher.update(&first_hash);
    let second_hash = second_hasher.finalize();

    let mut result = [0; 32];
    result.copy_from_slice(&second_hash);
    result
}

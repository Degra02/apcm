use std::{fs::File, io::Read};

pub struct Solver;

impl Solver {
    pub fn solve(path: &str) -> std::io::Result<String>{
        let mut file = File::open(path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;

        let content = content
            .lines()
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<String>>();

        let mut data = vec![];

        for line in content {
            let mut zeroes = 0u32;
            let bytes: Vec<u8> = line
                .split(',')
                .filter_map(|s| hex::decode(s).ok())
                .map(|tuple| tuple[1]) // taking only the second byte
                .inspect(|&b| {
                    if b == 0 {
                        zeroes += 1
                    }
                })
                .collect();

            data.push(zeroes as f32 / bytes.len() as f32);
        }

        let bits = data
            .iter()
            .map(|&p| if p < (1./128. + 1./256.) / 2. { 0 } else { 1 })
            .collect::<Vec<u8>>();

        let byte1 = bits[..8].iter().fold(0u8, |acc, &b| acc << 1 | b);
        let byte2 = bits[8..].iter().fold(0u8, |acc, &b| acc << 1 | b);

        let bytes = [byte1, byte2];

        if let Ok(flag) = str::from_utf8(&bytes) {
            Ok(flag.to_string())
        } else {
            Err(std::io::Error::other("too bad") )
        }
    }
}

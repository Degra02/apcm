#![allow(dead_code)]

mod eddsa;

// Name: Filippo De Grandi
// Group: curvy

fn main() {
    let secret_key = rand::random_iter::<u8>().take(32).collect::<Vec<u8>>();
}

#[cfg(test)]
mod tests {
}

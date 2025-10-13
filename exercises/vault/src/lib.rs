pub mod vault;

// Author: Filippo De Grandi
// Group: inpythonitslike6lines
//
// Run `cargo test -- --nocapture`
// to print the solution (must have valid fonts in the device)
//
// These were like 6 lines of python but whatever, let's be rusty

#[cfg(test)]
mod tests {
    use crate::vault::Solver;

    #[test]
    fn solution() -> std::io::Result<()> {
        let solution = Solver::solve("wall.txt")?;
        println!("Solution: {} (alef)", solution);

        Ok(())
    }
}

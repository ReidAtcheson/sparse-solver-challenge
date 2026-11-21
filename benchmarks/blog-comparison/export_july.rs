// Run the July solver library on its own registered statement. The comparison
// driver consumes the signed LE128 coordinates from stdout outside timed stages.
use sparse_stark_problem::ProblemSpec;
use sparse_stark_solver::solve_tridiagonal;
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let spec = ProblemSpec::read_json(std::env::args().nth(1).ok_or("missing problem path")?)?;
    let witness = solve_tridiagonal(&spec.expand()?)?;
    let mut out = io::BufWriter::new(io::stdout().lock());
    for coordinate in witness.values {
        out.write_all(&coordinate.raw().to_le_bytes())?;
    }
    out.flush()?;
    Ok(())
}

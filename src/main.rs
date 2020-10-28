#![warn(clippy::all, clippy::style, clippy::pedantic, clippy::nursery)]
use core::marker::PhantomData;
fn main() {}

/// This structure contains _phantom_data
struct OverComplicatedType<A, B, C, D> {
    _phantom_data: PhantomData<(A, B, C, D)>,
}

fn foo(too: i32, many: i64, redundant: u32, parameters: i16, in_this: i8, func: i64) {
    println!("Ahoy!");

    let quux = 6;
    for i in many..func {
        if redundant == redundant + 1 {
            println!(
                "{}",
                too > redundant as i32 || parameters < in_this as i16 && func > 0 || many < 0
            )
        }
    }
}

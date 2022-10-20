use std::env;
mod uci;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("no argument!");
        return
    }

    uci::print(args[1].to_string());
}

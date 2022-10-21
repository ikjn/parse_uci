use std::env;
mod uci;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("no argument!");
        return
    }

    if args[1] == "sh" {
        loop {
            use std::io::{stdin, stdout, Write};
            print!("> ");
            let _ = stdout().flush();
            let mut input = String::new();
            match stdin().read_line(&mut input) {
                Ok(size) => {
                    if size == 0 {
                        break;
                    }
                    if Some('\n') == input.chars().last() {
                        input.pop();
                    }
                    if Some('\r') == input.chars().last() {
                        input.pop();
                    }
                    println!("{}", input);
                    uci::parse(input);
                }
                Err(err)  => {
                    println!("{}", err);
                    break;
                }
            }
        }

    } else {
        uci::parse(args[1].to_string());
    }
}

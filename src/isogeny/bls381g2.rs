//! See section C.3 in
//! <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>


use amcl_milagro::bls381::{big::BIG, fp::FP, fp2::FP2};

pub fn x_num() -> [FP2; 4] {
    [
    // k_(1,0) = 0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6 +
    //           0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6 * I
    FP2::new_bigs(&BIG::from_hex("5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6".to_string()),
                  &BIG::from_hex("5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6".to_string())),
    // k_(1,1) = 0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a * I
    FP2::new_bigs(&BIG::new(),
                  &BIG::from_hex("11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a".to_string())),

    // k_(1,2) = 0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e +
    //           0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d * I
    FP2::new_bigs(&BIG::from_hex("11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e".to_string()),
                  &BIG::from_hex("8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d".to_string())),

    // k_(1,3) = 0x171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1
    FP2::new_bigs(&BIG::from_hex("171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1".to_string()),
                  &BIG::new()),
    ]
}

pub const X_NUM: [FP2; 4] = [
    FP2 {
        a: FP {
            x: BIG { w: [229182373751488563,274791675623598246,145833827580428652,205051290412245746,273972556256314900,17173904667915378,1068716987] },
            xes: 2,
        },
        b: FP {
            x: BIG{ w: [229182373751488563,274791675623598246,145833827580428652,205051290412245746,273972556256314900,17173904667915378,1068716987] },
            xes: 2,
        }
    },
    FP2 {
        a: FP {
            x: BIG { w: [0,0,0,0,0,0,0] },
            xes: 2,
        },
        b: FP {
            x: BIG{ w: [8254193971177576,207752214453588643,283232777839845264,279795529225852602,86642021590550222,89896355471185911,4875416630] },
            xes: 2,
        }
    },
    FP2 {
        a: FP {
            x: BIG { w: [283821804189390455,112296315535799964,230510482785579554,9792034573234533,263851394516194276,126181626950172145,4542735496] },
            xes: 2,
        },
        b: FP {
            x: BIG{ w: [148242285061444660,103876107226794321,141616388919922632,139897764612926301,187436198871130983,44948177735592955,2437708315] },
            xes: 2,
        }
    },
    FP2 {
        a: FP {
            x: BIG { w: [11384199280789756,15362496392553597,240229515898962074,162050850147726288,171456732008995245,287480113271012248,6777301451] },
            xes: 2,
        },
        b: FP {
            x: BIG{ w: [0,0,0,0,0,0,0] },
            xes: 2,
        }
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_consts() {
        // let x_num = x_num();
        // for i in 0..x_num.len() {
        //     println!("x_num[{}].a.x = [{}]", i, x_num[i].a.x.w.iter().map(|d| d.to_string()).collect::<Vec<String>>().join(","));
        //     println!("x_num[{}].a.xres = {}", i, x_num[i].a.xes);
        //     println!("x_num[{}].b.x = [{}]", i, x_num[i].b.x.w.iter().map(|d| d.to_string()).collect::<Vec<String>>().join(","));
        //     println!("x_num[{}].b.xres = {}", i, x_num[i].b.xes);
        // }

    }
}
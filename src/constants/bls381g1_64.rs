use amcl::bls381::big::BIG;

pub(crate) const MODULUS: BIG = BIG {
    w: amcl::bls381::rom::MODULUS,
};

pub(crate) const PM1DIV2: BIG = BIG {
    w: [
        71_916_856_549_561_685,
        108_086_211_381_297_143,
        186_063_435_852_751_093,
        218_960_087_668_936_289,
        225_643_796_693_662_629,
        229_680_090_418_738_422,
        3_490_221_905,
    ],
};
pub(crate) const H_EFF: BIG = BIG {
    w: [144_396_663_052_632_065, 52, 0, 0, 0, 0, 0],
};
pub const C1: BIG = BIG {
    w: [
        132_416_828_320_029_820,
        251_988_645_945_680_778,
        105_054_635_797_673_243,
        179_422_086_639_941_582,
        19_716_962_043_635_885,
        150_180_602_526_288_156,
        2_033_276_157,
    ],
};
pub(crate) const C2: BIG = BIG {
    w: [
        170_292_360_909_944_894,
        176_868_607_242_987_704,
        7_626_954_141_253_676,
        39_810_925_030_715_689,
        14_823_383_385_055_774,
        15_557_254_971_433_191,
        634_585_801,
    ],
};
pub(crate) const SQRT_C1: BIG = BIG {
    w: [
        180_073_616_350_636_715,
        198_158_293_766_504_443,
        237_146_906_002_231_418,
        253_595_231_910_324_016,
        112_821_898_346_831_314,
        258_955_233_285_225_083,
        1_745_110_952,
    ],
};

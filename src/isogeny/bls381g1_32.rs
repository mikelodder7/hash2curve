//! See section C.2 in
//! <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>

use amcl_milagro::bls381::big::BIG;

// A' = 144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d
pub const ISO_A: BIG = BIG {
    w: [
        223890461, 128008257, 406740951, 115284801, 135973257, 202209260, 446915490, 175144396,
        45148824, 374041164, 257576576, 124899974, 21260682, 0,
    ],
};
// B' = 12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0
pub const ISO_B: BIG = BIG {
    w: [
        236399584, 241321804, 456829300, 105034850, 368006562, 11003769, 29524711, 505301480,
        455087809, 61470577, 6472890, 47251552, 237570257, 9,
    ],
};
pub const Z: BIG = BIG {
    w: [11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
};
pub const X_NUM: [BIG; 12] = [
    // k_(1, 0) = 11a05f2b1e833340b809101dd99815856b303e88a2d7005ff2627b56cdb4e2c85610c2d5f2e62d6eaeac1662734649b7
    BIG {
        w: [
            323373495, 358658835, 428563371, 25537509, 237798753, 497772250, 25151881, 286546656,
            90910782, 248299692, 235029511, 486958721, 436597425, 8,
        ],
    },
    //     // k_(1, 1) = 17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bb
    BIG {
        w: [
            332104635, 27752333, 103863738, 300240358, 512144515, 295581800, 274716055, 191229264,
            477894631, 285883712, 23211692, 310859358, 311749950, 11,
        ],
    },
    // k_(1, 2) = d54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0
    BIG {
        w: [
            211737776, 12385517, 39626744, 410810964, 237357400, 310441524, 261464547, 241511216,
            466486052, 243815632, 121901617, 317518296, 356517339, 6,
        ],
    },
    // k_(1, 3) = 1778e7166fcc6db74e0609d307e55412d7f5e4656a8dbf25f1b33289f1b330835336e25ce3107193c5b388641d9b6861
    BIG {
        w: [
            496724065, 228344608, 68969713, 230996422, 319305011, 423950553, 479708876, 212685239,
            316143076, 406792864, 327254644, 530111342, 395211110, 11,
        ],
    },
    // k_(1, 4) = e99726a3199f4436642b4b3e4118e5499db995a1257fb3f086eeb65982fac18985a286f301e77c451154ce9ac8895d9
    BIG {
        w: [
            210277849, 145385293, 127791380, 340844128, 448891269, 364039191, 217850299, 188893951,
            345627545, 522226802, 428911916, 53733510, 160900771, 7,
        ],
    },
    // k_(1, 5) = 1630c3250d7313ff01d1201bf7a74ab5db3cb17dd952799b9ed3ab9097e68f90a0870d2dcae73d19cd13c1c66f652983
    BIG {
        w: [
            258288003, 144576051, 433014387, 236608405, 150538760, 365448179, 107903822, 263924303,
            366689457, 532494933, 7620614, 451291134, 51130960, 11,
        ],
    },
    // k_(1, 6) = d6ed6553fe44d296a3726c38ae652bfb11586264f0f8ce19008e218f9c86b2a8da25128c1052ecaddd7f225a139ed84
    BIG {
        w: [
            20573572, 247435565, 21738167, 77746562, 112371930, 286031076, 327565347, 80339441,
            531699078, 475476629, 445499824, 533240402, 384656723, 6,
        ],
    },
    // k_(1, 7) = 17b81e7701abdbe2e8743884d1117e53356de5ab275b4db1a682c62ef0f2753339b7c8f8c8f475af9ccb5618e3f0c88e
    BIG {
        w: [
            66111630, 106606791, 488467431, 261222801, 122893211, 51869817, 382114315, 358935401,
            322268645, 109612018, 438111777, 56080325, 461498224, 11,
        ],
    },
    // k_(1, 8) = 80d3cf1f9a78fc47b90b33563be990dc43b756ce79f5574a2c596c928c5d1de4fa295f296b74e956d71986a8497e317
    BIG {
        w: [
            77062935, 193774420, 231974235, 86762797, 488498426, 191140962, 366119702, 228389866,
            230964085, 186512584, 518270157, 323952520, 13881119, 4,
        ],
    },
    // k_(1, 9) = 169b1f8e1bcfa7c42e0c37515d138f22dd2ecb803a0c5c99676314baf4bb1b7fa3190b2edc0327797f241067be390c9e
    BIG {
        w: [
            507055262, 421561149, 13229663, 303455672, 297269809, 173898333, 308649356, 268910987,
            48049867, 183016569, 193138132, 396316552, 162658529, 11,
        ],
    },
    // k_(1, 10) = 10321da079ce07e272d8ec09d2565b0dfa7dccdde6787f96d50af36003b14866f69b771f8c285decca67df3f1605fb7b
    BIG {
        w: [
            369490811, 322894328, 169311026, 384712472, 344354665, 430965208, 509301803, 465358607,
            234520012, 244495064, 481704706, 328994756, 52550151, 8,
        ],
    },
    // k_(1, 11) = 6e08c248e260e70bd1e962381edee3d31d79d7e22c837bc23c0bf1bc24c6b68c24b1b80b64d391fa9c8ba2e8ba2d229
    BIG {
        w: [
            195220009, 239456628, 323897322, 372703596, 112626724, 529391910, 519081730, 264526086,
            489805725, 470773617, 256353672, 474750177, 235455048, 3,
        ],
    },
];

pub const X_DEN: [BIG; 11] = [
    // k_(2, 0) = 8ca8d548cff19ae18b2e62f4bd3fa6f01d5ef4ba35b48ba9c9588617fc8ac62b558d681be343df8993cf9fa40d21b1c
    BIG {
        w: [
            13769500, 166186962, 219119142, 296551292, 180759381, 70303716, 48919126, 158624617,
            251778543, 442408915, 103594379, 436089692, 212391240, 4,
        ],
    },
    // k_(2, 1) = 12561a5deb559c4348b4711298e536367041e8ca0cf0800c0126c2588c48bf5713daa8846cb026e9e5c8276ec82b3bff
    BIG {
        w: [
            137051135, 239156086, 201964153, 357632217, 200634685, 19678756, 3146907, 423730704,
            376455656, 348596657, 304946244, 380319878, 90285534, 9,
        ],
    },
    // k_(2, 2) = b2962fe57a3225e8137e629bff2991f6f89416f5a718cd1fca64e00b11aceacd6a3d0967c94fedcfcc239ba5cb83e19
    BIG {
        w: [
            481836569, 101830098, 88061759, 128003321, 216714602, 117463181, 323482265, 233524785,
            527403329, 234853576, 5110154, 256263357, 311832549, 5,
        ],
    },
    // k_(2, 3) = 3425581a58ae2fec83aafef7c40eb545b08243f16b1655154cca8abc28d6fd04976d5243eecf5c4130de8938dc62cd8
    BIG {
        w: [
            231091416, 409945244, 457011460, 229263485, 385680535, 341172550, 356864818, 132306476,
            341510180, 467797850, 302951419, 185976317, 337991706, 1,
        ],
    },
    // k_(2, 4) = 13a8e162022914a80a6f1d5f43e7a07dffdfc759a12062bb8d6b44e833b306da9bd29ba81f35781d539d395b3532a21e
    BIG {
        w: [
            355639838, 485083865, 224266068, 87511102, 275622333, 41163225, 183383469, 187966476,
            503308231, 438254851, 43763543, 72493392, 445519392, 9,
        ],
    },
    // k_(2, 5) = e7355f8e4e667b955390f7f0506c6e9395735e9ce9cad4d0a43bcef24b8982f7400d24bc4228f11c02df9a29f6304a5
    BIG {
        w: [
            526582949, 24104212, 144950384, 27563912, 159577920, 511152732, 355739918, 490328981,
            154752821, 405288503, 357450719, 164417394, 120938382, 7,
        ],
    },
    // k_(2, 6) = 772caacf16936190f3e0c63e0596721570f5799af53a1894e2e073062aede9cea73b3538f0de06cec2574496ee84a3a
    BIG {
        w: [
            250104378, 19636811, 58202939, 124167966, 233426599, 60305751, 103102648, 322300532,
            22482775, 520276793, 63931160, 47344690, 388803279, 3,
        ],
    },
    // k_(2, 7) = 14a7ac2a9d64a8b230b3f5b074cf01996e7f63c21bca68a81996e1cdf9822c580fa5b9489d11e2d311f7d99bbdcc5a5e
    BIG {
        w: [
            499931742, 264162525, 75019460, 192057658, 46498042, 283573441, 44066395, 407075149,
            426671971, 61241356, 204275052, 449401188, 175817385, 10,
        ],
    },
    // k_(2, 8) = a10ecf6ada54f825e920b3dafc7a3cce07f8d1d7161366b74100da67f39883503826692abba43704776ec3a79a1d641
    BIG {
        w: [
            430036545, 465002963, 244374545, 80553303, 411258936, 114507676, 430821440, 61746214,
            216039309, 226376990, 396657359, 457875204, 17747818, 5,
        ],
    },
    // k_(2, 9) = 95fc13ab9e92ad4476d6e3eb3a56680f682b4ee96f7d03776df533978f31c1593174e4b4b7865002d6384d168ecdd0a
    BIG {
        w: [
            149740810, 186394251, 504971275, 245143190, 297883953, 161266809, 14539645, 500358906,
            16155316, 362621748, 299588495, 332551592, 368841643, 4,
        ],
    },
    // k_(2, 10) = 1
    BIG {
        w: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    },
];

pub const Y_NUM: [BIG; 16] = [
    // k_(3, 0) = 90d97c81ba24ee0259d1f094980dcfa11ad138e48a869522b52af6c956543d3cd0c7aee9b3ba3c2be9845719707bb33
    BIG {
        w: [
            386382643, 348269452, 250146991, 418766134, 339557584, 397822642, 88649034, 298390797,
            437366035, 172754663, 157763522, 390372800, 282688641, 4,
        ],
    },
    // k_(3, 1) = 134996a104ee5811d51036d776fb46831223e96c254f383d0f906343eb67ad34d6c56711962fa8bfe097e75a2e41c696
    BIG {
        w: [
            239191702, 79641297, 199897080, 181281580, 450055532, 295826867, 16006721, 226798055,
            51520489, 465033780, 356781493, 165457955, 345598480, 9,
        ],
    },
    // k_(3, 2) = cc786baa966e66f4a384c86a3b49942552e2d658a31ce2c344be4b91400da7d26d521628b00523b8dfe240c72de1f6
    BIG {
        w: [
            120447478, 117379590, 201410798, 446966865, 14318886, 522569888, 327879954, 449516643,
            337990370, 55695948, 489218354, 355261645, 214402746, 0,
        ],
    },
    // k_(3, 3) = 1f86376e8981c217898751ad8746757d42aa7b90eeb791c09e4a3ec03251cf9de405aba9ec61deca6355c77b0e5f4cb
    BIG {
        w: [
            283505867, 296412093, 294091561, 11892029, 298819044, 301334930, 74459026, 388095343,
            399780519, 381920058, 505814342, 288372802, 528889710, 0,
        ],
    },
    // k_(3, 4) = 8cc03fdefe0ff135caf4fe2a21529c4195536fbe3ce50b879833fd221351adc2ee7f8dc099040a841b6daecf2e8fedb
    BIG {
        w: [
            317259483, 230086503, 68168208, 267499539, 296600302, 535367834, 48358924, 528251338,
            68769078, 353413454, 388748280, 532807206, 213925854, 4,
        ],
    },
    // k_(3, 5) = 16603fca40634b6a2211e11db8f0a6a074a7d0d4afadb7bd76505c3d3ad5544e203f6326c95a807299b23ab13633a5f0
    BIG {
        w: [
            372483568, 227661193, 379591846, 516312466, 356835843, 236887402, 519428417, 446035382,
            7645136, 231179573, 142899271, 13014740, 100924580, 11,
        ],
    },
    // k_(3, 6) = 4ab0b9bcfac1bbcb2c977d027796b3ce75bb8ca2be184cb5231413c4d634f3747a87ac2460f415ec961f8855fe9d6f2
    BIG {
        w: [
            535418610, 185582634, 63985586, 284525708, 351499386, 10364593, 321734853, 423984176,
            484924344, 20695897, 213016052, 525875065, 179354044, 2,
        ],
    },
    // k_(3, 7) = 987c8d5333ab86fde9926bd2ca6c674170a05bfe3bdd81ffd038da6c26c842642f64550fedfe935a15e4ca31870fb29
    BIG {
        w: [
            410057513, 183657752, 402279784, 210412029, 138568751, 114516278, 8385550, 402421691,
            337054213, 157627955, 396773807, 108359903, 410815827, 4,
        ],
    },
    // k_(3, 8) = 9fc4018bd96684be88c9e221e4da1bb8f3abd16679dc26c1e8b6e6a1f20cabe69d65201c78607a360370e577bdba587
    BIG {
        w: [
            467379591, 28865211, 25290968, 212075407, 212592285, 389353360, 162560557, 46986168,
            462371517, 284323085, 438511496, 455921815, 532939147, 4,
        ],
    },
    // k_(3, 9) = e1bba7a1186bdb5223abde7ada14a23c42a0ca7915af6fe06985e7ed1e4d43b9b3f7055dd4eba6f2bafaaebca731c30
    BIG {
        w: [
            175316016, 494753630, 330210250, 518040506, 222542259, 255813874, 469244513, 351415134,
            63187468, 493685329, 143568761, 51215210, 29075361, 7,
        ],
    },
    // k_(3, 10) = 19713e47937cd1be0dfd0b8f1d43fb93cd2fcbcb6caf493fd1183e416389e61031bf3a5cce3fbafce813711ad011c132
    BIG {
        w: [
            269599026, 10193110, 267304762, 510966172, 509674267, 522236356, 83838048, 426612201,
            332214219, 417996764, 58671843, 117023612, 387179641, 12,
        ],
    },
    // k_(3, 11) = 18b46a908f36f6deb918c143fed2edcc523559b8aaf0c2462e6bfe7f911f643249d9cdf41b44d606ce07c8a4d0074d8e
    BIG {
        w: [
            268914062, 272516390, 288719283, 328984630, 373499037, 524273807, 152615343, 387276312,
            206714201, 536254318, 239480912, 510520765, 189180168, 12,
        ],
    },
    // k_(3, 12) = b182cac101b9399d155096004f53f447aa7b12a3426b08ec02710e807b4633f06c851c1919211f20d4c04f00b971ef8
    BIG {
        w: [
            194453240, 174073728, 75791491, 279151395, 104067180, 141820890, 37421212, 88507606,
            75147185, 2599418, 341131864, 3614515, 293784257, 5,
        ],
    },
    // k_(3, 13) = 245a394ad1eca9b72fc00ae7be315dc757b3b080d4c158013e6632d3c40659cc6cf90ad1c232a6442d9d3f5db980133
    BIG {
        w: [
            462946611, 382640046, 147495184, 522279480, 106548332, 295083552, 369119129, 16886146,
            477461307, 333387950, 482279467, 440243510, 73021770, 1,
        ],
    },
    // k_(3, 14) = 5c129645e44cf1102a159f748c4a3fc5e673d81d7e86568d9ab0f5d396a7ce46ba1049b6579afb7866b1e715475224b
    BIG {
        w: [
            343220811, 324596618, 510389729, 34158282, 130959034, 128883893, 363030188, 272301324,
            475948861, 440804639, 11032189, 478780962, 470980165, 2,
        ],
    },
    // k_(3, 15) = 15e6be4e990f03ce4ea50b3b42df2eb5cb181d8f84965a3957add4fa95af01b2b665027efec01c7704b456be69c8b604
    BIG {
        w: [
            164148740, 94549491, 268901825, 168099325, 270216038, 175983319, 149249719, 300978891,
            365631517, 437713269, 329859790, 303957916, 510387433, 10,
        ],
    },
];

pub const Y_DEN: [BIG; 16] = [
    // k_(4, 0) = 16112c4c3a9c98b252181140fad0eae9601a6de578980be6eec3232b5be72e7a07f3688ef60c206d01479253b03663c1
    BIG {
        w: [
            271999937, 171741853, 50862912, 114367980, 317169791, 295022067, 261864204, 481235713,
            157293165, 131499863, 344327248, 356069732, 18007235, 11,
        ],
    },
    // k_(4, 1) = 1962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59ca4a10356f453e01f78a4260763529e3532f6102c2e49a03d
    BIG {
        w: [
            239706173, 397443425, 346525004, 139202246, 503445386, 28015145, 376607364, 518404250,
            411420751, 35527237, 109260635, 117588028, 372078018, 12,
        ],
    },
    // k_(4, 2) = 58df3306640da276faaae7d6e8eb15778c4855551ae7f310c35a5dd279cd2eca6757cd636f96f891e2538b53dbf67f2
    BIG {
        w: [
            499083250, 287950249, 509338183, 184134765, 221170279, 317625294, 482619606, 178927055,
            393790597, 192181642, 468364191, 209826894, 417280774, 2,
        ],
    },
    // k_(4, 3) = 16b7d288798e5395f20d23bf89edb4d1d115c5dbddbcd30e123da489e726af41727364f2c28297ada8d26d98445f5416
    BIG {
        w: [
            73356310, 110324930, 10873706, 113894789, 183768871, 306508691, 205015286, 461092762,
            298915269, 474967462, 478365935, 320644907, 192751751, 11,
        ],
    },
    // k_(4, 4) = be0e079545f43e4b00cc912f8228ddcc6d19c9f0f69bbb0542eda0fc9dec916a20b15dc0fd2ededda39142311a5001d
    BIG {
        w: [
            296026141, 298361112, 347831158, 371963935, 210856480, 218621167, 247550139, 333573431,
            482791836, 398529646, 201536068, 146704329, 504235925, 5,
        ],
    },
    // k_(4, 5) = 8d9e5297186db2d9fb266eaac783182b70152c65550d881c5ecd87b6f0f5a6449f38db9dfa9cce202c6477faaf9b7ac
    BIG {
        w: [
            184137644, 372390909, 175323264, 119239615, 363218079, 205371271, 34019251, 415935003,
            45547858, 358859148, 132946362, 51230299, 228479639, 4,
        ],
    },
    // k_(4, 6) = 166007c08a99db2fc3ba8734ace9824b5eecfdfa8d0cf8ef5dd365bc400a0051d5fa9c01a58b1fb93d1a1399126a775c
    BIG {
        w: [
            308967260, 147889352, 46657103, 355992395, 335199, 316547077, 62748493, 525443487,
            190770429, 90655762, 284074445, 355710559, 100695048, 11,
        ],
    },
    // k_(4, 7) = 16a3ef08be3ea7ea03bcddfabba6ff6ee5a4375efa1f4fd7feb34fd206357132b920f5b00801dee460ee415a15812ed9
    BIG {
        w: [
            360787673, 124914384, 7846168, 32202768, 387132306, 132711194, 526383821, 199181289,
            249930807, 366819323, 15677310, 477974484, 171896971, 11,
        ],
    },
    // k_(4, 8) = 1866c8ed336c61231a1be54fd1d74cc4f9fb0ce4c6af5920abc5750c4bf39b4852cfe2f7bb9248836b233d9d55535d4a
    BIG {
        w: [
            357784906, 421129450, 76685530, 533065591, 431260972, 444999161, 75673365, 479778283,
            83491596, 512670310, 109508947, 114868806, 107777747, 12,
        ],
    },
    // k_(4, 9) = 167a55cda70a6e1cea820597d94a84903216f763e13d87bb5308592e7ea7d4fbc7385ea3d529b35e346ef48bb8913f55
    BIG {
        w: [
            412172117, 58172509, 174905229, 280840106, 491764851, 211238739, 518868001, 209463216,
            271718135, 516576292, 446726501, 236248121, 128277722, 11,
        ],
    },
    // k_(4, 10) = 4d2f259eea405bd48f010a01ad2911d9c6dd039bb61a6290e591b36e636a5c871a5c29f4f83060400f8b49cba8f6aa8
    BIG {
        w: [
            445606568, 130393317, 12681472, 193281695, 173836058, 228291355, 413415780, 121072692,
            496790992, 14062728, 305923112, 491260794, 221193630, 2,
        ],
    },
    // k_(4, 11) = accbb67481d033ff5852c1e48c50c477f94ff8aefce42d28c0f9a88cea7913516f968986f7ebbea9684b529e2561092
    BIG {
        w: [
            39194770, 338012495, 531561125, 315699422, 420696431, 222586707, 189411390, 291371464,
            125801727, 306587746, 492915463, 272238207, 214677108, 5,
        ],
    },
    // k_(4, 12) = ad6b9514c767fe3c3613144b45f1496543346d98adf02267d5ceef9a00d9b8693000763e3b90ac11e99b138573345cc
    BIG {
        w: [
            389236172, 349014466, 239251527, 968647, 431515952, 394055686, 144307571, 456219616,
            374616902, 94566564, 282610769, 418185159, 225154324, 5,
        ],
    },
    // k_(4, 13) = 2660400eb2e4f3b628bdd0d53cd76f2bf565b94e72927c1cb748df27942480e420517bd8714cc80d1fadc1326ed06f7
    BIG {
        w: [
            116197111, 265740441, 87236660, 170883854, 75555872, 116997281, 520564178, 312272164,
            314529371, 178154423, 413333315, 375168630, 106971150, 1,
        ],
    },
    // k_(4, 14) = e0fa1d816ddc03e6b24255e0d7819c171c40f65e273b853324efcd6356caa205ca2f570f13497804415473a1d634b8f
    BIG {
        w: [
            493046671, 11155920, 220586001, 99279330, 178390474, 510335670, 21809467, 213667447,
            24232975, 275497166, 449382743, 230391932, 16391553, 7,
        ],
    },
    // k_(4, 15) = 1
    BIG {
        w: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    },
];
//! See section C.2 in
//! <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>

use amcl_miracl::bls381::big::BIG;

pub const ISO_A: BIG = BIG { w: [68723909903010845, 61893056659349463, 108560269967018377, 94029932059124642, 200811820887370392, 67055163207732864, 21260682] };
pub const ISO_B: BIG = BIG { w: [129558657235364832, 56390156168112500, 5907603866473890, 271281666432074471, 33001765190244033, 25367983822128314, 5069408465] };
pub const Z: BIG = BIG { w: [11, 0, 0, 0, 0, 0, 0] };
pub const X_NUM: [BIG; 12] = [
    // k_(1, 0) = 11a05f2b1e833340b809101dd99815856b303e88a2d7005ff2627b56cdb4e2c85610c2d5f2e62d6eaeac1662734649b7
    BIG { w: [ 192553496166681015
        ,13710346175601579
        ,267239442063590753
        ,153838564562422153
        ,133304882184269886
        ,261433972884653063
        ,4731564721
    ] },
    // k_(1, 1) = 17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bb
    BIG { w: [ 14899420659942331
        ,161190314922530234
        ,158689271048746115
        ,102665429639484823
        ,153482649665279975
        ,166891347056406188
        ,6217329982
    ] },
    // k_(1, 2) = d54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0
    BIG { w: [ 6649424019119280
        ,220552456941905912
        ,166667024349907288
        ,129660347053613539
        ,130897521178182436
        ,170466337272107569
        ,3577742811
    ] },
    // k_(1, 3) = 1778e7166fcc6db74e0609d307e55412d7f5e4656a8dbf25f1b33289f1b330835336e25ce3107193c5b388641d9b6861
    BIG { w: [ 122591578443966561
        ,124015259816846577
        ,227606720351319347
        ,114184518710576844
        ,218395256206915044
        ,284601359968338548
        ,6300791142
    ] },
    // k_(1, 4) = e99726a3199f4436642b4b3e4118e5499db995a1257fb3f086eeb65982fac18985a286f301e77c451154ce9ac8895d9
    BIG { w: [ 78053135054575065
        ,182989297976996116
        ,195442052924803461
        ,101411667962503611
        ,280368379806210969
        ,28847958947573036
        ,3918997155
    ] },
    // k_(1, 5) = 1630c3250d7313ff01d1201bf7a74ab5db3cb17dd952799b9ed3ab9097e68f90a0870d2dcae73d19cd13c1c66f652983
    BIG { w: [ 77618676612016515
        ,127028170612229747
        ,196198497299008008
        ,141693281358478158
        ,285881040681778353
        ,242285082695714822
        ,5956710992
    ] },
    // k_(1, 6) = d6ed6553fe44d296a3726c38ae652bfb11586264f0f8ce19008e218f9c86b2a8da25128c1052ecaddd7f225a139ed84
    BIG { w: [ 132840957463358852
        ,41739867667542711
        ,153561764744833242
        ,43131909286805539
        ,255269571977614726
        ,286281261382486448
        ,3605882195
    ] },
    // k_(1, 7) = 17b81e7701abdbe2e8743884d1117e53356de5ab275b4db1a682c62ef0f2753339b7c8f8c8f475af9ccb5618e3f0c88e
    BIG { w: [ 57234085175675022
        ,140242923896531943
        ,27847396080956315
        ,192701976466070027
        ,58847504392089061
        ,30107895666118177
        ,6367078256
    ] },
    // k_(1, 8) = 80d3cf1f9a78fc47b90b33563be990dc43b756ce79f5574a2c596c928c5d1de4fa295f296b74e956d71986a8497e317
    BIG { w: [ 104031849664733975
        ,46580422185035099
        ,102618023077995770
        ,122615876017097494
        ,100133181302520693
        ,173920685375368397
        ,2161364767
    ] },
    // k_(1, 9) = 169b1f8e1bcfa7c42e0c37515d138f22dd2ecb803a0c5c99676314baf4bb1b7fa3190b2edc0327797f241067be390c9e
    BIG { w: [ 226323919034453150
        ,162916523391442527
        ,93360956930259505
        ,144370487146159500
        ,98256272358190795
        ,212770828906073556
        ,6068238561
    ] },
    // k_(1, 10) = 10321da079ce07e272d8ec09d2565b0dfa7dccdde6787f96d50af36003b14866f69b771f8c285decca67df3f1605fb7b
    BIG { w: [ 173352572722477947
        ,206540935869725490
        ,231372684603584361
        ,249837500256441387
        ,131262288223698380
        ,176627715178642178
        ,4347517447
    ] },
    // k_(1, 11) = 6e08c248e260e70bd1e962381edee3d31d79d7e22c837bc23c0bf1bc24c6b68c24b1b80b64d391fa9c8ba2e8ba2d229
    BIG { w: [ 128557298454024745
        ,200093719814096874
        ,284215117639748644
        ,142016361557692162
        ,252744661594134429
        ,254879560754505096
        ,1846067784
    ] }
];

pub const X_DEN: [BIG; 11] = [
    // k_(2, 0) = 8ca8d548cff19ae18b2e62f4bd3fa6f01d5ef4ba35b48ba9c9588617fc8ac62b558d681be343df8993cf9fa40d21b1c
    BIG { w: [
        89220945865218844
        ,159209762809937446
        ,37744020306668373
        ,85160942843359830
        ,237516477924759023
        ,234123870761433483
        ,2359874888
    ] },
    // k_(2, 1) = 12561a5deb559c4348b4711298e536367041e8ca0cf0800c0126c2588c48bf5713daa8846cb026e9e5c8276ec82b3bff
    BIG { w: [
        128395946138221567
        ,192002334703336057
        ,10564951881380157
        ,227488689502028955
        ,187151405540196840
        ,204182680058534980
        ,4922123742
    ] },
    // k_(2, 2) = b2962fe57a3225e8137e629bff2991f6f89416f5a718cd1fca64e00b11aceacd6a3d0967c94fedcfcc239ba5cb83e19
    BIG { w: [
        54669618064145945
        ,68721259772360511
        ,63062565326605674
        ,125372664621036185
        ,126086054060984641
        ,137580342189881738
        ,2996187109
    ] },
    // k_(2, 3) = 3425581a58ae2fec83aafef7c40eb545b08243f16b1655154cca8abc28d6fd04976d5243eecf5c4130de8938dc62cd8
    BIG { w: [
        220087677247433944
        ,123084896737259780
        ,183165618453546135
        ,71031498790490930
        ,251147058702649380
        ,99845275221142523
        ,874862618
    ] },
    // k_(2, 4) = 13a8e162022914a80a6f1d5f43e7a07dffdfc759a12062bb8d6b44e833b306da9bd29ba81f35781d539d395b3532a21e
    BIG { w: [
        260427417354674718
        ,46982165365131092
        ,22099338422233533
        ,100913733578929581
        ,235286282048102343
        ,38919593520777047
        ,5277357600
    ] },
    // k_(2, 5) = e7355f8e4e667b955390f7f0506c6e9395735e9ce9cad4d0a43bcef24b8982f7400d24bc4228f11c02df9a29f6304a5
    BIG { w: [
        12940850806064293
        ,14798262718678128
        ,274423033559709504
        ,263243367565240590
        ,217587608383477557
        ,88270916622894047
        ,3879034766
    ] },
    // k_(2, 6) = 772caacf16936190f3e0c63e0596721570f5799af53a1894e2e073062aede9cea73b3538f0de06cec2574496ee84a3a
    BIG { w: [
        10542432880446010
        ,66662169205807931
        ,32376403771641511
        ,173033780656027832
        ,279321476372827991
        ,25417986962588440
        ,1999416015
    ] },
    // k_(2, 7) = 14a7ac2a9d64a8b230b3f5b074cf01996e7f63c21bca68a81996e1cdf9822c580fa5b9489d11e2d311f7d99bbdcc5a5e
    BIG { w: [
        141821176212904542
        ,103110170082063556
        ,152242331935146234
        ,218546806540232283
        ,32878703074508643
        ,241270425859718508
        ,5544526505
    ] },
    // k_(2, 8) = a10ecf6ada54f825e920b3dafc7a3cce07f8d1d7161366b74100da67f39883503826692abba43704776ec3a79a1d641
    BIG { w: [
        249646565258548801
        ,43246725490596881
        ,61475840856379448
        ,33149746653548608
        ,121535221293154189
        ,245819878750323407
        ,2702102378
    ] },
    // k_(2, 9) = 95fc13ab9e92ad4476d6e3eb3a56680f682b4ee96f7d03776df533978f31c1593174e4b4b7865002d6384d168ecdd0a
    BIG { w: [
        100069651675667722
        ,131610248490860555
        ,86579459121043761
        ,268628142206081917
        ,194681068575949492
        ,178537276783680399
        ,2516325291
    ] },
    // k_(2, 10) = 1
    BIG { w: [
        1
        ,0
        ,0
        ,0
        ,0
        ,0
        ,0
    ] }
];

pub const Y_NUM: [BIG; 16] = [
    // k_(3, 0) = 90d97c81ba24ee0259d1f094980dcfa11ad138e48a869522b52af6c956543d3cd0c7aee9b3ba3c2be9845719707bb33
    BIG { w: [
        186975738703362867
        ,224823356525441199
        ,213579404964347088
        ,160197339406445898
        ,92746953914428691
        ,209579801313757122
        ,2430172289
    ] },
    // k_(3, 1) = 134996a104ee5811d51036d776fb46831223e96c254f383d0f906343eb67ad34d6c56711962fa8bfe097e75a2e41c696
    BIG { w: [
        42757095992444566
        ,97324807383298040
        ,158820840330448236
        ,121761278643682881
        ,249663109630927849
        ,88829563555286453
        ,5177436688
    ] },
    // k_(3, 2) = cc786baa966e66f4a384c86a3b49942552e2d658a31ce2c344be4b91400da7d26d521628b00523b8dfe240c72de1f6
    BIG { w: [
        63017687653933558
        ,239963508647741678
        ,280552572368616742
        ,241332410414468370
        ,29901534735454946
        ,190729643838988594
        ,214402746
    ] },
    // k_(3, 3) = 1f86376e8981c217898751ad8746757d42aa7b90eeb791c09e4a3ec03251cf9de405aba9ec61deca6355c77b0e5f4cb
    BIG { w: [
        159135030980244683
        ,6384484748852009
        ,161777958985375204
        ,208357100813821842
        ,205041770249333415
        ,154818969711549766
        ,528889710
    ] },
    // k_(3, 4) = 8cc03fdefe0ff135caf4fe2a21529c4195536fbe3ce50b879833fd221351adc2ee7f8dc099040a841b6daecf2e8fedb
    BIG { w: [
        123526751021760219
        ,143612721530677776
        ,287423417591644910
        ,283602777645639180
        ,189737403430819126
        ,286048690994140152
        ,2361409502
    ] },
    // k_(3, 5) = 16603fca40634b6a2211e11db8f0a6a074a7d0d4afadb7bd76505c3d3ad5544e203f6326c95a807299b23ab13633a5f0
    BIG { w: [
        122224672685401584
        ,277193144877980838
        ,127177955909886467
        ,239463422838036801
        ,124113588199925712
        ,6987235476142151
        ,6006504612
    ] },
    // k_(3, 6) = 4ab0b9bcfac1bbcb2c977d027796b3ce75bb8ca2be184cb5231413c4d634f3747a87ac2460f415ec961f8855fe9d6f2
    BIG { w: [
        99633918502360818
        ,152753576405391282
        ,5564448847918202
        ,227624771564423365
        ,11111025581972408
        ,282327025957625332
        ,1253095868
    ] },
    // k_(3, 7) = 987c8d5333ab86fde9926bd2ca6c674170a05bfe3bdd81ffd038da6c26c842642f64550fedfe935a15e4ca31870fb29
    BIG { w: [
        98600505222167337
        ,112964098307280232
        ,61480458747274287
        ,216048500264137742
        ,84625864294599173
        ,58175280344615343
        ,2558299475
    ] },
    // k_(3, 8) = 9fc4018bd96684be88c9e221e4da1bb8f3abd16679dc26c1e8b6e6a1f20cabe69d65201c78607a360370e577bdba587
    BIG { w: [
        15496892622022023
        ,113857117194152152
        ,209032493686056605
        ,25225507028105773
        ,152644794408975037
        ,244771161058256776
        ,2680422795
    ] },
    // k_(3, 9) = e1bba7a1186bdb5223abde7ada14a23c42a0ca7915af6fe06985e7ed1e4d43b9b3f7055dd4eba6f2bafaaebca731c30
    BIG { w: [
        265618832728726576
        ,278120879239371722
        ,137339028059175347
        ,188664563950426721
        ,265045292884437516
        ,27495956644540281
        ,3787171745
    ] },
    // k_(3, 10) = 19713e47937cd1be0dfd0b8f1d43fb93cd2fcbcb6caf493fd1183e416389e61031bf3a5cce3fbafce813711ad011c132
    BIG { w: [
        5472384531415346
        ,274322875030093626
        ,280373509234950939
        ,229035681505035360
        ,224410304233942987
        ,62826573358645987
        ,6829630585
    ] },
    // k_(3, 11) = 18b46a908f36f6deb918c143fed2edcc523559b8aaf0c2462e6bfe7f911f643249d9cdf41b44d606ce07c8a4d0074d8e
    BIG { w: [
        146306123103161742
        ,176622278630801843
        ,281467357275301021
        ,207917386972051887
        ,287899344975312217
        ,274083748939968592
        ,6631631112
    ] },
    // k_(3, 12) = b182cac101b9399d155096004f53f447aa7b12a3426b08ec02710e807b4633f06c851c1919211f20d4c04f00b971ef8
    BIG { w: [
        93455121301053176
        ,149868264095513731
        ,76139510659018860
        ,47517159189577884
        ,1395551987476401
        ,1940528305619544
        ,2978138817
    ] },
    // k_(3, 13) = 245a394ad1eca9b72fc00ae7be315dc757b3b080d4c158013e6632d3c40659cc6cf90ad1c232a6442d9d3f5db980133
    BIG { w: [
        205428310926688563
        ,280396660893980944
        ,158421775784987756
        ,9065680972304281
        ,178986293243771707
        ,236353935198060587
        ,609892682
    ] },
    // k_(3, 14) = 5c129645e44cf1102a159f748c4a3fc5e673d81d7e86568d9ab0f5d396a7ce46ba1049b6579afb7866b1e715475224b
    BIG { w: [
        174266482680996427
        ,18338588520082913
        ,69194013307979450
        ,146190660517717676
        ,236655189029709629
        ,257043571728209533
        ,1544721989
    ] },
    // k_(3, 15) = 15e6be4e990f03ce4ea50b3b42df2eb5cb181d8f84965a3957add4fa95af01b2b665027efec01c7704b456be69c8b604
    BIG { w: [
        50760871626454532
        ,90247638188236225
        ,94480325238532966
        ,161586811853168311
        ,234995522288162845
        ,163186163902399182
        ,5879096553
    ] }
];

pub const Y_DEN: [BIG; 16] = [
    // k_(4, 0) = 16112c4c3a9c98b252181140fad0eae9601a6de578980be6eec3232b5be72e7a07f3688ef60c206d01479253b03663c1
    BIG { w: [
        92203205520679873
        ,61400841777060672
        ,158388766487584895
        ,258361456387144460
        ,70598451533978221
        ,191163482098762832
        ,5923587267
    ] },
    // k_(4, 1) = 1962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59ca4a10356f453e01f78a4260763529e3532f6102c2e49a03d
    BIG { w: [
        213375814287859773
        ,74733637108993356
        ,15040516949407626
        ,278316162858783364
        ,19073540540450895
        ,63129591941902171
        ,6814528962
    ] },
    // k_(4, 2) = 58df3306640da276faaae7d6e8eb15778c4855551ae7f310c35a5dd279cd2eca6757cd636f96f891e2538b53dbf67f2
    BIG { w: [
        154592113290340338
        ,98856599725793863
        ,170523781485218407
        ,96060731681943766
        ,103176733803988101
        ,112649956412271519
        ,1491022598
    ] },
    // k_(4, 3) = 16b7d288798e5395f20d23bf89edb4d1d115c5dbddbcd30e123da489e726af41727364f2c28297ada8d26d98445f5416
    BIG { w: [
        59230245858792470
        ,61146799253351274
        ,164555600656865063
        ,247547291856554230
        ,254996214793180613
        ,172144924127611119
        ,6098331783
    ] },
    // k_(4, 4) = be0e079545f43e4b00cc912f8228ddcc6d19c9f0f69bbb0542eda0fc9dec916a20b15dc0fd2ededda39142311a5001d
    BIG { w: [
        160181402600800285
        ,199696617362389878
        ,117371345520650784
        ,179085872367489211
        ,213958974989848988
        ,78761287106114116
        ,3188590485
    ] },
    // k_(4, 5) = 8d9e5297186db2d9fb266eaac783182b70152c65550d881c5ecd87b6f0f5a6449f38db9dfa9cce202c6477faaf9b7ac
    BIG { w: [
        199925847119476652
        ,64016281026902144
        ,110257861923587231
        ,223303404427351987
        ,192661038111850834
        ,27504057479109050
        ,2375963287
    ] },
    // k_(4, 6) = 166007c08a99db2fc3ba8734ace9824b5eecfdfa8d0cf8ef5dd365bc400a0051d5fa9c01a58b1fb93d1a1399126a775c
    BIG { w: [
        79397491592296284
        ,191121961815371343
        ,169944917920259423
        ,282095324132898637
        ,48670441813765373
        ,190970652502434253
        ,6006275080
    ] },
    // k_(4, 7) = 16a3ef08be3ea7ea03bcddfabba6ff6ee5a4375efa1f4fd7feb34fd206357132b920f5b00801dee460ee415a15812ed9
    BIG { w: [
        67062899620785881
        ,17288729432930584
        ,71248780142521234
        ,106934640805149389
        ,196934624728163383
        ,256610597153486718
        ,6077477003
    ] },
    // k_(4, 8) = 1866c8ed336c61231a1be54fd1d74cc4f9fb0ce4c6af5920abc5750c4bf39b4852cfe2f7bb9248836b233d9d55535d4a
    BIG { w: [
        226092152249343306
        ,286187410072674522
        ,238907105836565804
        ,257579004427677461
        ,275237776968514316
        ,61669720747080019
        ,6550228691
    ] },
    // k_(4, 9) = 167a55cda70a6e1cea820597d94a84903216f763e13d87bb5308592e7ea7d4fbc7385ea3d529b35e346ef48bb8913f55
    BIG { w: [
        31231128372330325
        ,150774884009301901
        ,113407934948424819
        ,112454708323240993
        ,277334785275336439
        ,126834744626282853
        ,6033857754
    ] },
    // k_(4, 10) = 4d2f259eea405bd48f010a01ad2911d9c6dd039bb61a6290e591b36e636a5c871a5c29f4f83060400f8b49cba8f6aa8
    BIG { w: [
        70004379462101672
        ,103767319880237312
        ,122562988134401818
        ,65000406985750884
        ,7549870103358928
        ,263743630810547240
        ,1294935454
    ] },
    // k_(4, 11) = accbb67481d033ff5852c1e48c50c477f94ff8aefce42d28c0f9a88cea7913516f968986f7ebbea9684b529e2561092
    BIG { w: [
        181469076497240210
        ,169489837138573989
        ,119500328806863215
        ,156428863797866558
        ,164598042928846079
        ,146156774966250247
        ,2899031668
    ] },
    // k_(4, 12) = ad6b9514c767fe3c3613144b45f1496543346d98adf02267d5ceef9a00d9b8693000763e3b90ac11e99b138573345cc
    BIG { w: [
        187375715051849164
        ,520038637547591
        ,211557035953121584
        ,244931041458517363
        ,50770037834003270
        ,224511447979805777
        ,2909508884
    ] },
    // k_(4, 13) = 2660400eb2e4f3b628bdd0d53cd76f2bf565b94e72927c1cb748df27942480e420517bd8714cc80d1fadc1326ed06f7
    BIG { w: [
        142668313031149303
        ,91742570630291508
        ,62812437027546144
        ,167649841999457746
        ,95645927867373147
        ,201417124955223875
        ,643842062
    ] },
    // k_(4, 14) = e0fa1d816ddc03e6b24255e0d7819c171c40f65e273b853324efcd6356caa205ca2f570f13497804415473a1d634b8f
    BIG { w: [
        5989289437645711
        ,53300184660434961
        ,273984376757421514
        ,114711837157411131
        ,147906414788068367
        ,123690727099664727
        ,3774487937
    ] },
    // k_(4, 15) = 1
    BIG { w: [
        1
        ,0
        ,0
        ,0
        ,0
        ,0
        ,0
    ] }
];
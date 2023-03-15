RC = [0x0684704ce620c00ab2c5fef075817b9d, 0x8b66b4e188f3a06b640f6ba42f08f717,
	  0x3402de2d53f28498cf029d609f029114, 0x0ed6eae62e7b4f08bbf3bcaffd5b4f79,
	  0xcbcfb0cb4872448b79eecd1cbe397044, 0x7eeacdee6e9032b78d5335ed2b8a057b,
	  0x67c28f435e2e7cd0e2412761da4fef1b, 0x2924d9b0afcacc07675ffde21fc70b3b,
	  0xab4d63f1e6867fe9ecdb8fcab9d465ee, 0x1c30bf84d4b7cd645b2a404fad037e33,
	  0xb2cc0bb9941723bf69028b2e8df69800, 0xfa0478a6de6f55724aaa9ec85c9d2d8a,
	  0xdfb49f2b6b772a120efa4f2e29129fd4, 0x1ea10344f449a23632d611aebb6a12ee,
	  0xaf0449884b0500845f9600c99ca8eca6, 0x21025ed89d199c4f78a2c7e327e593ec,
	  0xbf3aaaf8a759c9b7b9282ecd82d40173, 0x6260700d6186b01737f2efd910307d6b,
	  0x5aca45c22130044381c29153f6fc9ac6, 0x9223973c226b68bb2caf92e836d1943a,
	  0xd3bf9238225886eb6cbab958e51071b4, 0xdb863ce5aef0c677933dfddd24e1128d,
	  0xbb606268ffeba09c83e48de3cb2212b1, 0x734bd3dce2e4d19c2db91a4ec72bf77d,
	  0x43bb47c361301b434b1415c42cb3924e, 0xdba775a8e707eff603b231dd16eb6899,
	  0x6df3614b3c7559778e5e23027eca472c, 0xcda75a17d6de7d776d1be5b9b88617f9,
	  0xec6b43f06ba8e9aa9d6c069da946ee5d, 0xcb1e6950f957332ba25311593bf327c1,
	  0x2cee0c7500da619ce4ed0353600ed0d9, 0xf0b1a5a196e90cab80bbbabc63a4a350,
	  0xae3db1025e962988ab0dde30938dca39, 0x17bb8f38d554a40b8814f3a82e75b442,
	  0x34bb8a5b5f427fd7aeb6b779360a16f6, 0x26f65241cbe5543843ce5918ffbaafde,
	  0x4ce99a54b9f3026aa2ca9cf7839ec978, 0xae51a51a1bdff7be40c06e2822901235,
	  0xa0c1613cba7ed22bc173bc0f48a659cf, 0x756acc03022882884ad6bdfde9c59da1]

print("{ ")
for c in RC:
  b = c.to_bytes(16, "little")
  for by in b:
    print("0x" + format(by, "02x"), end = ", ")
  print("")
print("}")

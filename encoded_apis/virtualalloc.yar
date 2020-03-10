rule xor_encoded_VirtualAlloc : XOR_VirtualAlloc
{
meta:
	score = 10
strings:

	$1 = {57 68 73 75 74 60 6d 40 6d 6d 6e 62}
	$2 = {54 6b 70 76 77 63 6e 43 6e 6e 6d 61}
	$3 = {55 6a 71 77 76 62 6f 42 6f 6f 6c 60}
	$4 = {52 6d 76 70 71 65 68 45 68 68 6b 67}
	$5 = {53 6c 77 71 70 64 69 44 69 69 6a 66}
	$6 = {50 6f 74 72 73 67 6a 47 6a 6a 69 65}
	$7 = {51 6e 75 73 72 66 6b 46 6b 6b 68 64}
	$8 = {5e 61 7a 7c 7d 69 64 49 64 64 67 6b}
	$9 = {5f 60 7b 7d 7c 68 65 48 65 65 66 6a}
	$10 = {5c 63 78 7e 7f 6b 66 4b 66 66 65 69}
	$11 = {5d 62 79 7f 7e 6a 67 4a 67 67 64 68}
	$12 = {5a 65 7e 78 79 6d 60 4d 60 60 63 6f}
	$13 = {5b 64 7f 79 78 6c 61 4c 61 61 62 6e}
	$14 = {58 67 7c 7a 7b 6f 62 4f 62 62 61 6d}
	$15 = {59 66 7d 7b 7a 6e 63 4e 63 63 60 6c}
	$16 = {46 79 62 64 65 71 7c 51 7c 7c 7f 73}
	$17 = {47 78 63 65 64 70 7d 50 7d 7d 7e 72}
	$18 = {44 7b 60 66 67 73 7e 53 7e 7e 7d 71}
	$19 = {45 7a 61 67 66 72 7f 52 7f 7f 7c 70}
	$20 = {42 7d 66 60 61 75 78 55 78 78 7b 77}
	$21 = {43 7c 67 61 60 74 79 54 79 79 7a 76}
	$22 = {40 7f 64 62 63 77 7a 57 7a 7a 79 75}
	$23 = {41 7e 65 63 62 76 7b 56 7b 7b 78 74}
	$24 = {4e 71 6a 6c 6d 79 74 59 74 74 77 7b}
	$25 = {4f 70 6b 6d 6c 78 75 58 75 75 76 7a}
	$26 = {4c 73 68 6e 6f 7b 76 5b 76 76 75 79}
	$27 = {4d 72 69 6f 6e 7a 77 5a 77 77 74 78}
	$28 = {4a 75 6e 68 69 7d 70 5d 70 70 73 7f}
	$29 = {4b 74 6f 69 68 7c 71 5c 71 71 72 7e}
	$30 = {48 77 6c 6a 6b 7f 72 5f 72 72 71 7d}
	$31 = {49 76 6d 6b 6a 7e 73 5e 73 73 70 7c}
	$32 = {76 49 52 54 55 41 4c 61 4c 4c 4f 43}
	$33 = {77 48 53 55 54 40 4d 60 4d 4d 4e 42}
	$34 = {74 4b 50 56 57 43 4e 63 4e 4e 4d 41}
	$35 = {75 4a 51 57 56 42 4f 62 4f 4f 4c 40}
	$36 = {72 4d 56 50 51 45 48 65 48 48 4b 47}
	$37 = {73 4c 57 51 50 44 49 64 49 49 4a 46}
	$38 = {70 4f 54 52 53 47 4a 67 4a 4a 49 45}
	$39 = {71 4e 55 53 52 46 4b 66 4b 4b 48 44}
	$40 = {7e 41 5a 5c 5d 49 44 69 44 44 47 4b}
	$41 = {7f 40 5b 5d 5c 48 45 68 45 45 46 4a}
	$42 = {7c 43 58 5e 5f 4b 46 6b 46 46 45 49}
	$43 = {7d 42 59 5f 5e 4a 47 6a 47 47 44 48}
	$44 = {7a 45 5e 58 59 4d 40 6d 40 40 43 4f}
	$45 = {7b 44 5f 59 58 4c 41 6c 41 41 42 4e}
	$46 = {78 47 5c 5a 5b 4f 42 6f 42 42 41 4d}
	$47 = {79 46 5d 5b 5a 4e 43 6e 43 43 40 4c}
	$48 = {66 59 42 44 45 51 5c 71 5c 5c 5f 53}
	$49 = {67 58 43 45 44 50 5d 70 5d 5d 5e 52}
	$50 = {64 5b 40 46 47 53 5e 73 5e 5e 5d 51}
	$51 = {65 5a 41 47 46 52 5f 72 5f 5f 5c 50}
	$52 = {62 5d 46 40 41 55 58 75 58 58 5b 57}
	$53 = {63 5c 47 41 40 54 59 74 59 59 5a 56}
	$54 = {60 5f 44 42 43 57 5a 77 5a 5a 59 55}
	$55 = {61 5e 45 43 42 56 5b 76 5b 5b 58 54}
	$56 = {6e 51 4a 4c 4d 59 54 79 54 54 57 5b}
	$57 = {6f 50 4b 4d 4c 58 55 78 55 55 56 5a}
	$58 = {6c 53 48 4e 4f 5b 56 7b 56 56 55 59}
	$59 = {6d 52 49 4f 4e 5a 57 7a 57 57 54 58}
	$60 = {6a 55 4e 48 49 5d 50 7d 50 50 53 5f}
	$61 = {6b 54 4f 49 48 5c 51 7c 51 51 52 5e}
	$62 = {68 57 4c 4a 4b 5f 52 7f 52 52 51 5d}
	$63 = {69 56 4d 4b 4a 5e 53 7e 53 53 50 5c}
	$64 = {16 29 32 34 35 21 2c 01 2c 2c 2f 23}
	$65 = {17 28 33 35 34 20 2d 00 2d 2d 2e 22}
	$66 = {14 2b 30 36 37 23 2e 03 2e 2e 2d 21}
	$67 = {15 2a 31 37 36 22 2f 02 2f 2f 2c 20}
	$68 = {12 2d 36 30 31 25 28 05 28 28 2b 27}
	$69 = {13 2c 37 31 30 24 29 04 29 29 2a 26}
	$70 = {10 2f 34 32 33 27 2a 07 2a 2a 29 25}
	$71 = {11 2e 35 33 32 26 2b 06 2b 2b 28 24}
	$72 = {1e 21 3a 3c 3d 29 24 09 24 24 27 2b}
	$73 = {1f 20 3b 3d 3c 28 25 08 25 25 26 2a}
	$74 = {1c 23 38 3e 3f 2b 26 0b 26 26 25 29}
	$75 = {1d 22 39 3f 3e 2a 27 0a 27 27 24 28}
	$76 = {1a 25 3e 38 39 2d 20 0d 20 20 23 2f}
	$77 = {1b 24 3f 39 38 2c 21 0c 21 21 22 2e}
	$78 = {18 27 3c 3a 3b 2f 22 0f 22 22 21 2d}
	$79 = {19 26 3d 3b 3a 2e 23 0e 23 23 20 2c}
	$80 = {06 39 22 24 25 31 3c 11 3c 3c 3f 33}
	$81 = {07 38 23 25 24 30 3d 10 3d 3d 3e 32}
	$82 = {04 3b 20 26 27 33 3e 13 3e 3e 3d 31}
	$83 = {05 3a 21 27 26 32 3f 12 3f 3f 3c 30}
	$84 = {02 3d 26 20 21 35 38 15 38 38 3b 37}
	$85 = {03 3c 27 21 20 34 39 14 39 39 3a 36}
	$86 = {00 3f 24 22 23 37 3a 17 3a 3a 39 35}
	$87 = {01 3e 25 23 22 36 3b 16 3b 3b 38 34}
	$88 = {0e 31 2a 2c 2d 39 34 19 34 34 37 3b}
	$89 = {0f 30 2b 2d 2c 38 35 18 35 35 36 3a}
	$90 = {0c 33 28 2e 2f 3b 36 1b 36 36 35 39}
	$91 = {0d 32 29 2f 2e 3a 37 1a 37 37 34 38}
	$92 = {0a 35 2e 28 29 3d 30 1d 30 30 33 3f}
	$93 = {0b 34 2f 29 28 3c 31 1c 31 31 32 3e}
	$94 = {08 37 2c 2a 2b 3f 32 1f 32 32 31 3d}
	$95 = {09 36 2d 2b 2a 3e 33 1e 33 33 30 3c}
	$96 = {36 09 12 14 15 01 0c 21 0c 0c 0f 03}
	$97 = {37 08 13 15 14 00 0d 20 0d 0d 0e 02}
	$98 = {34 0b 10 16 17 03 0e 23 0e 0e 0d 01}
	$99 = {35 0a 11 17 16 02 0f 22 0f 0f 0c 00}
	$100 = {32 0d 16 10 11 05 08 25 08 08 0b 07}
	$101 = {33 0c 17 11 10 04 09 24 09 09 0a 06}
	$102 = {30 0f 14 12 13 07 0a 27 0a 0a 09 05}
	$103 = {31 0e 15 13 12 06 0b 26 0b 0b 08 04}
	$104 = {3e 01 1a 1c 1d 09 04 29 04 04 07 0b}
	$105 = {3f 00 1b 1d 1c 08 05 28 05 05 06 0a}
	$106 = {3c 03 18 1e 1f 0b 06 2b 06 06 05 09}
	$107 = {3d 02 19 1f 1e 0a 07 2a 07 07 04 08}
	$108 = {3a 05 1e 18 19 0d 00 2d 00 00 03 0f}
	$109 = {3b 04 1f 19 18 0c 01 2c 01 01 02 0e}
	$110 = {38 07 1c 1a 1b 0f 02 2f 02 02 01 0d}
	$111 = {39 06 1d 1b 1a 0e 03 2e 03 03 00 0c}
	$112 = {26 19 02 04 05 11 1c 31 1c 1c 1f 13}
	$113 = {27 18 03 05 04 10 1d 30 1d 1d 1e 12}
	$114 = {24 1b 00 06 07 13 1e 33 1e 1e 1d 11}
	$115 = {25 1a 01 07 06 12 1f 32 1f 1f 1c 10}
	$116 = {22 1d 06 00 01 15 18 35 18 18 1b 17}
	$117 = {23 1c 07 01 00 14 19 34 19 19 1a 16}
	$118 = {20 1f 04 02 03 17 1a 37 1a 1a 19 15}
	$119 = {21 1e 05 03 02 16 1b 36 1b 1b 18 14}
	$120 = {2e 11 0a 0c 0d 19 14 39 14 14 17 1b}
	$121 = {2f 10 0b 0d 0c 18 15 38 15 15 16 1a}
	$122 = {2c 13 08 0e 0f 1b 16 3b 16 16 15 19}
	$123 = {2d 12 09 0f 0e 1a 17 3a 17 17 14 18}
	$124 = {2a 15 0e 08 09 1d 10 3d 10 10 13 1f}
	$125 = {2b 14 0f 09 08 1c 11 3c 11 11 12 1e}
	$126 = {28 17 0c 0a 0b 1f 12 3f 12 12 11 1d}
	$127 = {29 16 0d 0b 0a 1e 13 3e 13 13 10 1c}
	$128 = {d6 e9 f2 f4 f5 e1 ec c1 ec ec ef e3}
	$129 = {d7 e8 f3 f5 f4 e0 ed c0 ed ed ee e2}
	$130 = {d4 eb f0 f6 f7 e3 ee c3 ee ee ed e1}
	$131 = {d5 ea f1 f7 f6 e2 ef c2 ef ef ec e0}
	$132 = {d2 ed f6 f0 f1 e5 e8 c5 e8 e8 eb e7}
	$133 = {d3 ec f7 f1 f0 e4 e9 c4 e9 e9 ea e6}
	$134 = {d0 ef f4 f2 f3 e7 ea c7 ea ea e9 e5}
	$135 = {d1 ee f5 f3 f2 e6 eb c6 eb eb e8 e4}
	$136 = {de e1 fa fc fd e9 e4 c9 e4 e4 e7 eb}
	$137 = {df e0 fb fd fc e8 e5 c8 e5 e5 e6 ea}
	$138 = {dc e3 f8 fe ff eb e6 cb e6 e6 e5 e9}
	$139 = {dd e2 f9 ff fe ea e7 ca e7 e7 e4 e8}
	$140 = {da e5 fe f8 f9 ed e0 cd e0 e0 e3 ef}
	$141 = {db e4 ff f9 f8 ec e1 cc e1 e1 e2 ee}
	$142 = {d8 e7 fc fa fb ef e2 cf e2 e2 e1 ed}
	$143 = {d9 e6 fd fb fa ee e3 ce e3 e3 e0 ec}
	$144 = {c6 f9 e2 e4 e5 f1 fc d1 fc fc ff f3}
	$145 = {c7 f8 e3 e5 e4 f0 fd d0 fd fd fe f2}
	$146 = {c4 fb e0 e6 e7 f3 fe d3 fe fe fd f1}
	$147 = {c5 fa e1 e7 e6 f2 ff d2 ff ff fc f0}
	$148 = {c2 fd e6 e0 e1 f5 f8 d5 f8 f8 fb f7}
	$149 = {c3 fc e7 e1 e0 f4 f9 d4 f9 f9 fa f6}
	$150 = {c0 ff e4 e2 e3 f7 fa d7 fa fa f9 f5}
	$151 = {c1 fe e5 e3 e2 f6 fb d6 fb fb f8 f4}
	$152 = {ce f1 ea ec ed f9 f4 d9 f4 f4 f7 fb}
	$153 = {cf f0 eb ed ec f8 f5 d8 f5 f5 f6 fa}
	$154 = {cc f3 e8 ee ef fb f6 db f6 f6 f5 f9}
	$155 = {cd f2 e9 ef ee fa f7 da f7 f7 f4 f8}
	$156 = {ca f5 ee e8 e9 fd f0 dd f0 f0 f3 ff}
	$157 = {cb f4 ef e9 e8 fc f1 dc f1 f1 f2 fe}
	$158 = {c8 f7 ec ea eb ff f2 df f2 f2 f1 fd}
	$159 = {c9 f6 ed eb ea fe f3 de f3 f3 f0 fc}
	$160 = {f6 c9 d2 d4 d5 c1 cc e1 cc cc cf c3}
	$161 = {f7 c8 d3 d5 d4 c0 cd e0 cd cd ce c2}
	$162 = {f4 cb d0 d6 d7 c3 ce e3 ce ce cd c1}
	$163 = {f5 ca d1 d7 d6 c2 cf e2 cf cf cc c0}
	$164 = {f2 cd d6 d0 d1 c5 c8 e5 c8 c8 cb c7}
	$165 = {f3 cc d7 d1 d0 c4 c9 e4 c9 c9 ca c6}
	$166 = {f0 cf d4 d2 d3 c7 ca e7 ca ca c9 c5}
	$167 = {f1 ce d5 d3 d2 c6 cb e6 cb cb c8 c4}
	$168 = {fe c1 da dc dd c9 c4 e9 c4 c4 c7 cb}
	$169 = {ff c0 db dd dc c8 c5 e8 c5 c5 c6 ca}
	$170 = {fc c3 d8 de df cb c6 eb c6 c6 c5 c9}
	$171 = {fd c2 d9 df de ca c7 ea c7 c7 c4 c8}
	$172 = {fa c5 de d8 d9 cd c0 ed c0 c0 c3 cf}
	$173 = {fb c4 df d9 d8 cc c1 ec c1 c1 c2 ce}
	$174 = {f8 c7 dc da db cf c2 ef c2 c2 c1 cd}
	$175 = {f9 c6 dd db da ce c3 ee c3 c3 c0 cc}
	$176 = {e6 d9 c2 c4 c5 d1 dc f1 dc dc df d3}
	$177 = {e7 d8 c3 c5 c4 d0 dd f0 dd dd de d2}
	$178 = {e4 db c0 c6 c7 d3 de f3 de de dd d1}
	$179 = {e5 da c1 c7 c6 d2 df f2 df df dc d0}
	$180 = {e2 dd c6 c0 c1 d5 d8 f5 d8 d8 db d7}
	$181 = {e3 dc c7 c1 c0 d4 d9 f4 d9 d9 da d6}
	$182 = {e0 df c4 c2 c3 d7 da f7 da da d9 d5}
	$183 = {e1 de c5 c3 c2 d6 db f6 db db d8 d4}
	$184 = {ee d1 ca cc cd d9 d4 f9 d4 d4 d7 db}
	$185 = {ef d0 cb cd cc d8 d5 f8 d5 d5 d6 da}
	$186 = {ec d3 c8 ce cf db d6 fb d6 d6 d5 d9}
	$187 = {ed d2 c9 cf ce da d7 fa d7 d7 d4 d8}
	$188 = {ea d5 ce c8 c9 dd d0 fd d0 d0 d3 df}
	$189 = {eb d4 cf c9 c8 dc d1 fc d1 d1 d2 de}
	$190 = {e8 d7 cc ca cb df d2 ff d2 d2 d1 dd}
	$191 = {e9 d6 cd cb ca de d3 fe d3 d3 d0 dc}
	$192 = {96 a9 b2 b4 b5 a1 ac 81 ac ac af a3}
	$193 = {97 a8 b3 b5 b4 a0 ad 80 ad ad ae a2}
	$194 = {94 ab b0 b6 b7 a3 ae 83 ae ae ad a1}
	$195 = {95 aa b1 b7 b6 a2 af 82 af af ac a0}
	$196 = {92 ad b6 b0 b1 a5 a8 85 a8 a8 ab a7}
	$197 = {93 ac b7 b1 b0 a4 a9 84 a9 a9 aa a6}
	$198 = {90 af b4 b2 b3 a7 aa 87 aa aa a9 a5}
	$199 = {91 ae b5 b3 b2 a6 ab 86 ab ab a8 a4}
	$200 = {9e a1 ba bc bd a9 a4 89 a4 a4 a7 ab}
	$201 = {9f a0 bb bd bc a8 a5 88 a5 a5 a6 aa}
	$202 = {9c a3 b8 be bf ab a6 8b a6 a6 a5 a9}
	$203 = {9d a2 b9 bf be aa a7 8a a7 a7 a4 a8}
	$204 = {9a a5 be b8 b9 ad a0 8d a0 a0 a3 af}
	$205 = {9b a4 bf b9 b8 ac a1 8c a1 a1 a2 ae}
	$206 = {98 a7 bc ba bb af a2 8f a2 a2 a1 ad}
	$207 = {99 a6 bd bb ba ae a3 8e a3 a3 a0 ac}
	$208 = {86 b9 a2 a4 a5 b1 bc 91 bc bc bf b3}
	$209 = {87 b8 a3 a5 a4 b0 bd 90 bd bd be b2}
	$210 = {84 bb a0 a6 a7 b3 be 93 be be bd b1}
	$211 = {85 ba a1 a7 a6 b2 bf 92 bf bf bc b0}
	$212 = {82 bd a6 a0 a1 b5 b8 95 b8 b8 bb b7}
	$213 = {83 bc a7 a1 a0 b4 b9 94 b9 b9 ba b6}
	$214 = {80 bf a4 a2 a3 b7 ba 97 ba ba b9 b5}
	$215 = {81 be a5 a3 a2 b6 bb 96 bb bb b8 b4}
	$216 = {8e b1 aa ac ad b9 b4 99 b4 b4 b7 bb}
	$217 = {8f b0 ab ad ac b8 b5 98 b5 b5 b6 ba}
	$218 = {8c b3 a8 ae af bb b6 9b b6 b6 b5 b9}
	$219 = {8d b2 a9 af ae ba b7 9a b7 b7 b4 b8}
	$220 = {8a b5 ae a8 a9 bd b0 9d b0 b0 b3 bf}
	$221 = {8b b4 af a9 a8 bc b1 9c b1 b1 b2 be}
	$222 = {88 b7 ac aa ab bf b2 9f b2 b2 b1 bd}
	$223 = {89 b6 ad ab aa be b3 9e b3 b3 b0 bc}
	$224 = {b6 89 92 94 95 81 8c a1 8c 8c 8f 83}
	$225 = {b7 88 93 95 94 80 8d a0 8d 8d 8e 82}
	$226 = {b4 8b 90 96 97 83 8e a3 8e 8e 8d 81}
	$227 = {b5 8a 91 97 96 82 8f a2 8f 8f 8c 80}
	$228 = {b2 8d 96 90 91 85 88 a5 88 88 8b 87}
	$229 = {b3 8c 97 91 90 84 89 a4 89 89 8a 86}
	$230 = {b0 8f 94 92 93 87 8a a7 8a 8a 89 85}
	$231 = {b1 8e 95 93 92 86 8b a6 8b 8b 88 84}
	$232 = {be 81 9a 9c 9d 89 84 a9 84 84 87 8b}
	$233 = {bf 80 9b 9d 9c 88 85 a8 85 85 86 8a}
	$234 = {bc 83 98 9e 9f 8b 86 ab 86 86 85 89}
	$235 = {bd 82 99 9f 9e 8a 87 aa 87 87 84 88}
	$236 = {ba 85 9e 98 99 8d 80 ad 80 80 83 8f}
	$237 = {bb 84 9f 99 98 8c 81 ac 81 81 82 8e}
	$238 = {b8 87 9c 9a 9b 8f 82 af 82 82 81 8d}
	$239 = {b9 86 9d 9b 9a 8e 83 ae 83 83 80 8c}
	$240 = {a6 99 82 84 85 91 9c b1 9c 9c 9f 93}
	$241 = {a7 98 83 85 84 90 9d b0 9d 9d 9e 92}
	$242 = {a4 9b 80 86 87 93 9e b3 9e 9e 9d 91}
	$243 = {a5 9a 81 87 86 92 9f b2 9f 9f 9c 90}
	$244 = {a2 9d 86 80 81 95 98 b5 98 98 9b 97}
	$245 = {a3 9c 87 81 80 94 99 b4 99 99 9a 96}
	$246 = {a0 9f 84 82 83 97 9a b7 9a 9a 99 95}
	$247 = {a1 9e 85 83 82 96 9b b6 9b 9b 98 94}
	$248 = {ae 91 8a 8c 8d 99 94 b9 94 94 97 9b}
	$249 = {af 90 8b 8d 8c 98 95 b8 95 95 96 9a}
	$250 = {ac 93 88 8e 8f 9b 96 bb 96 96 95 99}
	$251 = {ad 92 89 8f 8e 9a 97 ba 97 97 94 98}
	$252 = {aa 95 8e 88 89 9d 90 bd 90 90 93 9f}
	$253 = {ab 94 8f 89 88 9c 91 bc 91 91 92 9e}
	$254 = {a8 97 8c 8a 8b 9f 92 bf 92 92 91 9d}
	$255 = {a9 96 8d 8b 8a 9e 93 be 93 93 90 9c}
condition:
any of them
}


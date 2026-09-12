
<a name="v0.16.3"></a>
## [v0.16.3] - 2026-08-24
### Fix
- range check quotient for small fields
- update version
<a name="v0.16.2"></a>
## [v0.16.2] - 2026-08-21
### Fix
- Bind quotient in smallCheckZero
- **sha3:** Bind the Euclidean relation length
<a name="v0.16.1"></a>
## [v0.16.1] - 2026-08-20
### Fix
- AddUnified for bw6-761 2-torsion points
<a name="v0.16.0"></a>
## [v0.16.0] - 2026-08-19
### Build
- **deps:** bump golang.org/x/crypto from 0.48.0 to 0.52.0 in the go_modules group across 1 directory ([#1793](https://github.com/Consensys/gnark/issues/1793))
### Chore
- prepare v0.16.0 release
- update dependencies ([#1803](https://github.com/Consensys/gnark/issues/1803))
- pin and update GitHub Actions to latest releases ([#1784](https://github.com/Consensys/gnark/issues/1784))
- remove FRI verifier gadget ([#1777](https://github.com/Consensys/gnark/issues/1777))
### Feat
- map-to-curve relations ([#1746](https://github.com/Consensys/gnark/issues/1746))
### Fix
- regenerate gkr_poseidon2 binary file
- do not discard returned value in Miller loop precomputelines ([#1786](https://github.com/Consensys/gnark/issues/1786))
- validate Plonk proof structure according to verifying key ([#1787](https://github.com/Consensys/gnark/issues/1787))
- GLV subscalar range checks ([#1778](https://github.com/Consensys/gnark/issues/1778))
### Perf
- optimize `Lookup2` and `Xor(x,0)` ([#1801](https://github.com/Consensys/gnark/issues/1801))
- twisted Edwards lattice-based double-base MSM ([#1765](https://github.com/Consensys/gnark/issues/1765))
- G2 lattice-based GLV+FakeGLV scalar-mul ([#1764](https://github.com/Consensys/gnark/issues/1764))
- use lattice scalar decomposition for tighter scalar-mul bounds ([#1763](https://github.com/Consensys/gnark/issues/1763))
- **bls12-377:** randomized Schwartz-Zippel in native Fp6 and Fp12 ([#1760](https://github.com/Consensys/gnark/issues/1760))
### Refactor
- enforce least-privilege in GitHub Actions workflows ([#1785](https://github.com/Consensys/gnark/issues/1785))
<a name="v0.15.0"></a>
## [v0.15.0] - 2026-05-14
### Build
- updated to latest gnark crypto api change (code gen) ([#1668](https://github.com/Consensys/gnark/issues/1668))
- **deps:** bump golang.org/x/crypto from 0.41.0 to 0.45.0 in the go_modules group across 1 directory ([#1652](https://github.com/Consensys/gnark/issues/1652))
- **deps:** bump github.com/consensys/gnark-crypto from 0.19.0 to 0.19.1 in the go_modules group across 1 directory ([#1636](https://github.com/Consensys/gnark/issues/1636))
### CI
- enable security code scanner ([#1655](https://github.com/Consensys/gnark/issues/1655))
### Chore
- pin GitHub Actions to commit SHAs ([#1766](https://github.com/Consensys/gnark/issues/1766))
- golangcilint update ([#1726](https://github.com/Consensys/gnark/issues/1726))
- add dependabot configuration for GitHub Actions updates ([#1714](https://github.com/Consensys/gnark/issues/1714))
- update CI workflows to go 1.25 ([#1710](https://github.com/Consensys/gnark/issues/1710))
- regenerate tinyfield ([#1602](https://github.com/Consensys/gnark/issues/1602))
- use self hosted runners ([#1633](https://github.com/Consensys/gnark/issues/1633))
- small cleanup in pairings ([#1621](https://github.com/Consensys/gnark/issues/1621))
- use standard lib testing environment detection ([#1631](https://github.com/Consensys/gnark/issues/1631))
- collect small contributions for next release v0.15 ([#1606](https://github.com/Consensys/gnark/issues/1606))
### Docs
- update README.md ([#1712](https://github.com/Consensys/gnark/issues/1712))
- added zkBTC to gnark known users ([#1658](https://github.com/Consensys/gnark/issues/1658))
### Feat
- better emulation for small fields in large fields ([#1682](https://github.com/Consensys/gnark/issues/1682))
- correct curve names in error messages and vector type ([#1587](https://github.com/Consensys/gnark/issues/1587))
- make elliptic curve arithmetic complete by default and only fallback to incomplete path on request ([#1751](https://github.com/Consensys/gnark/issues/1751))
- add grumpkin curve support ([#1729](https://github.com/Consensys/gnark/issues/1729))
- Test engine to store elements in Montgomery format ([#1695](https://github.com/Consensys/gnark/issues/1695))
- add new api to profile package to capture virtual constraints ([#1696](https://github.com/Consensys/gnark/issues/1696))
- add PointEval precompiles for 16-bit limbs ([#1689](https://github.com/Consensys/gnark/issues/1689))
- emulated arithmetic bound optimization ([#1688](https://github.com/Consensys/gnark/issues/1688))
- Compiled Gates for GKR ([#1676](https://github.com/Consensys/gnark/issues/1676))
- add internal Koalabear E4 extension for field emulation and logderivative argument ([#1672](https://github.com/Consensys/gnark/issues/1672))
- allow replacing hints in test engine ([#1737](https://github.com/Consensys/gnark/issues/1737))
- implement log-derivative argument over small fields ([#1673](https://github.com/Consensys/gnark/issues/1673))
- clean up interface assertions in circuits ([#1685](https://github.com/Consensys/gnark/issues/1685))
- Enable multiple GKR sub-circuits ([#1661](https://github.com/Consensys/gnark/issues/1661))
- add example for printing constraints ([#1643](https://github.com/Consensys/gnark/issues/1643))
- EIP-7951 for ECDSA on P-256 curve ([#1649](https://github.com/Consensys/gnark/issues/1649))
- implement flag based recursive groth16 and EdDSA check ([#1647](https://github.com/Consensys/gnark/issues/1647))
- add BLS12-377, BLS12-381 and BW6-761 GPU acceleration support for Groth16 ([#1625](https://github.com/Consensys/gnark/issues/1625))
- add Grumpkin elliptic curve (native 2-cycle with BN254) ([#1409](https://github.com/Consensys/gnark/issues/1409))
- allow taking benchmarking instance in NewAssert ([#1607](https://github.com/Consensys/gnark/issues/1607))
- implement BLS signature verification (minimal public key) ([#1473](https://github.com/Consensys/gnark/issues/1473))
- pointeval precompile circuit for failing inputs  ([#1572](https://github.com/Consensys/gnark/issues/1572))
- **poseidon2:** support BN254 widths t=4,8,12,16; fix matMulExternal indexing ([#1743](https://github.com/Consensys/gnark/issues/1743))
- GKR-Hashers ([#1512](https://github.com/Consensys/gnark/issues/1512))
### Fix
- plonk commitment input deduplicate effective constants ([#1754](https://github.com/Consensys/gnark/issues/1754))
- add proof commitment length check for better error messages ([#1739](https://github.com/Consensys/gnark/issues/1739))
- initialize in-circuit KZG SRS at compile time ([#1738](https://github.com/Consensys/gnark/issues/1738))
- emulated package tests failing with 1 constraint with PLONK backend ([#1733](https://github.com/Consensys/gnark/issues/1733))
- BLS12-381 Solidity contract init and proof marshaling ([#1732](https://github.com/Consensys/gnark/issues/1732))
- DivUnchecked consistency ([#1734](https://github.com/Consensys/gnark/issues/1734))
- non-native constant ops fast paths ([#1730](https://github.com/Consensys/gnark/issues/1730))
- register gates in GKR Poseidon ([#1719](https://github.com/Consensys/gnark/issues/1719))
- fix cursor bot comments ([#1713](https://github.com/Consensys/gnark/issues/1713))
- EdDSA strict equality check for s ([#1684](https://github.com/Consensys/gnark/issues/1684))
- handle uints8 Long addition even in small field ([#1674](https://github.com/Consensys/gnark/issues/1674))
- avoid MulAcc overwriting constants ([#1632](https://github.com/Consensys/gnark/issues/1632))
- handle OR call for constant inputs ([#1592](https://github.com/Consensys/gnark/issues/1592))
- use the little-endian representation for serialized values in KZG Pointeval precompile ([#1614](https://github.com/Consensys/gnark/issues/1614))
- bit/byte shift in random bound ([#1590](https://github.com/Consensys/gnark/issues/1590))
- add G1 membership for ML and FE in bls precompile ([#1591](https://github.com/Consensys/gnark/issues/1591))
- KZG proof verification for edge cases ([#1567](https://github.com/Consensys/gnark/issues/1567))
### ICICLE
- MSM chunking, safety on proof generation and GPU memory reduction ([#1665](https://github.com/Consensys/gnark/issues/1665))
### Perf
- use known base length for small field emulation ([#1693](https://github.com/Consensys/gnark/issues/1693))
- optimize native Fp2 mul ([#1758](https://github.com/Consensys/gnark/issues/1758))
- optimize emulated multi-miller loops via sparse×sparse line multiplications for 0-bits ([#1701](https://github.com/Consensys/gnark/issues/1701))
- Factor Eq in ZeroCheck when possible ([#1742](https://github.com/Consensys/gnark/issues/1742))
- GKR Levels ([#1735](https://github.com/Consensys/gnark/issues/1735))
- solver optimizations ([#1728](https://github.com/Consensys/gnark/issues/1728))
- emulated Eval support negative coefficients ([#1727](https://github.com/Consensys/gnark/issues/1727))
- optimize emulated `ToBits` and `ToBitsCanonical` ([#1707](https://github.com/Consensys/gnark/issues/1707))
- windowed-4 ModExp precompile ([#1700](https://github.com/Consensys/gnark/issues/1700))
- save 1 inverse in P256Verify circuit ([#1656](https://github.com/Consensys/gnark/issues/1656))
- use generic hint mechanism for bls12-381 map to G1/G2 hints ([#1653](https://github.com/Consensys/gnark/issues/1653))
- dedicated `Cube` method in extension fields ([#1759](https://github.com/Consensys/gnark/issues/1759))
- optimize LogUp for constant single-column tables (range checks) ([#1717](https://github.com/Consensys/gnark/issues/1717))
- optimize range checks for small number of small field ops ([#1699](https://github.com/Consensys/gnark/issues/1699))
- optimize smallmul zero check ([#1694](https://github.com/Consensys/gnark/issues/1694))
- generalize sparse solver optimizations ([#1761](https://github.com/Consensys/gnark/issues/1761))
- optimize scs constraints for bls12377 poseidon2 permutation ([#1690](https://github.com/Consensys/gnark/issues/1690))
- improve compile time by 20% ([#1686](https://github.com/Consensys/gnark/issues/1686))
- optimize rangecheck recomposition for PlonK backend ([#1683](https://github.com/Consensys/gnark/issues/1683))
- deduplicate commitment copy constraints in PLONK ([#1670](https://github.com/Consensys/gnark/issues/1670))
- **Mux:** shared selector decomposition and ±Y symmetry optimization in emulated MSM ([#1704](https://github.com/Consensys/gnark/issues/1704))
- **plonk:** reduce LRO commitment MSM size via s0-padding identity ([#1716](https://github.com/Consensys/gnark/issues/1716))
### Refactor
- remove bls24-315, bls24-317, and bw6-633 ([#1708](https://github.com/Consensys/gnark/issues/1708))
- support dynamic emulation parameters for ecrec ([#1660](https://github.com/Consensys/gnark/issues/1660))
- PLONK commitment input and output registration ([#1642](https://github.com/Consensys/gnark/issues/1642))
### Release
- gnark v0.15.0 ([#1731](https://github.com/Consensys/gnark/issues/1731))
### Test
- add small field test in checkcircuit ([#1671](https://github.com/Consensys/gnark/issues/1671))
- handle gnark-crypto not returning malleable signatures anymore ([#1601](https://github.com/Consensys/gnark/issues/1601))
- refactor crumb test to standard path ([#1648](https://github.com/Consensys/gnark/issues/1648))
<a name="v0.14.0"></a>
## [v0.14.0] - 2025-08-22
### Chore
- update to latest gnark-crypto ([#1586](https://github.com/Consensys/gnark/issues/1586))
### Docs
- add doctest examples ([#1569](https://github.com/Consensys/gnark/issues/1569))
- add AlgoPlonk to KNOWN_USERS.md
- add reclaim protocol ([#1537](https://github.com/Consensys/gnark/issues/1537))
### Feat
- addition of Trace constructor of plonk on koalabear ([#1514](https://github.com/Consensys/gnark/issues/1514))
- add conversion utility to convert between bytes and elements ([#1542](https://github.com/Consensys/gnark/issues/1542))
- add separate Bytes API in `std/math/uints` package for handling bytes (U8) directly ([#1541](https://github.com/Consensys/gnark/issues/1541))
### Fix
- bls12-381 edge cases ([#1559](https://github.com/Consensys/gnark/issues/1559))
- prevent early return in RegisterHint causing missing registrations ([#1552](https://github.com/Consensys/gnark/issues/1552))
- scalarmul by 0 on twisted edwards curves ([#1551](https://github.com/Consensys/gnark/issues/1551))
- single constraint unsafe KZG SRS in tests ([#1544](https://github.com/Consensys/gnark/issues/1544))
- optimize zero constant detection and assignment ([#1545](https://github.com/Consensys/gnark/issues/1545))
- update Zcash protocol specification link ([#1535](https://github.com/Consensys/gnark/issues/1535))
- update broken Ethereum precompile contract links ([#1532](https://github.com/Consensys/gnark/issues/1532))
- enable fuzzing for multi-output-hint test by improving dvHint validation ([#1517](https://github.com/Consensys/gnark/issues/1517))
### Refactor
- BLS EVM precompile integration ([#1515](https://github.com/Consensys/gnark/issues/1515))
- crossfield hints in non-native ([#1539](https://github.com/Consensys/gnark/issues/1539))
### Release
- prepare for v0.14.0 release
- v0.13.0 ([#1516](https://github.com/Consensys/gnark/issues/1516))
<a name="v0.13.0"></a>
## [v0.13.0] - 2025-06-12
### Build
- upgrade gnark-crypto to v0.18.0 and minor upgrades in go.mod
- **deps:** bump golang.org/x/crypto from 0.33.0 to 0.35.0 ([#1478](https://github.com/Consensys/gnark/issues/1478))
### Chore
- remove useless github workflow
- add not-accepted github workflow
### Docs
- up comments ([#1503](https://github.com/Consensys/gnark/issues/1503))
- notify undefined result ([#1488](https://github.com/Consensys/gnark/issues/1488))
### Feat
- constant value binary decomposition ([#1510](https://github.com/Consensys/gnark/issues/1510))
- implement field emulation over small fields ([#1495](https://github.com/Consensys/gnark/issues/1495))
- add WideCommitter for obtaining commitment in the field extension ([#1494](https://github.com/Consensys/gnark/issues/1494))
- add field extension support over native fields ([#1493](https://github.com/Consensys/gnark/issues/1493))
- make automatic element initialization aware of the current field ([#1492](https://github.com/Consensys/gnark/issues/1492))
- emulated AssertIsDifferent ([#1479](https://github.com/Consensys/gnark/issues/1479))
- map to g2 on BLS12-381 ([#1477](https://github.com/Consensys/gnark/issues/1477))
- add Pectra BLS12-381 elliptic curve precompiles ([#1447](https://github.com/Consensys/gnark/issues/1447))
- make constraint.Element generic interface ([#1463](https://github.com/Consensys/gnark/issues/1463))
- use OSS ICICLE for GPU acceleration (version v3.2.2) ([#1451](https://github.com/Consensys/gnark/issues/1451))
- merkle damgard and poseidon2 ([#1407](https://github.com/Consensys/gnark/issues/1407))
- **wires:** implements GetWiresConstraintExact as a draft proposal ([#1462](https://github.com/Consensys/gnark/issues/1462))
- implement FixedLengthSum function for sha3 ([#1379](https://github.com/Consensys/gnark/issues/1379))
### Fix
- don't use assignment to compile ([#1508](https://github.com/Consensys/gnark/issues/1508))
- range over all limbs in normalized form for lookup ([#1505](https://github.com/Consensys/gnark/issues/1505))
- fake glv neg scalars ([#1487](https://github.com/Consensys/gnark/issues/1487))
- Ratio Verification on Groth16 MPC - Phase 1 ([#1465](https://github.com/Consensys/gnark/issues/1465))
- non-native zero IsZero edge case ([#1413](https://github.com/Consensys/gnark/issues/1413))
- make GetWiresConstraint(Exact) deterministic ([#1485](https://github.com/Consensys/gnark/issues/1485))
### Perf
- optimize selector.Mux with recursive BinaryMux for various sizes ([#1420](https://github.com/Consensys/gnark/issues/1420))
- Poseidon2 GKR circuit ([#1410](https://github.com/Consensys/gnark/issues/1410))
### Style
- `goimports` ([#1491](https://github.com/Consensys/gnark/issues/1491))
<a name="v0.12.0"></a>
## [v0.12.0] - 2025-01-24
### Build
- modify workflows for new CI slack bot ([#1277](https://github.com/Consensys/gnark/issues/1277))
- **deps:** bump golang.org/x/crypto from 0.26.0 to 0.31.0 ([#1346](https://github.com/Consensys/gnark/issues/1346))
### Chore
- fix some struct names in comment ([#1370](https://github.com/Consensys/gnark/issues/1370))
- fix typos ([#1371](https://github.com/Consensys/gnark/issues/1371))
- fix error message  ([#1337](https://github.com/Consensys/gnark/issues/1337))
- use errors.New to replace fmt.Errorf with no parameters ([#1338](https://github.com/Consensys/gnark/issues/1338))
- fix some problematic function names in comment ([#1334](https://github.com/Consensys/gnark/issues/1334))
- fix some struct and interface names in comment ([#1329](https://github.com/Consensys/gnark/issues/1329))
- remove duplicate nil-check ([#1355](https://github.com/Consensys/gnark/issues/1355))
- fix some function names in comment ([#1304](https://github.com/Consensys/gnark/issues/1304))
- Replace fmt.Printf calls with warning logs ([#1305](https://github.com/Consensys/gnark/issues/1305))
- Pedersen verification key reference field ([#1295](https://github.com/Consensys/gnark/issues/1295))
- lint generated files ([#1289](https://github.com/Consensys/gnark/issues/1289))
- up gnark-crypto ([#1274](https://github.com/Consensys/gnark/issues/1274))
### Docs
- add audit report ([#1342](https://github.com/Consensys/gnark/issues/1342))
- Change copyright year to 2025 (not autogenerated) ([#1388](https://github.com/Consensys/gnark/issues/1388))
- less verbose Apache 2 header, latest bavard ([#1344](https://github.com/Consensys/gnark/issues/1344))
- add input packing example ([#1311](https://github.com/Consensys/gnark/issues/1311))
- update api doc following audit suggestions ([#1291](https://github.com/Consensys/gnark/issues/1291))
- final audit report from LA ([#1283](https://github.com/Consensys/gnark/issues/1283))
### Feat
- settable hasher for MiMC ([#1345](https://github.com/Consensys/gnark/issues/1345))
- 4-dimensional fake GLV ([#1296](https://github.com/Consensys/gnark/issues/1296))
- add ripemd160 hash function with permutation ([#1120](https://github.com/Consensys/gnark/issues/1120))
- direct multivariate polynomial evaluation in non-native ([#1299](https://github.com/Consensys/gnark/issues/1299))
- update to latest gnark-crypto
- replace stats gob format with csv for easier diffs ([#1276](https://github.com/Consensys/gnark/issues/1276))
- **bls12-381:** pairing using direct Fp12 + non-native `Eval()` ([#1349](https://github.com/Consensys/gnark/issues/1349))
### Fix
- stashed typo fixes for v0.12 ([#1398](https://github.com/Consensys/gnark/issues/1398))
- add G2 membership check for constant points ([#1397](https://github.com/Consensys/gnark/issues/1397))
- do not return unused sign ([#1385](https://github.com/Consensys/gnark/issues/1385))
- typos in documentation files ([#1369](https://github.com/Consensys/gnark/issues/1369))
- spellchecker  ([#1359](https://github.com/Consensys/gnark/issues/1359))
- typos in documentation files ([#1327](https://github.com/Consensys/gnark/issues/1327))
- tinyfield generation with updated gnark-crypto ([#1358](https://github.com/Consensys/gnark/issues/1358))
- avoid linking icicle dependent files when tag not provided ([#1352](https://github.com/Consensys/gnark/issues/1352))
- NNA quotient length computation edge cases ([#1340](https://github.com/Consensys/gnark/issues/1340))
- initialize public committed ([#1317](https://github.com/Consensys/gnark/issues/1317))
- sanitize groth16 verification key reading ([#1307](https://github.com/Consensys/gnark/issues/1307))
- expmod precompile if modulus is 1 ([#1294](https://github.com/Consensys/gnark/issues/1294))
- allow only v=0 or v=1 ([#1293](https://github.com/Consensys/gnark/issues/1293))
- fix slice init length ([#1288](https://github.com/Consensys/gnark/issues/1288))
### Optim
- avoid div in millerLoopAndFinalExpResult ([#1363](https://github.com/Consensys/gnark/issues/1363))
### Perf
- Pairing on BN254 using direct Fp12 extension and non-native `Eval()` ([#1339](https://github.com/Consensys/gnark/issues/1339))
- `PairingCheck` for BN254, BLS12-381, BLS12-377 and BW6-761 ([#1365](https://github.com/Consensys/gnark/issues/1365))
- G1/2 membership using Eval ([#1356](https://github.com/Consensys/gnark/issues/1356))
- using non-native Eval for curve arithmetic ([#1331](https://github.com/Consensys/gnark/issues/1331))
- normalize the random linear combination in logderivarg ([#1333](https://github.com/Consensys/gnark/issues/1333))
- BW6 pairing computation using non-native Eval ([#1312](https://github.com/Consensys/gnark/issues/1312))
- fast path operations for small non-native values ([#1326](https://github.com/Consensys/gnark/issues/1326))
- **bn254:** include G2 membership check in ML ([#1387](https://github.com/Consensys/gnark/issues/1387))
- **emulated:** small perf on doubleAndAdd ([#1386](https://github.com/Consensys/gnark/issues/1386))
### Refactor
- move poseidon2 to permutation package ([#1353](https://github.com/Consensys/gnark/issues/1353))
### Release
- v0.12.0 ([#1399](https://github.com/Consensys/gnark/issues/1399))
### Test
- add scalar mul to stats ([#1275](https://github.com/Consensys/gnark/issues/1275))

### Pull Requests
- Merge pull request [#1298](https://github.com/Consensys/gnark/issues/1298) from Consensys/build/gnark-crypto
<a name="v0.11.0"></a>
## [v0.11.0] - 2024-09-06
### Build
- update runner and go version ([#1260](https://github.com/Consensys/gnark/issues/1260))
### Chore
- explicit IO methods in interfaces ([#1266](https://github.com/Consensys/gnark/issues/1266))
- update gnark-crypto module
- clean old definition
- generate
- define interface for solidity-supported VK
- make function comments match function names ([#1163](https://github.com/Consensys/gnark/issues/1163))
### Docs
- update README ([#1255](https://github.com/Consensys/gnark/issues/1255))
- update reference
- describe potential length extension attack when using MiMC in-circuit ([#1198](https://github.com/Consensys/gnark/issues/1198))
- fix typo in package doc
- add documentation
- update documentation for ecdsa and eddsa
- update TODOs ([#1109](https://github.com/Consensys/gnark/issues/1109))
### Feat
- use offset variable in derive_gamma
- handle invalid signature failures in ECRecover precompile ([#1101](https://github.com/Consensys/gnark/issues/1101))
- allow configurable hash-to-field function for Groth16 Solidity verifier ([#1102](https://github.com/Consensys/gnark/issues/1102))
- add IsOnG2 for BN254 ([#1204](https://github.com/Consensys/gnark/issues/1204))
- use blake2 for variable hashcode ([#1197](https://github.com/Consensys/gnark/issues/1197))
- simplified offset computation
- ensure verifying keys implement Solidity interface
- handle solidity options in CI check
- use fpstr in Groth16 Solidity template
- define fpstr method for groth16 solidity template
- define import_fp template
- code gen
- statistical zero knowledge option for bn254
- use offset in pairing
- capture O variable in gate for external range checker ([#1211](https://github.com/Consensys/gnark/issues/1211))
- code gen
- add BN254 final exponentiation check with output ([#1209](https://github.com/Consensys/gnark/issues/1209))
- use anonymous struct
- added version solidity template groth16 verifier
- re ran code gen and add files
- update solidity template groth16
- update template
- change signature ExportSolidity groth16
- code gen
- code gen
- modified plonk template
- code gen
- modified signature of ExportSolidity in template
- addition of export options for solidity verifiers
- simplify loop constraint index
- **bw6:** Fp6 as a direct extension using Montgomery-6
- implement FixedLengthSum of sha2 ([#821](https://github.com/Consensys/gnark/issues/821))
### Fix
- Build on 32-bit arch would raise int overflow https://github.com/Consensys/gnark/issues/1192 ([#1195](https://github.com/Consensys/gnark/issues/1195))
- remove redundant select
- variable modulus subtraction padding ([#1200](https://github.com/Consensys/gnark/issues/1200))
- branch with unchecked cast could panic at compile time ([#1234](https://github.com/Consensys/gnark/issues/1234))
- minimum 1 bit for constant binary decomposition ([#1229](https://github.com/Consensys/gnark/issues/1229))
- edge case with PLONK backend when 1 constraint ([#1226](https://github.com/Consensys/gnark/issues/1226))
- strict ModReduce in emulated fields ([#1224](https://github.com/Consensys/gnark/issues/1224))
- used size in domain instead of recomputing it
- remove unconstrained and unused variables
- remove unconstrained and unused variables ([#1218](https://github.com/Consensys/gnark/issues/1218))
- avoid malicious hint in BLS12-381 final exp check
- avoid infinite loop in hint when previous ML=0
- avoid malicious hint in BN254 final exp check
- conditional check in non-native IsZero for applying optimization ([#1145](https://github.com/Consensys/gnark/issues/1145))
- use consecutive powers instead of squaring ([#1212](https://github.com/Consensys/gnark/issues/1212))
- use emulated arithmetic for GLV decomp ([#1167](https://github.com/Consensys/gnark/issues/1167))
- restored cfg struct
- fixed error_mod_exp comment
- shift constraint indices by nb of public vars ([#1128](https://github.com/Consensys/gnark/issues/1128))
- fixed conflicts
- fixed comment prove
- fixed typo PROOF_H_0_X -> PROOF_H_0_COM_X
- fixed UnmarshalSolidity
- fixed comment
- fixed fold_h comment
- fixed comment
- fixed comment
- removed redundant computation pointer update
- remove redundant computation
- several external typo fixes ([#1261](https://github.com/Consensys/gnark/issues/1261))
- ensure condition is bool in api.Select
- fix OR computation in case one input is constant and other variable ([#1181](https://github.com/Consensys/gnark/issues/1181))
- fixed comment unmarshal
- fixed comment solidity
- fixed comment solidity
- fixed comment solidity
- fixed comment solidity
- fixed some comments
- fixed L-05
- fixed L-04
- fixed M-04
- fixed L-04
- fixed l-02
- defer to math.bits when nbdigits big or not set
- fix [#1149](https://github.com/Consensys/gnark/issues/1149) by removing unused code ([#1164](https://github.com/Consensys/gnark/issues/1164))
- exact width for upper part
- more descriptive error message ([#1104](https://github.com/Consensys/gnark/issues/1104))
- added missing import in template
- fixed solidity template
- fixes [#1157](https://github.com/Consensys/gnark/issues/1157) ensures calls to AttachDebugInfo are surrounded with… ([#1160](https://github.com/Consensys/gnark/issues/1160))
- **bls12-377:** use FinalExponentiationCheck in pairing2.go
- **bls12-377:** push to cyclo group in pairing2.go
- **bls12-377:** hint computation for final exp
- **bls12-377:** naming of Fp6 mul
- **bw6:** Toom-Cook 6-way mul
- **bw6:** pairing using direct sextic extension
- **pairing:** fix benchmarks
- **uints:** constrain valueOf ([#1139](https://github.com/Consensys/gnark/issues/1139))
### Perf
- eliminate final exp in bls12-381 optimized
- eliminate final exp in bls12-377
- optimize final exp bls12-377
- **bls12-381:** use cyclotomic group in finel exp check
- **bls12-381:** eliminate finalexp ~naively
- **bls12-381:** revisit tower extension
- **bn254:** eliminate finalexp as per eprint 2024/640
- **bn254:** use cyclotomic group in final exp check
- **bn254:** revisit tower extension
- **bn254:** save one mul in finalExp check
- **bn254:** optimize addchain for exp by 6u+2
- **bn254:** eliminate finalexp in precompile
- **bw6:** optimize specialized Montgomery-6 mul
- **bw6:** sparse mul by lines
- **bw6:** save 2 subs in fp6 sq
- **bw6:** optimize mulby023
- **bw6:** mulby02345
- **bw6:** save some subs in Fp6 square
- **bw6:** Square uses Karatsuba over Chung-Hasan instead of TC6
- **bw6:** revisit tower extension
- **bw6:** save some adds in specialized mul e6
- **bw6:** use hint to divide by 362880 in Toom-6
- **bw6:** optimize Montgomery-6 mul
- **bw6:** optimize pairing with new tower
- **bw6:** use Karabina12345 instead of GS for small sizes too
- **bw6:** toom-cook-3x for Fp3 mul
- **bw6-761:** eliminate finalexp
- **bw6-761:** use Karabina even for 1 square
- **bw6-761:** push ML to cyclo-group before FE elimination
### Refactor
- clean code
- revert to old line computation and adjust gnark-crypto instead
- move utils from std/ to internal
- apply review suggestions
- apply review suggestions
- separate fixed circuits used in zkevm ([#1217](https://github.com/Consensys/gnark/issues/1217))
- clean code
- clean code
- move limb composition to package
- use single implementation
- clean code
- removes todods ([#1111](https://github.com/Consensys/gnark/issues/1111))
- **bls12-377:** karabina decompression
- **bn254:** clean FE elimination code
- **bn254:** add some comments
- **bw6:** remove dead code
- **bw6:** remove benchmark
- **bw6:** remove benchmark
- **bw6:** apply review suggestion
### Release
- v0.11.0 ([#1272](https://github.com/Consensys/gnark/issues/1272))
### Style
- fixed wrong EcMul comment
- fixed comment
- fixed comment
- fixed typos
- added comment
- removed unused variable
- constant for fixed size proof
- SHA2 constant to replace 0x2
- cleaner computation nb BSB commitments
- renamed H commitments constants
- reuse variable
- removed redundant if statement
- lagrangeOne -> lagrangeZero
- verify_opening_linearised_polynomial -> compute_opening_linearised_polynomial
- divideByXMinusOne could -> divideByZH
- fixed typo
- clean code
- remove old todos ([#1106](https://github.com/Consensys/gnark/issues/1106))
### Test
- update stats
- update stats
- added non regression test for api.Select bool cond
- add issue 1153 repro
- update stats
- check errors in test circuit ([#1140](https://github.com/Consensys/gnark/issues/1140))
- update stats
- update stats
- update stats
- update stats
- add PLONK test for public input mapping ([#1123](https://github.com/Consensys/gnark/issues/1123))
- update stats
### Wip
- toom-cook-3x

### Pull Requests
- Merge pull request [#1254](https://github.com/Consensys/gnark/issues/1254) from Consensys/perf/ML
- Merge pull request [#1258](https://github.com/Consensys/gnark/issues/1258) from Consensys/refactor/limb-composition
- Merge pull request [#1251](https://github.com/Consensys/gnark/issues/1251) from Consensys/build/bump-gnarkcrypto-vsn
- Merge pull request [#1247](https://github.com/Consensys/gnark/issues/1247) from Consensys/fix/issue1246
- Merge pull request [#1207](https://github.com/Consensys/gnark/issues/1207) from Consensys/perf/eliminate-finalExp-bls
- Merge pull request [#1214](https://github.com/Consensys/gnark/issues/1214) from Consensys/fix/BN254-finalExp
- Merge pull request [#1196](https://github.com/Consensys/gnark/issues/1196) from ThomasPiellard/audit/final-commit-fixes
- Merge pull request [#1143](https://github.com/Consensys/gnark/issues/1143) from Consensys/perf/eliminate-finalExp
- Merge pull request [#1187](https://github.com/Consensys/gnark/issues/1187) from Consensys/fix/groth16-solidity-templates
- Merge pull request [#1155](https://github.com/Consensys/gnark/issues/1155) from Consensys/perf/eliminate-finalExp-bw6761
- Merge pull request [#1173](https://github.com/Consensys/gnark/issues/1173) from Consensys/perf/eliminate-finalExp-bls12381
- Merge pull request [#11](https://github.com/Consensys/gnark/issues/11) from ThomasPiellard/audit/M-04
- Merge pull request [#10](https://github.com/Consensys/gnark/issues/10) from ThomasPiellard/audit/L-02
- Merge pull request [#14](https://github.com/Consensys/gnark/issues/14) from ThomasPiellard/audit/H-01
- Merge pull request [#13](https://github.com/Consensys/gnark/issues/13) from ThomasPiellard/audit/N-05
- Merge pull request [#2](https://github.com/Consensys/gnark/issues/2) from ThomasPiellard/audit/N-01
- Merge pull request [#5](https://github.com/Consensys/gnark/issues/5) from ThomasPiellard/audit/L-08
- Merge pull request [#7](https://github.com/Consensys/gnark/issues/7) from ThomasPiellard/audit/L-06
- Merge pull request [#6](https://github.com/Consensys/gnark/issues/6) from ThomasPiellard/audit/L-07
- Merge pull request [#8](https://github.com/Consensys/gnark/issues/8) from ThomasPiellard/audit/L-05
- Merge pull request [#4](https://github.com/Consensys/gnark/issues/4) from ThomasPiellard/audit/N-03
- Merge pull request [#3](https://github.com/Consensys/gnark/issues/3) from ThomasPiellard/audit/N-02
- Merge pull request [#1](https://github.com/Consensys/gnark/issues/1) from ThomasPiellard/audit/N-04
- Merge pull request [#9](https://github.com/Consensys/gnark/issues/9) from ThomasPiellard/audit/L-04
- Merge pull request [#12](https://github.com/Consensys/gnark/issues/12) from ThomasPiellard/audit/L-03
- Merge pull request [#1165](https://github.com/Consensys/gnark/issues/1165) from Consensys/fix/partition-bounds
- Merge pull request [#1138](https://github.com/Consensys/gnark/issues/1138) from Consensys/feat/option_solidity
- Merge pull request [#1131](https://github.com/Consensys/gnark/issues/1131) from Consensys/perf/toom3-r1cs
- Merge pull request [#1126](https://github.com/Consensys/gnark/issues/1126) from Consensys/perf/direct-extensions
- Merge pull request [#1110](https://github.com/Consensys/gnark/issues/1110) from Consensys/perf/field-extensions
- Merge pull request [#1113](https://github.com/Consensys/gnark/issues/1113) from Consensys/docs/signatures
<a name="v0.10.0"></a>
## [v0.10.0] - 2024-04-22
### Bench
- large
- don't inflate the decompressed size too much
- proving works
- 26KB
- huffman decoding
- awful
### Bls12377
- faster e6 MulBy01
- test e6 MulBy01
- test mul 01 by 01
### Bls12381
- faster e6 MulBy01
### Bls24315
- faster e12 MulBy01
- test e12 MulBy01
### Bn254
- faster e6 MulBy01
- test mul 01 by 01
### Build
- update compress to v0.2.3 ([#1032](https://github.com/Consensys/gnark/issues/1032))
- get gopter
### Bw6761
- faster e3 MulBy01
- test mul 01 by 01
### CI
- don't run redundant release checks
- run more tests when doing PR
- remove github bot
- make macOS and win do minimal tests only
### Chore
- remove prints and all huffman code
- comments/cleanup for lzss compression
- update stats
- remove committed profiles ([#1053](https://github.com/Consensys/gnark/issues/1053))
- adapt changes from native Fiat-Shamir transcript ([#974](https://github.com/Consensys/gnark/issues/974))
- go.sum
- update stats
- remove unused line eval init
- use type alias
- inline computation
- fix linter errors
- merge rough edges
- update gnark-crypto
- update gnark-crypto
- gitignore
- update stats
- remove unused line init
- remove unused code
- set word size to 1
- minor changes to benchmark
- update gnark-crypto to latest
- uncrowd the pr a bit more
- cleanup documentation examples
- avoid nonnative dereferences ([#861](https://github.com/Consensys/gnark/issues/861))
- better logging, remove code from data folder
- update gnark-crypto to latest
- clean up comments and prints
- avoid dereferencing into existing Elements
- remove prints
- clean up test cases
- improved analytics
- **deps:** bump golang.org/x/crypto from 0.12.0 to 0.17.0 ([#973](https://github.com/Consensys/gnark/issues/973))
### Clean
- rm solidity.tmpl
### Docs
- clean comments
- add hint definition for native inputs
- method doc native output
- add comments
- add subgroup check to doc_test.go
- describe that hint inputs and outputs are init-ed ([#1003](https://github.com/Consensys/gnark/issues/1003))
- clean comments
- update algebra documentations
- GLV hint
- define that addition is now unsafe
- add method documentation
- BestCompression vs BestSnarkDecomposition
- add docs to NewR1CS and NewSparseR1CS in system.go [#985](https://github.com/Consensys/gnark/issues/985)
### FEAT
- Add experimental support for Icicle GPU acceleration behind build tag ([#844](https://github.com/Consensys/gnark/issues/844))
### Feat
- register hints in std/ also when have no circuit
- change sign in comment
- modified comment
- expmod with variable modulus ([#1090](https://github.com/Consensys/gnark/issues/1090))
- moved claimed values of linearised polynomial out of the proof
- re enable test bs12->bw6
- code gen
- implement glv for all curves
- code gen
- replaced precompiles opcode with constants
- addition of precompiles as constants
- used  to compute offsets in state
- used  in template for proof offsetss
- Groth16 Solidity contract with commitments ([#1063](https://github.com/Consensys/gnark/issues/1063))
- add secp256k1 curve default initializer ([#1086](https://github.com/Consensys/gnark/issues/1086))
- add range check selector retrieval ([#1066](https://github.com/Consensys/gnark/issues/1066))
- add MulNoReduce and Sum methods in field emulation ([#1072](https://github.com/Consensys/gnark/issues/1072))
- add non-native hint with native inputs
- add non-native hint with native output
- add non-native hint with native output
- non-native sumcheck verifier ([#1042](https://github.com/Consensys/gnark/issues/1042))
- verify commitments in groth16 recursion verifier ([#1057](https://github.com/Consensys/gnark/issues/1057))
- add option for enforcing number of goroutines for the solver ([#1052](https://github.com/Consensys/gnark/issues/1052))
- stabilize anonymous hint function names ([#1054](https://github.com/Consensys/gnark/issues/1054))
- modified algebraic relation
- G2 membership bls12-377
- G1 membership bls12-377
- curve/twist membership bls12-377
- subgroup G1/G2 membership BW6-761
- add PLONK in-circuit verifier ([#880](https://github.com/Consensys/gnark/issues/880))
- pairing precompile error handled
- code gen
- clean MarshalSolidity
- fix unmarshalling solidity
- use n-bit mux for switching PLONK verification keys ([#1017](https://github.com/Consensys/gnark/issues/1017))
- code gen plonk upgrade
- adds plonk.SRSSize helper method ([#1012](https://github.com/Consensys/gnark/issues/1012))
- different PLONK circuit verification ([#1010](https://github.com/Consensys/gnark/issues/1010))
- renaming zhZeta
- opening of h0, h1, h2 ok
- using batch inversion
- remove foldedHDigest
- add quotient to the linearised polynomial
- multiply s1, s2 by alpha
- some todos and dead code ([#993](https://github.com/Consensys/gnark/issues/993))
- add WithUseSafe option
- update compress version; failing test (resolved) ([#979](https://github.com/Consensys/gnark/issues/979))
- regenerate internal/stats
- updated comment in fold_state
- groth16 solidity use calldatacopy for commitments ([#1097](https://github.com/Consensys/gnark/issues/1097))
- plonk verifier options ([#1028](https://github.com/Consensys/gnark/issues/1028))
- if we don't compress we don't need the dict ([#929](https://github.com/Consensys/gnark/issues/929))
- exit when an error is encountered
- exit when condition is not filled
- make registries for gkr thread safe ([#920](https://github.com/Consensys/gnark/issues/920))
- cache lookup blueprint entries in solving phase ([#915](https://github.com/Consensys/gnark/issues/915))
- batched KZG ([#908](https://github.com/Consensys/gnark/issues/908))
- forceDivisibleBy
- compile large circuit outside tests
- Fiat-Shamir transcript using a short hash ([#900](https://github.com/Consensys/gnark/issues/900))
- snark decomp done, not yet tested
- snark decompressor, all but eof logic done
- offset, length and bytes tables
- read lengths!
- new stream
- add multi symbol
- started v2
- r/w num, (un)marshal for stream
- implement bit mode for short hash
- use bitlength from parameters
- bit-level alignment of compressed
- marshalling G1 and Scalar on emulated curves, following gnark-crypto
- add short-hash wrappers for recursion ([#884](https://github.com/Consensys/gnark/issues/884))
- native marshal (bls12, 24) consistent with gnark-crypto
- marshal G1 ok on non emulated curves (bls12, 24)
- pack/unpack functions
- add fixed pairing for bw6-761
- allow custom hash function in backends ([#873](https://github.com/Consensys/gnark/issues/873))
- more analytics
- some analytics
- add bw6 kzg
- add bw6 emulated ScalarMul and ScalarMulBase
- api.IsNonZero
- huffman Decode
- add bw6 fields
- bzip2 (bzip would be better)
- some experiments with huffman coding
- preliminary snark decompressor impl
- basic i/o funcs
- small tests work with indeterminate length
- basic lzss decompressor
- new data set and huffman estimations
- IsByteZero works
- add naive bw6 miller loop
- add bw6 final exp
- **2-chain:** MSM of size 2
- **emulated bw6 pairing:** optimal tate version working
- **sw_bls12377:** Add DoubleFixedQPairing
- **sw_bls24315:** Add DoubleFixedQPairing
### Fix
- test final exp without gnark-crypto hack
- JointScalarMulBase without GLV (for ecdsa package)
- fixed type
- folded MSM scalar decomposition
- emulated hint tests ([#1083](https://github.com/Consensys/gnark/issues/1083))
- edge cases in SM and JSM were inverted + comments
- incorrect parameter
- several typos in the documentation ([#943](https://github.com/Consensys/gnark/issues/943))
- remove duplicate error check
- scs add/mul when recorded constraint is 0
- organize std packages hints registrations ([#1043](https://github.com/Consensys/gnark/issues/1043))
- another occurence of G1 in SRS ([#1036](https://github.com/Consensys/gnark/issues/1036))
- use G1 generator from SRS ([#1035](https://github.com/Consensys/gnark/issues/1035))
- verifier works
- fixed size slice
- fixed formula in comments
- AssertOnG1 BLS12-377
- use subtraction with reduce in AssertIsEqual ([#1026](https://github.com/Consensys/gnark/issues/1026))
- plonk recursion without commitment
- fixed compute_gamma_kzg
- fixed offset opening at zeta-omega
- Decompressor to return -1 when output doesn't fit ([#1022](https://github.com/Consensys/gnark/issues/1022))
- fixed typo
- fixed verify_opening_linearised_polynomial
- fixed proof size
- fixed generator
- fixed comment derive alpha
- fixed MarshalSolidity
- assign baseChallenge correctly while verifying gkr solution ([#1020](https://github.com/Consensys/gnark/issues/1020))
- verifier ok
- add Placeholder for vk with fixed lines
- remove shorthash override for same field ([#1008](https://github.com/Consensys/gnark/issues/1008))
- bw6 field emulation
- works on small test case
- "last byte" bug
- typo
- typo
- typo
- typo
- rename ScalarMulGeneric to scalarMulGeneric in tests
- swith points order in JointScalarMulBase
- init lines before assigning
- use eigenvalue and thirdroot pointers
- stats
- use Generic instead of GLV for ECMUL to handle edge-cases
- remove debug panic from previous commit
- ensure plonk verify check witness length ([#952](https://github.com/Consensys/gnark/issues/952))
- update stats
- some bugs
- groth16 verifier
- ReadIntoStream
- bn254 -> {{ toLower .Curve }}
- test Expt remaned to ExpX0
- compression works on the first 300b of calldata
- missing wait on channel in plonk prover ([#926](https://github.com/Consensys/gnark/issues/926))
- minor test issues
- bad merge. bad git!
- use platform independent method for counting new multiplication overflow from result limb count ([#916](https://github.com/Consensys/gnark/issues/916))
- actually remove the go generate line
- comment out go generate in suffixarray
- groth16 recursion
- non-native arithmetic autoreduction for division, inversion and sqrt ([#870](https://github.com/Consensys/gnark/issues/870))
- readIntoStream bug
- simple table lookup works
- test with backrefs
- some minor bugs
- use gt(arg, R_MOD_MINUS_ONE)
- small packing test works
- fuzzer bug
- 18b offset - ave
- snark errors
- DoublePairFixedQ with different inputs
- test MulBy014 and remove old MulBy034
- make tests pass
- update latest.stats
- make builder private again
- 1B addresses seem to work
- trailing backref bug
- plonk.SRSSize takes constraint.ConstraintSystem as input, not constraint.System
- works on 2c2964. performance awful
- remove outdated test
- read bugs
- ineffectual assignment to err
- failed
- presumption of long negative space of zeros
- two symbols test
- use M-twist (014) for emulated BW6 pairing
- RLE bug
- bug with negative indexes
- bug with lone 0 in high indexes
- all tests pass, except for 3c2943: too slow
- all zeros tests pass
- write to the output table
- all "simple" tests pass
- zerosAfterNonzero pass
- can handle two consecutive backrefs
- works on 3c2943 with symb 0
- **2-chain:** last iteration of MSM of size 2
- **2-chains:** varScalarMulG1 edge cases
- **2-chains:** constScalarMulG1 edge cases
- **2-chains:** ScalarMulG2 edge cases
- **bw6:** fix Expt test
- **bw6:** DecompressKarabina edge cases
- **linter:** ineffectual assignment
### Perf
- add lazy match look ahead 1
- adjustement
- use logderiv map
- prefer actual backrefs for RLE; better but still bad
- replace dummy G by (0,1) in ScalarMul
- dfa search; actually makes things worse
- ite -> api.Select
- naive emulated bw6 pairing working
- huffman improvement
- use less outputs (joint)
- use less outputs from hints
- optimize hint computation with corresponding output field
- do not use multiplication for subscalar check
- simplify the glv decomposition hint
- emulated equality assertion ([#1064](https://github.com/Consensys/gnark/issues/1064))
- minor optims for plonk verifier
- save some negs in ec arithmetic
- big optim for JointScalarMulBase
- reduce 1 lookup per backref
- a few petty opts
- do not store zero mul constraint
- glv-base msm for bw6 (dirty)
- a few little opts
- custom constraint for inIDelta
- custom constraint for advancing inI
- custom constraint for copying
- more small optim to jointScalarMulGLV
- more optim to jointScalarMulGLV
- "start at"
- kzg gadget using DoubleFixedQPairing
- make compress way faster
- plonk verifier
- binary search of longest backref
- small optim replacing Sub by Add
- one binary search only
- fold H before big MSM
- even better lookahead for lazy deflate
- non-native multilinear polynomial evaluation ([#1087](https://github.com/Consensys/gnark/issues/1087))
- groth16 uses precomputed lines for all curves
- mark the result of `builder.IsZero` as boolean to save constraints when used in future ([#977](https://github.com/Consensys/gnark/issues/977))
- smaller backrefs
- faster compression by reducing search space
- avoid some additions in jointScalarMulGLV
- bw6 glv with smaller loop
- small optim in jointScalarMulGLV
- save 4 scs in lookup2 api
- big optim for JointScalarMul and MSM
- isolate trival add/mul by 0/1 in plonk verifier and kzg
- rewrite Hayashida et al. hard part
- non-native modular multiplication ([#749](https://github.com/Consensys/gnark/issues/749))
- implement unified addition in 2-chains
- mutualize bit decomposition when same scalar used is ScalarMul
- reduce mem alloc when init suffix array
- use JointScalarMul in plonk recursion
- bounded scalar multiplication ([#934](https://github.com/Consensys/gnark/issues/934))
- use G2 precomputed lines for Miller loop ([#930](https://github.com/Consensys/gnark/issues/930))
- replace sort.Search
- don't use 0 as symbol delimiter
- lookup blueprint compile time improvement ([#899](https://github.com/Consensys/gnark/issues/899))
- use new fixed-arg pairing in kzg
- use new fixed-arg pairing in kzg (WIP)
- **2-chain:** handle edge cases in varScalarMul
- **2-chain:** optimize varScalarMul
- **2-chain:** small scs optim to doubleAndAdd
- **2-chain:** save 1 add in varScalarMul in G2
- **2-chain:** optimize folded MSM
- **2-chains:** small optim in varScalarMul and JointScalarMul
- **2-chains:** apply fast path for constScalarMul edge cases
- **2-chains:** save an addition per iteration in ScalarMul
- **bls12-377:** implement a variant of Karabina cyclo square
- **bls24:** optimize varScalarMul
- **bn254:** mul lines 2-by-2 in fixed-arg pairing for KZG when bit=0
- **bw6:** manually reducing E12 at some places yields better perf
- **bw6:** lines-by-acc mul gives better results than line-by-line mul
- **bw6:** implement a variant of Karabina cyclo square
- **bw6:** use optimized DoublePairFixedQ in kzg
- **bw6:** optimize final exponentiation
- **bw6:** use more efficient addchains
- **bw6-761:** save 1 ScalarMul in subgroup membership tests
- **ecdsa:** use GLV in JointScalarMulBase
- **ecmul:** use GLV with safe handling of edge cases in EVM ecmul
- **ecrecover:** save 1 MulMod in ecrecover
- **emulated:** huge optim scalarMulGLV
- **emulated:** ScalarMulBase with GLV is better
- **emulated:** save 1 add in scalarMulGLV
- **emulated:** optimize GLV hint
- **emulated:** big optim jointScalarMulGLV
- **emulated:** big optim scalarMulGLV
- **kzg:** remove folding and shrinked scalars options in MSM
- **kzg:** use MSM instead of two SM in CheckOpeningProof
- **plonkVerif:** manually reduce wrong-field elements here and there
- **sw_emulated:** optimize jointScalarMulGeneric
### Refac
- compression modes
- remove useless functions
### Refactor
- some refactoring
- address PR review
- compile 600KB
- use safe version in precompile
- merge safe implementation
- ScalarMulSafe and ScalarMul
- work on pointer values
- use existing modulus value
- use emulated pointer to avoid init when no GLV
- make newG2Aff private
- use line evaluation references for avoiding copies
- hardcode glv values instead of exporting from gnark-crypto
- remove SameScalarMul from interface
- plonk.Setup takes kzg srs in canonical and lagrange form ([#953](https://github.com/Consensys/gnark/issues/953))
- reconcile with master
- rename precompute to compute when done in-circuit
- clean comments
- algebra interface and pairing
- use external compressor repo ([#942](https://github.com/Consensys/gnark/issues/942))
- consolidate emulated bw6-761 pairing with other curves
- consolidate bw6-761 tower + fix GT exp tests
- apply PR review suggestions
- simplify hint overloading for api.Commit ([#919](https://github.com/Consensys/gnark/issues/919))
- re-introduce points in KZG verification key
- kill backend.PLONK_FRI ([#1075](https://github.com/Consensys/gnark/issues/1075))
- use variable point in tests for precomputeLines
- lzssv2 -> lzss
- kill backend.PLONK_FRI
- use lineEvaluation type instead of field elements
- use emulated.FieldParams as type parameter to generic Curve and Pairing ([#901](https://github.com/Consensys/gnark/issues/901))
- bls24 also uses size 4 lines
- lots of cleanup. one failing test remaining
- keep one version + multi-pairing
- get rid of lzssv1
- no need for outAt
- packing as stream feature
- simplify packing
- do not use internal objects
- massive simplification of lzssv1 compression
- consolidate pairing implementations
- remove log heads
- cleaning tests
- **2-chain:** precomputed lines in pairing + KZG + plonk verifier
- **2-chain bls24:** precomputed lines in pairing+KZG+plonk verifier
- **2-chains:** use gnark-crytpo fixed-arg pairing
- **2-chains:** remove Jacobian coordiantes code
- **bls12-381:** precomputed lines embedded in G2Affine struct
- **bn254:** precomputed lines embedded in G2Affine struct
- **bw6:** remove some unnecessary computations
- **bw6 pairing:** use MillerLoopOptAte in gnark-crypto for test
- **bw6-761:** use revisited Ate pairing instead of Tate
- **emulated:** use gnark-crytpo fixed-arg pairing
- **kzg:** lazy precomputation of lines
### Revert
- kill IsNonZero
- map.keys/values to be private as before
- uncrowd the pr
- remove TestCompressWithContext
- strange uppercase
- dfa search was counterproductive
### Style
- code cleaning
- code cleaning
- costmetics
- remove prints
- clean and document the code
- remove redundant checks
### Test
- decompression works; must go about packing differently
- plonk verifier with precomputed lines
- add tests for all types of hints
- update stats
- add regression test for zero mul duplicate
- compress_tests pass
- keep test curve
- pack
- bypassing decompression works
- updates fuzz test with new API
- fuzz
- actual calldata
- 253-254-255 fails
- trying to recreate the length bug
- add testdata/ fuzzer dir
- average batch
- compression roundtrip passes w merged stream utils
- marshal test
- add scalar marshal+hash
- add g1 marshal + hash test
- add test case for not recording zero mul constraint
- update stats
- add emulated pairing circuits to stats ([#1031](https://github.com/Consensys/gnark/issues/1031))
- reactivate other for cmp
- added BenchmarkAverageBatch
- added average batch test case
- bw6 emulated kzg
- a couple
- failing test for cs loading
- single symbol test
- add huffman estimated gains
- decompression snark
- twoBackrefsAfterNonzero fails
- actually, 257zerosAfterNonzero fails
- twoZerosAfterNonzero
- zeroAfterNonzero added, fixed
- more, failing "8zerosAfterNonzero"
- more state machine tests. failing
- print compressed file size
- some logging
- **bw6:** recude multi-pairing size in tests

### Pull Requests
- Merge pull request [#1044](https://github.com/Consensys/gnark/issues/1044) from Consensys/feat/plonk_update
- Merge pull request [#1085](https://github.com/Consensys/gnark/issues/1085) from Consensys/perf/ec-arithmetic-2chain
- Merge pull request [#1061](https://github.com/Consensys/gnark/issues/1061) from Consensys/perf/ec-arithmetic
- Merge pull request [#1080](https://github.com/Consensys/gnark/issues/1080) from Consensys/feat/emulated-nativehint
- Merge pull request [#1077](https://github.com/Consensys/gnark/issues/1077) from shramee/faster-fq6-01
- Merge pull request [#1076](https://github.com/Consensys/gnark/issues/1076) from shramee/faster-fq6-01-01
- Merge pull request [#1068](https://github.com/Consensys/gnark/issues/1068) from Consensys/fix/recorded-scs
- Merge pull request [#1030](https://github.com/Consensys/gnark/issues/1030) from Consensys/feat/bw6-subgroupcheck
- Merge pull request [#1049](https://github.com/Consensys/gnark/issues/1049) from Consensys/perf/jointScalarMulGeneric
- Merge pull request [#1023](https://github.com/Consensys/gnark/issues/1023) from Consensys/fix/ec-edgecases
- Merge pull request [#1016](https://github.com/Consensys/gnark/issues/1016) from Consensys/perf/g16-circuit
- Merge pull request [#976](https://github.com/Consensys/gnark/issues/976) from Consensys/perf/ecmul-precompile
- Merge pull request [#992](https://github.com/Consensys/gnark/issues/992) from GoodDaisy/master
- Merge pull request [#975](https://github.com/Consensys/gnark/issues/975) from Consensys/perf/ecdsa
- Merge pull request [#949](https://github.com/Consensys/gnark/issues/949) from Consensys/perf/plonk-verifier
- Merge pull request [#928](https://github.com/Consensys/gnark/issues/928) from Consensys/feat/plonk_exit_if_error
- Merge pull request [#933](https://github.com/Consensys/gnark/issues/933) from Consensys/perf/karabina-cycloSq
- Merge pull request [#931](https://github.com/Consensys/gnark/issues/931) from Consensys/perf/bw6-finalExp
- Merge pull request [#924](https://github.com/Consensys/gnark/issues/924) from Consensys/feat/bypass-compression
- Merge pull request [#891](https://github.com/Consensys/gnark/issues/891) from Consensys/feat/marshal_g1_scalar
- Merge pull request [#889](https://github.com/Consensys/gnark/issues/889) from secure12/master
- Merge pull request [#876](https://github.com/Consensys/gnark/issues/876) from Consensys/feat/bw6761-fixed-pairing
- Merge pull request [#878](https://github.com/Consensys/gnark/issues/878) from Consensys/chore/example-cleanup
- Merge pull request [#868](https://github.com/Consensys/gnark/issues/868) from Consensys/fix/decompressKarabina
- Merge pull request [#866](https://github.com/Consensys/gnark/issues/866) from Consensys/feat/bw6761-kzg
- Merge pull request [#846](https://github.com/Consensys/gnark/issues/846) from Consensys/feat/bw6761-pairing
<a name="v0.9.1"></a>
## [v0.9.1] - 2023-10-16
### CI
- update mod download tpl for prettier errors
- remove gotestfmt for push to master workflow
- new attempt to fix push to master workflow
- grmpf
- use runner.os
- fix ubuntu ref
- fix push workflow
- fix push workflow
### Chore
- go.mod tidy
- update import paths
- remove excessive comment
### Docs
- add example docs
- add example docs
- add package documentation
- add package documentation
### Feat
- add BLS12-381 and BLS24-315 support to Groth16 gadget
- add one more type parameter for witness initialisation
- add BLS12-381 and BLS24-315 support to KZG gadget
- add Curve and Pairing compatiblity for BLS24-315
- add placeholder generating functions
- add default pairing and curve getter
- add witness assignment function
- add helper methods to native pairing
- add generic Groth16 implementation
- add MSM and GT equality to generic interfaces
- add generic KZG polynomial commitment verification
- add generic Curve and Pairing interfaces
### Fix
- cast bls12377 GT element coords to bw6 fr
- fixed fold_state
### Perf
- a special case for mulacc ([#859](https://github.com/Consensys/gnark/issues/859))
### Refactor
- remove typed KZG and Groth16 verifiers
- rename KZG tests
- use only KZG VK part
- implement fully generic kzg verifier
- use name type parameter types
- add Scalar type alias
- fix types
- implement generic pairing and curve for bls12377
- add Add to emulated SW
### Test
- rename subtests
- add ValueOf tests
- full generic groth16 verifier
- implement inner circuit without commitment
- implement recursion test
- add generic groth16 test (broken)
- add KZG test for BLS12377
- update version tag ([#841](https://github.com/Consensys/gnark/issues/841))

### Pull Requests
- Merge pull request [#840](https://github.com/Consensys/gnark/issues/840) from Consensys/refactor/generic-kzg
- Merge pull request [#820](https://github.com/Consensys/gnark/issues/820) from Consensys/fix/fold_state
<a name="v0.9.0"></a>
## [v0.9.0] - 2023-09-19
### Build
- fix linter warning
- update PR template and CI actions
- generify bsb22 comm fs move
### CI
- cosmetic change
- remove ubuntu specifics from windows / macOS path
- adjust test on non-ubuntu target
- avoid running std/ test on macOS CI
### Feat
- add bounded comparator functions ([#530](https://github.com/Consensys/gnark/issues/530))
- add sha3 primitive ([#817](https://github.com/Consensys/gnark/issues/817))
### Fix
- assert that the binary decomposition of a variable is less than the modulus ([#835](https://github.com/Consensys/gnark/issues/835))
- remove panic when iterating constraints
- don't bind bsb22 comm to gamma
- move bsb22 comm fs in plonk prover
- fs bsb22 commitment fs right before needed
- plonk must commit to Qcp
### Perf
- improve plonk prover memory footprint ([#815](https://github.com/Consensys/gnark/issues/815))
### Refactor
- **pairing:** remove bls24 bench + remove bn254 duplicate line

### Pull Requests
- Merge pull request [#816](https://github.com/Consensys/gnark/issues/816) from Consensys/perf/pairing-neg
- Merge pull request [#812](https://github.com/Consensys/gnark/issues/812) from Consensys/fix/plonk-bsb-challenge
<a name="v0.9.0-alpha"></a>
## [v0.9.0-alpha] - 2023-08-18
### Bench
- gkr inefficient
- merkle tree
### Build
- update direct dependencies
- go gen
- generify the changes
- generify bn254 changes
- generify
- some generification and remove commented code
- generify plonk refactor
- generify commitment hashing
- generify batch verification
- generify serialization fix
- merge named hint PR
- generify some
- remove debugging modifications
- generify bn254 changes
- generify bn254 changes
- update gnark-crypto dependency
- update gnark-crypto dep
- go generate
- update ci script
- update stats
- go get gnark-crypto[@develop](https://github.com/develop)
- generify hashing pi2
- generify public var fix
- generify verifier changes
- generify prover changes
- generify setup changes
- go generate
- generify verifier changes
- generify prover changes
- generify setup changes
- generify constraint changes
- generify mpcsetup for all curves
- upgraded github.com/stretchr/testify v1.8.1 => v1.8.2
- gnark-crypto[@develop](https://github.com/develop)
- generify
- generify bn254/gkr changes
- reran go generate
- make linter happy
### CI
- allow weak rng in marshaling tests
- ensure linter runs on generated files + adjustements ([#677](https://github.com/Consensys/gnark/issues/677))
### Chore
- update gnark-crypto dependency ([#790](https://github.com/Consensys/gnark/issues/790))
- make staticcheck happy
- merge changes
- more accurate field name, remove some dead code
- rm deadcd, improve verifier mem, some docs
- document hollow, remove in-house search
- clean up tests
- delete unnecessary test cases
- go get gnark-crypto[@develop](https://github.com/develop)
- point to gnark-crypto[@develop](https://github.com/develop)
- git ignore go workspace ([#635](https://github.com/Consensys/gnark/issues/635))
- remove debug printing code
- remove training wheels
- update gnark-crypto dependency for exported towers
- remove heavy profiling and compiling
- some efforts from before christmas break
### Clean
- removed dead code + double comments
- removed dead code
- even more deadcode
- removed more dead code
- removed dead code
### Dep
- newer gnark-crypto
- gnark-crypto
### Docs
- clarify some comments
- fix select description in field emulation
- GKR API
- comment fixed pairing
- point at infinity
- better names and a link to hackMd
- explain the optionality of f in AddSolverHint
- typo
- subgroup check in doc-example
- comment about AddUnified
- typo
- godoc linking
- explain that r1cs.NewBuilder returns frontend.Committer
- update pr template
- make long equation codeblock
- correct comment
- comment about subgroup membership
- comment about subgroup membership
- update version in README.md
- make href in godoc
- correct `WithNbDigits` description ([#522](https://github.com/Consensys/gnark/issues/522))
- add documentation to std/algebra packages
- implement lookup2 comment
- fix docs, make links
- make documentation of weierstrass/ better
- add comments to sw_emulated
- add package documentation and example
- **fixed-emulated-pairing:** add some comments
- explain commitment constraint
- explain committed constraint
### Feat
- hint name options
- use AssertIsOnG2 for ECPAIR precompile + comments
- calldatacopy in compute_gamma_kzg
- calldata ok
- compute_commitment_linearised_polynomial calldata ok
- fold_h calldata ok
- verify_quotient_poly_eval_at_zeta calldata ok
- pi contribution in calldata ok
- sum_pi_wo_commit calldata ok
- derive challenges calldata ok
- sanity checks in calldata Ok
- put function calls at the beginning of Verify
- verifier in one assembly block
- zeta to the n minus 1 extracted from compute_pi
- one single assembly block ok
- check_input_size in main block
- challenges derivation in the main block
- compute_pi in main assembly block ok
- compute_pi assembly ok
- hash_fr in assembly + removed Utils
- staticcall fails -> revert immediately instead of updated state_success
- zeta_power_n_minus_one save and reused in compute_pi
- [PLONK_AUDIT_4-15] fixes 757
- status of staticcalls are checked, fixes [#753](https://github.com/Consensys/gnark/issues/753)
- added plonk.ProvingKey WriteRawTo and UnsafeReadFrom ([#746](https://github.com/Consensys/gnark/issues/746))
- [PLONK_AUDIT_4-8] fixes [#743](https://github.com/Consensys/gnark/issues/743)
- [PLONK_AUDIT_4-4] fixes [#741](https://github.com/Consensys/gnark/issues/741)
- restored comments
- [PLONK_AUDIT_4-9] fixes 738
- "named gate"
- [PLONK_AUDIT_4-11] fixes [#735](https://github.com/Consensys/gnark/issues/735)
- gkr-api for plonk
- update plonk solidity template ([#729](https://github.com/Consensys/gnark/issues/729))
- added dummy setup part for g16 multi commit ([#725](https://github.com/Consensys/gnark/issues/725))
- implement add-only Joye scalarMul
- groth16 commitmetInfo experiments
- in-place-ish DivideByThresholdOrList
- add sha2 primitive ([#689](https://github.com/Consensys/gnark/issues/689))
- commitment info in groth16.vk[bn254] serialization
- commitment placeholder -> randomness
- lazy line initialising
- define precomputed lines only if initalising
- filterHeap for unsorted lists
- groth16 multicommit setup bn254, hopefully
- batch pedersen poks
- implement NIST P-256 and P-384 curves ([#697](https://github.com/Consensys/gnark/issues/697))
- differentiate ecrecover with strict and lax check for s ([#656](https://github.com/Consensys/gnark/issues/656))
- no commitments -> vanilla groth16
- prover with no commitment act like vanilla groth16
- reflect pedersen changes in bn254
- emulated pairing 2-by-2 fixed circuit for EVM
- verifier template ok
- prover template ok
- modification opening order kzg bn254
- plonk provingkey marshaling with muticommits
- introduce constraint blueprints. improve memory usage, enables custom gates and group of constraints ([#641](https://github.com/Consensys/gnark/issues/641))
- sr1cs multicommits
- compilation side - plonk multicommits
- described zpnmo parameter + reuse zpnmo in compute_alpha_square_lagrange_0 (forgot to push it)
- use state instead of mload(0x40)
- bn254 plonk multicommit backend
- log-derivative vector lookups ([#620](https://github.com/Consensys/gnark/issues/620))
- multi-commits in constraint system data structures
- add modular square root in field emulation ([#623](https://github.com/Consensys/gnark/issues/623))
- plonkVk.WriteRawTo
- serialize minimal commitmentinfo with plonk vk
- use Brier-Joye unified add for evm ecadd
- experiments with solving
- development done for bn254. to test and generify
- "generic" top sort
- simple compilation test passes
- support more operations
- codegen
- yet more codegen
- add n to 1 MUX and MAP ([#475](https://github.com/Consensys/gnark/issues/475))
- add EVM precompiles ([#488](https://github.com/Consensys/gnark/issues/488))
- add PairingCheck function
- store api in pairing structs
- add simple key value storage
- embed key-value storage in R1CS and SCS
- embed key-value storage in test engine
- add gadget for enabling multiple commitments in-circuit ([#562](https://github.com/Consensys/gnark/issues/562))
- isZero in field emulation ([#609](https://github.com/Consensys/gnark/issues/609))
- range checks using log derivative, fixes [#581](https://github.com/Consensys/gnark/issues/581) ([#583](https://github.com/Consensys/gnark/issues/583))
- implement commit for test engine
- set default compression threshold ([#599](https://github.com/Consensys/gnark/issues/599))
- add IsOnCurve to sw_bn254/g2
- add IsOnCurve to sw_emulated
- add bls12-381 to std/algebra/emulated
- blind commitment
- add a partition selector ([#486](https://github.com/Consensys/gnark/issues/486))
- reintroduce hints for field emulation ([#547](https://github.com/Consensys/gnark/issues/547))
- some bsb22 proving in plonk
- range check gadget ([#472](https://github.com/Consensys/gnark/issues/472))
- plonk frontend filter common cases of duplicate constraints ([#539](https://github.com/Consensys/gnark/issues/539))
- add calling hints to field emulation
- commitment verification - plonk bn254
- gnark/profile now filter frontend private method for clarity and return a tree as txt repr ([#538](https://github.com/Consensys/gnark/issues/538))
- BN254 pairing ([#411](https://github.com/Consensys/gnark/issues/411))
- compute table on init once
- add defer to the Compiler interface ([#483](https://github.com/Consensys/gnark/issues/483))
- compilation, setup and commitment done; proof and verification next
- update gnark version to v0.8.0
- add equality assertion for GT elements
- add BN254 pairing using field emulation
- **fields_bn254:** add IsZero in extensions
- **fields_bn254:** add Select in extensions
- **fields_bn254:** add String helpers
- **pairing:** check points are on curve and twist
- **sw_bls12381:** add AssertIsOnG1 and AssertIsOnG2
- **sw_bls12381:** G1 and G2 membership without hints
- **sw_bn254:** add AssertIsOnG2
- **sw_bn254:** G2 membership without hints
- **sw_bn254:** endomorphism optims for G2 membership
- **sw_emulated:** AddSafe for input points equal or not
- **sw_emulated:** infinity as (0,0) edge-cases in UnifiedAdd
- **sw_emulated:** infinity as (0,0) edge-cases in ScalarMul
- Export multicommit ([#789](https://github.com/Consensys/gnark/issues/789))
### Fix
- use jacobain double for test
- fixed [#761](https://github.com/Consensys/gnark/issues/761)
- fixed kzg G1 srs in template :/
- compute_kzg fixed calldata
- update develop version ([#776](https://github.com/Consensys/gnark/issues/776))
- update circuits stats
- do not accumulate terms with zero coefficient for addition ([#763](https://github.com/Consensys/gnark/issues/763))
- use AddUnified in ECRecover
- create full-length slice for gkr value ([#751](https://github.com/Consensys/gnark/issues/751))
- removed deadcode
- loop counter corrected fixes [#755](https://github.com/Consensys/gnark/issues/755)
- fixed pairing check (wait for 4-5 to check staticcall using dedicated function)
- range checks for quotient + linearised polynomials openigns
- plonk scs serialization issues ([#747](https://github.com/Consensys/gnark/issues/747))
- compute_pi takes the proof only when commit is called
- Verify is public
- fixed visibilities, changed library to contract
- replace hints bn254
- emulated ToBits ([#731](https://github.com/Consensys/gnark/issues/731))
- K -> Z
- nil -> empty slice
- the previous fix
- bn254 multicommit proving keys
- commitmentInfo serialization
- committed commitment folding bug
- groth16 tests pass
- bellman test vk
- make linter happy
- randomize fake commitments
- groth16 works. plonk fuzzer fails
- remove unnecessary import
- test double fixed pairing
- commitment to commitment works
- single commitments work again
- attempt at commitment hint input filtering
- two indep commitments work for bn254
- using loop counter in lambda
- single commits work for bn254
- no commitments case for bn254
- empty commitments vector
- no private committed bug
- groth16 commit verification error handling
- gorth16 commit compile bug
- re uploading solidity template
- removed solidity folder
- remove dead file
- removed non used code
- removed commented code
- fixes [#672](https://github.com/Consensys/gnark/issues/672)
- fixed kzg serialisation on bn254
- init elements in arrays and slices if have init hook ([#695](https://github.com/Consensys/gnark/issues/695))
- PI2 renaming in marshal
- failing vk serialization test
- newNamedHint bug
- one commit works
- claimed quotient
- no commit test passes
- prover no longer errors; unexpected quotient for 2-commit
- Proving key serialization
- proof serialization
- fix race condition when compiling circuits in parallel ([#676](https://github.com/Consensys/gnark/issues/676))
- added missing cbor tags for BlueprintSparseR1CBool
- register commitment func with new name
- HasCommitment -> NbCommitments
- multi-commit unsupported error messages
- in case no commitment
- private -> public
- assert oddity of y coordinate from v instead of high bit ([#655](https://github.com/Consensys/gnark/issues/655))
- companion to pedersen breakup
- field emulation subtract padding compute ([#603](https://github.com/Consensys/gnark/issues/603))
- add (0,0) case to curve membership
- fixed double comments
- fixes [#768](https://github.com/Consensys/gnark/issues/768)
- one omitted change
- finalExp when element is 1 in torus
- restore reference plonk circuit size
- don't set comm to 0; it might be inverted
- filter constants
- use frontend.Committer properly
- plonk.Commit race condition
- remove an ineffectual assign in E6
- update stats
- marshaling tests - plonk
- double blind commitment
- add pi2 to fs - bn254
- bsb22 in plonk with public vars
- match latest backend changes in bw6-761
- minor mistake in setup generification
- make linter happy
- disastrous typo
- subtraction overflow computation bug ([#579](https://github.com/Consensys/gnark/issues/579))
- circuit-efficient Expt
- open qcp commitment
- qcp formats
- computing t(X) requires lagrange coset input
- handle nested Define signature in call stack for profile
- pass canonical version of pi2 to computeLinearizedPolynomial
- use mocked api.Commit also in Windows tests ([#560](https://github.com/Consensys/gnark/issues/560))
- fix [#516](https://github.com/Consensys/gnark/issues/516) compiler detects api.AssertIsDifferent(x,x) with better error ([#552](https://github.com/Consensys/gnark/issues/552))
- do not pass limb width enforcement for consts in AssertIsEqual ([#550](https://github.com/Consensys/gnark/issues/550))
- append solver options to prover options in tests
- fix profile example to not compare expected output with varying line numbers
- allow unreplaced BSB22 commitment hint in solver ([#507](https://github.com/Consensys/gnark/issues/507))
- stable levelbuilder hint mapping ([#533](https://github.com/Consensys/gnark/issues/533))
- initialize new variable if field emulation multiplication check ([#534](https://github.com/Consensys/gnark/issues/534))
- handle stack traces with deferred function ([#521](https://github.com/Consensys/gnark/issues/521))
- update path to algebra/native/twistededwards
- update path to algebra/native
- update path to algebra/native
- use sw_emulated instead of weierstrass
- remove pairing_bn254
- restrict constants in field emulation to width ([#518](https://github.com/Consensys/gnark/issues/518))
- closes [#509](https://github.com/Consensys/gnark/issues/509) api did not handle AssertIsLessOrEqual with constant as first param ([#511](https://github.com/Consensys/gnark/issues/511))
- remove profiling
- used keyed struct fields, silence linter
- scs.MarkBoolean missing return w/ constant ([#491](https://github.com/Consensys/gnark/issues/491))
- allocate new variable in engine.MulAcc ([#482](https://github.com/Consensys/gnark/issues/482))
- update version ([#477](https://github.com/Consensys/gnark/issues/477))
- remove printfs
- witness-related functions no longer return ptrs
- reflect gkr changes in gnark-crypto
- log correction
- avoid overlogging
- dumping error and solver test
- solving bug - bn254
- bn254 mem pool
- a small bug and some new benchmarks
- go mod tidy
- mod tidy
- no defineGkrHints for tinyfield and more
- no gkr for tinyfield
- minor stuff, some code generation
- small mimc test
- race condition
- propagating gkrInfo
- import cycle
- solver works. prover doesn't. possibly deeper gkr issue
- solving works on the simplest example
- inconsistencies re assignments alignment
- more `ToBigIntRegular` => `BigInt`
- **add-only scalarMul:** handle 0-scalar and (0,0) edge-cases
- **ecadd:** add y1+y2=0 edge case
- **sw_bn254:** fix size of 2-naf table of the seed
### Perf
- ScalarMulBase for sw_bls12377 on G2
- ELM03+Joye07 for emulated scalarMul
- special E12 squaring in the second ML iteration
- replace Add(Mul) by MulAdd
- async parallel plonk pr read ([#748](https://github.com/Consensys/gnark/issues/748))
- add a generalized version of binary selection ([#636](https://github.com/Consensys/gnark/issues/636))
- use ScalarMulAddOnly is ecrecover and ecmul precompiles
- use ScalarMulAddOnly is ecrecover and ecmul precompiles
- add frontend.WithCompressThreshold in compile test opts
- replace intSet by bitset
- use cpt in topo sort
- optimise one sub
- factorize MultiLin.Evaluate hot loop
- reflect new gc gkr opts and parallelize solving
- ScalarMulBase with pre-computed points + use in ecdsa
- use `api.Lookup2` for constructing 4 to 1 mux
- use `api.Select` for 2 to 1 mux
- ScalarMulBase for sw_bls12377
- optimize final exp (Fuentes et al.)
- save 1 Select at each iteration in the emulated scalar mul
- reduce mem allocs in scs frontend ([#654](https://github.com/Consensys/gnark/issues/654))
- special E24 squaring in the second ML iteration
- ScalarMulBase for sw_bls24315 G1/G2 + KZG in-circuit
- plonk ccs serialization ([#557](https://github.com/Consensys/gnark/issues/557))
- **bls381-pairing:** optimize Frobenius and FrobeniusSquare
- **bn254-pair:** MulByNonResidueInverse using hints
- **bn254-pair:** optimize fields ops + cleaning
- **bn254-pair:** optimize Halve using hints
- **bn254-pair:** optimize FrobeniusSquare computations
- **bn254-pair:** use hinted Div in tower instead of plain inv+mul
- **bn254-pairing:** isolate i=63 in MillerLoop to save a doubleStep
- **bn254-pairing:** test and optimize MultiMillerLoop
- **bn254-pairing:** some missed small optims
- **bn254-pairing:** Mul lines between them before mul by accumulator
- **ecdsa:** JoinScalarMulBase avoids 0 edge-cases
- **pairing-bn254:** optimize emulated pairing over BN254
- **pairing-bn254:** optimize Miller loop (last line out of loop)
- **pairing-bn254:** optimize doubleStep (mulByConst 3)
- **pairings:** switch to no edge-cases when single pairing
- **scalarMul:** saves computation in last two iterations
- **scalarMulBase:** lookup2 for the first 2 bits
- **sw_bn254:** use 2-NAF for fixed scalar Mul on G2
- **sw_bn254:** optim of fixed scalar Mul on G2
- **sw_bn254:** use addchain/doubleAndAdd for fixed scalar mul
- Improve MultiLin.Eval number of constraints ([#788](https://github.com/Consensys/gnark/issues/788))
### Refactor
- use select instead of lookup2
- renaming as per robot overlords
- inputs check are in a proper function
- use gnark-crypto gate registries
- apply suggested edits
- compactify commitment tests ([#728](https://github.com/Consensys/gnark/issues/728))
- remove api from ScalarMulAddOnly arguments
- reflect commitmentInfo changes in plonk
- reflect changes in plonk prover
- bn254 groth16 commitmentinfo
- separate groth16 commitmentInfo experiments
- do not pass api in pairing
- FindInSlice use
- make native precomputed lines private
- remove profiler code
- use c.CommitmentWireIndexes in Plonk backend
- eliminate GetNbCommitments
- groth16 and plonk tests to hollow circuits themselves
- test utils to another file
- emulation parameters ([#696](https://github.com/Consensys/gnark/issues/696))
- get the input length for pair lengths
- end-to-end commitment tests
- rename PI2
- reuse dummy one
- remove HintIds struct
- NewNamedHint not taking hint function input
- r1cs NewNamedHint not taking hint func
- commitmentInfo array for groth16 bn254
- commitmentInfo array in plonk setup
- commitmentinfo array in plonk prover
- get rid of CommittedAndCommitment
- limit commitment info in groth16 ver
- in method work with pointers instead of values
- init b of twist once
- use assertIsOnCurve from sw_emulated
- init point at return
- g2 gadget as pointer
- init emulated constants once
- make double, add, triple and doubleAndAdd private
- remove DivSpecial
- do not include committed wires indexes in plonk vk
- more adapting to separated kzg srs
- use separated kzg pk, vk
- separate final exp into safe and unsafe
- gkrAPI is no longer a frontend.API
- rename ScalarMulAddOnly to ScalarMul and ditch old
- remove duplicate test utils
- do not pass api in towers
- embed api and init emulation in tower
- same bsb22 placeholder for groth16 and plonk
- make E6 double public
- remove dead code (Frobenius and GS cyclosq)
- remove profiler in test
- remove profiler in test
- make lineEvaluation private
- make all hints private
- unify calling interfaces
- made some util func private
- expose all typed backends in gnark/backend (moved from internal/) ([#561](https://github.com/Consensys/gnark/issues/561))
- minor code cleaning
- move utils in mpcsetup; limit api surface
- setup -> mpcsetup
- flatten mpc structure, idomify APIs
- expose all typed backends in gnark/backend (moved from internal/)
- compute lagrange basis from scratch
- dont need nativemod in emulated hint unwrapper
- solving and compilation in accordance with commitmentInfo struct changes
- SparceCS.CommitmentConstraint instead of C; more "honest" constraints
- take api.Commit to api.go
- algebra into native (2-chain) and emulated
- use generator from gnark-crypto to init points
- make internal methods private
- use generator from gnark-crypto to init points
- rename methods for getting tables
- lazy compute the base tables on init
- plonk uses constraint/ and couple of fixes closes [#467](https://github.com/Consensys/gnark/issues/467) ([#493](https://github.com/Consensys/gnark/issues/493))
- latest gnark-crypto, use FFT signature change with opts ([#485](https://github.com/Consensys/gnark/issues/485))
- make methods private
- remove Commit from Compiler, make optional interface
- some cleanup - bn254 only
- hint-lite, has import cycle
- use mostly no-ptr data. better information silos
- improved, simplified solver; compiler to match
- all in one package
- MSM takes Montgomery only - Plonk
- groth16 backend tests pass
- no non-mont on bls12-377
- **pairing-bn254:** remove dead code (fields_e2)
- **pairing-bn254:** remove dead code (E2 Halve)
- **pairing-bn254:** remove dead code
- std/algebra ([#526](https://github.com/Consensys/gnark/issues/526))
### Remove
- unused func
- some unused code
### Revert
- special case for empty slice
- forced conversion
- remove extra testing funcs
- unexport cs.system
- unnecessary stylistic change
- unnecessary stylistic changes
- bn254/gkr changes
### Style
- remove prints
- remove comment
- subscript group index
- remove commented import
- unused input -> _
- correct some comments
- fewer vars
- remove unnecessary stylistic changes
- academic style reference for documentation
- rename addStepLineOnly to lineCompute
- rename variables
- apply suggested edits
- public-value-defining constraints as -x + c = 0 for consistency
- **fields_bn254:** clean hints
- **pairing-bn254:** add comments
- **pairing-bn254:** add comments
### Test
- product of pairings on bls12-381
- print some linpoly arguments
- more for bsb22 plonk
- add failing test for round trip pk serialization
- handle all cases in a single parametric circuit
- proof is correct. verification failing
- print solution
- public values
- don't parallelize
- print commitment
- pi is computed correctly
- failing on parallel
- JointScalarMulBase
- use assertless sampling
- use deep.Equal in Plonk roundtrip
- fails. pointer issue
- add bn254 and bl12381 test of AssertIsOnCurve
- test bls12-381 in sw_emulated + comments
- add safe final exp tests
- test also unsafe final exp
- multi commits in scs
- added failing test for groth16 pk serialization round trip
- added missing integration test for round trip serialization
- remove profiling test
- remove blindings and hashes, simplest no-commitment test that fails
- added reference benchmark
- ensure phase2 serialization is tested
- solver error found
- with dependency. err: inputs are modified
- add emulated Fp12 tests
- add emulated Fp6 tests
- add emulated Fp2 tests
- basic permutation tests passing
- only the gkr solver
- more instances
- with dependency
- "doubling" circuit passes
- end-to-end: can't use test engine (for now)
- **emulated:** ScalarMul with random scalars
- **fields_bn254:** add remaing tests
- **fields_bn254:** clean tests
- **sw_emulated:** infinity as (0,0) edge-cases in ScalarMul

### Pull Requests
- Merge pull request [#814](https://github.com/Consensys/gnark/issues/814) from Consensys/develop
- Merge pull request [#804](https://github.com/Consensys/gnark/issues/804) from Consensys/feat/revert_staticcall
- Merge pull request [#796](https://github.com/Consensys/gnark/issues/796) from Consensys/feat/calldata_pi_proof
- Merge pull request [#795](https://github.com/Consensys/gnark/issues/795) from Consensys/feat/clean_compute_pi
- Merge pull request [#794](https://github.com/Consensys/gnark/issues/794) from Consensys/feat/clean_hash_fr
- Merge pull request [#792](https://github.com/Consensys/gnark/issues/792) from Consensys/perf/solidity-cached-array-index
- Merge pull request [#783](https://github.com/Consensys/gnark/issues/783) from Consensys/perf/emulated-scalarMul
- Merge pull request [#775](https://github.com/Consensys/gnark/issues/775) from Consensys/fix/plonk_audit_4-23
- Merge pull request [#772](https://github.com/Consensys/gnark/issues/772) from Consensys/perf/pairing-add0
- Merge pull request [#760](https://github.com/Consensys/gnark/issues/760) from Consensys/perf/emulated-scalarMul
- Merge pull request [#769](https://github.com/Consensys/gnark/issues/769) from Consensys/fix/plonk_contract_i_768
- Merge pull request [#762](https://github.com/Consensys/gnark/issues/762) from Consensys/fix/i_761
- Merge pull request [#758](https://github.com/Consensys/gnark/issues/758) from Consensys/fix/plonk_audit_4-15
- Merge pull request [#754](https://github.com/Consensys/gnark/issues/754) from Consensys/fix/plonk_audit_4-5
- Merge pull request [#756](https://github.com/Consensys/gnark/issues/756) from Consensys/fix/plonk_audit_4-13
- Merge pull request [#742](https://github.com/Consensys/gnark/issues/742) from Consensys/fix/plonk_audit_4-4
- Merge pull request [#744](https://github.com/Consensys/gnark/issues/744) from Consensys/fix/plonk_audit_4-8
- Merge pull request [#714](https://github.com/Consensys/gnark/issues/714) from Consensys/perf/emulated-pairing
- Merge pull request [#698](https://github.com/Consensys/gnark/issues/698) from Consensys/evm/ecpair
- Merge pull request [#726](https://github.com/Consensys/gnark/issues/726) from Consensys/emulated/scalarMul
- Merge pull request [#708](https://github.com/Consensys/gnark/issues/708) from Consensys/feat/fixed-pairing
- Merge pull request [#739](https://github.com/Consensys/gnark/issues/739) from Consensys/fix/plonk_audit_4-9
- Merge pull request [#736](https://github.com/Consensys/gnark/issues/736) from Consensys/fix/plonk_audit_4-11
- Merge pull request [#737](https://github.com/Consensys/gnark/issues/737) from Consensys/feat/gkr-custom-gates
- Merge pull request [#443](https://github.com/Consensys/gnark/issues/443) from Consensys/feat/gkr-api
- Merge pull request [#733](https://github.com/Consensys/gnark/issues/733) from Consensys/refactor/gkr-notfrontend-api
- Merge pull request [#723](https://github.com/Consensys/gnark/issues/723) from ConsenSys/fix/serialization
- Merge pull request [#702](https://github.com/Consensys/gnark/issues/702) from ConsenSys/feat/g16-multicommits
- Merge pull request [#712](https://github.com/Consensys/gnark/issues/712) from ConsenSys/fix/plonk-commit0
- Merge pull request [#707](https://github.com/Consensys/gnark/issues/707) from ConsenSys/perf/scalarMul-2chain
- Merge pull request [#706](https://github.com/Consensys/gnark/issues/706) from ConsenSys/perf/scalarMul-2chain
- Merge pull request [#694](https://github.com/Consensys/gnark/issues/694) from ConsenSys/feat/change_opening_order_kzg
- Merge pull request [#701](https://github.com/Consensys/gnark/issues/701) from ConsenSys/fix/672
- Merge pull request [#668](https://github.com/Consensys/gnark/issues/668) from ConsenSys/feat/plonk-multicommit
- Merge pull request [#666](https://github.com/Consensys/gnark/issues/666) from ConsenSys/feat/hint-naming-options
- Merge pull request [#661](https://github.com/Consensys/gnark/issues/661) from ConsenSys/perf/ecdsa
- Merge pull request [#629](https://github.com/Consensys/gnark/issues/629) from ConsenSys/feat/emulated/subgroup-check
- Merge pull request [#658](https://github.com/Consensys/gnark/issues/658) from ConsenSys/perf/kzg-verify
- Merge pull request [#632](https://github.com/Consensys/gnark/issues/632) from ConsenSys/refactor/kzg-srs-breakup-companion
- Merge pull request [#633](https://github.com/Consensys/gnark/issues/633) from ConsenSys/plonk-commitment-info
- Merge pull request [#631](https://github.com/Consensys/gnark/issues/631) from ConsenSys/feat/AddSafe
- Merge pull request [#625](https://github.com/Consensys/gnark/issues/625) from aybehrouz/perf/mux
- Merge pull request [#613](https://github.com/Consensys/gnark/issues/613) from ConsenSys/fix-605
- Merge pull request [#586](https://github.com/Consensys/gnark/issues/586) from ConsenSys/406-bsb22-commitments-plonk
- Merge pull request [#591](https://github.com/Consensys/gnark/issues/591) from ConsenSys/feat/bls12-381-pairing
- Merge pull request [#594](https://github.com/Consensys/gnark/issues/594) from ConsenSys/perf/bn254-FinalExp
- Merge pull request [#566](https://github.com/Consensys/gnark/issues/566) from ConsenSys/perf/bn254-pairing
- Merge pull request [#563](https://github.com/Consensys/gnark/issues/563) from ConsenSys/stage/bnb/groth16setup
- Merge pull request [#519](https://github.com/Consensys/gnark/issues/519) from ConsenSys/refactor/remove-profiling
- Merge pull request [#514](https://github.com/Consensys/gnark/issues/514) from ConsenSys/refactor/weierstrass-scalarmulbase
- Merge pull request [#506](https://github.com/Consensys/gnark/issues/506) from ConsenSys/perf/kzg-in-circuit
- Merge pull request [#497](https://github.com/Consensys/gnark/issues/497) from ConsenSys/perf/ecdsa
- Merge pull request [#503](https://github.com/Consensys/gnark/issues/503) from ConsenSys/docs/emulated-select
- Merge pull request [#481](https://github.com/Consensys/gnark/issues/481) from ConsenSys/refactor/commit-interface
- Merge pull request [#480](https://github.com/Consensys/gnark/issues/480) from ConsenSys/feat/kvstore
<a name="v0.8.1"></a>
## [v0.8.1] - 2023-07-11
### Chore
- update CHANGELOG
- update version
- update gnark-crypto dependency

### Pull Requests
- Merge pull request [#771](https://github.com/Consensys/gnark/issues/771) from Consensys/release/v0.8.1
<a name="v0.8.0"></a>
## [v0.8.0] - 2023-02-14
### Build
- update to latest gnark-crypto
- update to latest gnark-crypto
- make linter happy remove deprecated call
- updated to feat/commitment branch on gnark-crypto ([#408](https://github.com/Consensys/gnark/issues/408))
- test only on go 1.18 for now
- re-ran go generate
- update CI ([#318](https://github.com/Consensys/gnark/issues/318))
### CI
- fix slack integration + adds golanglint-ci ([#316](https://github.com/Consensys/gnark/issues/316))
### Clean
- remove deadcode and kill `api.Tag` and `api.Counter` ([#353](https://github.com/Consensys/gnark/issues/353))
### Docs
- updated README.md
- remove logo references
- update doc link
- describe limb regrouping for equality
- add method documentation
- add explainer
- comments
- add method docs
### Feat
- added serialization header to CS and debug info to all constraints with -tags=debug ([#347](https://github.com/Consensys/gnark/issues/347))
- checkpoint 3, computations are correct, some commitments are failing
- add cs.GetConstraint with examples, and pretty printer helpers ([#452](https://github.com/Consensys/gnark/issues/452))
- cleaned plonk constraints evaluation
- code gen + cleaned code
- update gnark version to v0.8.0
- plonk constraints captured using Expressions
- code gen
- Evalute is used instead of manually evaluatin
- removed printings
- fixed verifier
- add automatic non-native witness element limb constraining ([#446](https://github.com/Consensys/gnark/issues/446))
- cleaned code
- addition of missing commitments and openings in vk and pk
- checkpoint 2
- checkpoint refactor
- add ECDSA signature verification ([#372](https://github.com/Consensys/gnark/issues/372))
- adds `api.MAC(..)` ([#427](https://github.com/Consensys/gnark/issues/427))
- keccak-f permutation function ([#401](https://github.com/Consensys/gnark/issues/401))
- add debug.SymbolTable into constraint system for storage efficiency of debug info ([#421](https://github.com/Consensys/gnark/issues/421))
- split field in field emulation into Field and FieldAPI ([#395](https://github.com/Consensys/gnark/issues/395))
- testing options and clearer errors
- add linear expression packing for R1CS ([#418](https://github.com/Consensys/gnark/issues/418))
- merge develop
- add inherit circuit tag ([#387](https://github.com/Consensys/gnark/issues/387))
- add gnark tags
- gkr verifier is NOT a witness object
- some sumcheck experiments
- poly functions and some tests
- gkr verifier
- some sumcheck experiments
- replaced full bit decomposition by rshift in emulated/assertIsEqual ([#354](https://github.com/Consensys/gnark/issues/354))
- cleaned code
- add test.NoFuzzing() testing option ([#296](https://github.com/Consensys/gnark/issues/296))
- map in snark
- add fake API for emulated arithmetics
- split add/mul/sub into cond and op
- addition of dynamic test for kzg bls24315
- addition of dynamic test kzg bls12377
- size of fiat shamir data is harcoded
- count fields in first schema parsing
- add VariableCount method to builder
- implement AssertIsLessEqualThan
- binary composition
- add Params.isEqual
- implement Lookup2 and select
- add panicking constant init
- added verifier (forgot to commit it)
- merge develop
- addition of proximity tests
- uncomment integration tests
- only mul is tested for plonk fri
- addition of plonkfri in test package
- code gen
- addition of templates
- Fiat Shamir done
- re activated blinding
- removed dead code + old commented code
- removed mock commitment scheme
- verification of Z, Zshifted
- addition of proofs for s1,s2,s3 and ccircuit coefficients
- **frontend:** add builder wrapper compile opt
- **hint:** allow registering multiple hints
- **plonk:** addition of skeleton prover with non homomorphic PCS
- **std:** KZG verifier gadget bls24-315 (with static witness)
### Fix
- mark and output boolean ([#459](https://github.com/Consensys/gnark/issues/459))
- mimc pow7
- prover-verifier work with blinding
- handle recursive hints in level builder ([#441](https://github.com/Consensys/gnark/issues/441))
- verifier working \o/
- pack full limbs for quotient ([#439](https://github.com/Consensys/gnark/issues/439))
- add shortcut for const input in MulConst ([#438](https://github.com/Consensys/gnark/issues/438))
- closes [#434](https://github.com/Consensys/gnark/issues/434) returns a copy of the input slice when filtering groth16+commitment ([#435](https://github.com/Consensys/gnark/issues/435))
- fix previous commit
- closes [#400](https://github.com/Consensys/gnark/issues/400) path trimming correct, example with unix path separators
- tests expected to fail
- engine.Println to take strings ([#419](https://github.com/Consensys/gnark/issues/419))
- verifier input building
- idiotic load circuit bug
- update test vector proofs to proper size, some bugs
- fix [#400](https://github.com/Consensys/gnark/issues/400) with trim path handling in profile report ([#409](https://github.com/Consensys/gnark/issues/409))
- fixed Lagrange polynomials construction ([#389](https://github.com/Consensys/gnark/issues/389))
- staticcheck
- multi-fan-out input bug
- update test vectors, hash finalevalproofs
- less elegant "hollow", but it works
- some problems in sumcheck and gkr
- TestTranscript works
- Xor(var, constant) in scs corrected
- simple sumcheck test passes
- IsZero throws panic on ([#367](https://github.com/Consensys/gnark/issues/367))
- fixes [#359](https://github.com/Consensys/gnark/issues/359) missing fields in plonk serialized format ([#364](https://github.com/Consensys/gnark/issues/364))
- Sumcheck verifier usable as circuit
- InterpolateOnRange works even when it doesn't really have to "inerpolate"
- extra nosec G404 in test file
- minor typo
- misspelled ("decsribes" ->  "describes") ([#339](https://github.com/Consensys/gnark/issues/339))
- remove leq overwrite
- reduce element when init from const
- fixed comments
- kzg verifier test
- rebase on develop
- reduce div integration circuit
- remove broken equality fast-path
- remove subtraction padding optimisation
- use BaseField() to get modulus
- use scalar field bitlength directly
- change hint definitions
- reduce given argument not inline
- ToBits return nb of bits
- ToBits edge case for overflow=0
- consider carries in bit decomposition
- return element
- add/set use argument nb of limbs
- set overflow after reduce
- remove unused method
- more precise padding computation
- make conversion functions private
- remove debug calls
- multiplication top limb width
- remove second high limb exception in sub padding
- added DecomposeScalarG2 to std.RegisterHints
- enfore width after inverse and div
- remove api from constant init
- ignore plonk_fri in internal/stats for now
- remove unused error return
- check unchecked error
- copy instead of loop
- fixed position of the shifted opening
- fixed size Iop (error due to the blinding)
- fixed opening Merkle path
- fixed vanilla plonk fri
- removed unused debug function
- **emulated:** enforce widths of packed limbs ([#368](https://github.com/Consensys/gnark/issues/368))
- **nonnative:** off by one error
- **plonk:** fixed generic verifier
- minor typo ([#360](https://github.com/Consensys/gnark/issues/360))
### Perf
- more precomputation in plonk/iop ([#471](https://github.com/Consensys/gnark/issues/471))
- mimc on bls12-377/fr uses x^17 as a permutation
- api.IsZero generate less constraints ([#356](https://github.com/Consensys/gnark/issues/356))
- minor improvments to big.Int test engine ([#344](https://github.com/Consensys/gnark/issues/344))
- allocate less in test engine
- remove width enforcement in Reduce()
- lazy reduction
- constrain main bits in equality diff to be only zeros
- optimize equality check
### Refactor
- update to latest gnark crypto
- keeping up
- gnark-crypto iop 1
- clean up witness package, introduces clean `witness.Witness` interface ([#450](https://github.com/Consensys/gnark/issues/450))
- emulated clean up fixes [#448](https://github.com/Consensys/gnark/issues/448) ([#449](https://github.com/Consensys/gnark/issues/449))
- reflect gnark-crypto gkr changes, debug pending
- add constraint package and improve memory management in frontend ([#412](https://github.com/Consensys/gnark/issues/412))
- use polynomial package
- std/math/nonnative -> std/math/emulated ([#345](https://github.com/Consensys/gnark/issues/345))
- remove in-method reductions
- use field in schema leaf handler
- Compile(ecc.ID) -> Compile(field *big.Int) ([#328](https://github.com/Consensys/gnark/issues/328))
- VerifyFri -> Verify
- remove geth dependency ([#440](https://github.com/Consensys/gnark/issues/440))
### Style
- clean up unused functions
- remove questions
- Multilin -> MultiLin
- Multilin -> MultiLin
- comment about scalar fields of in-circuit KZG
- moved kzg in circuit in commitment/ folder
- removed dead code
- removed dead comments
- factored code in integration_test
- remove dead code
- remove irrelevant TODOs
- typos
- rename n to r
- inline test struct init
- cleanup test comments
- change field to params in tests
- test name update
- remove unused documentation file
- removed dead debug printings
- uncomment verify.go in generic plonk
- removed printing functions
### Test
- add four-instance test case
- all pass except "two_input_single_identity_gate_two_instances"
- trying to feed proof as circuit input, reflect errors
- routine developed for gkr
- Transcript fails
- doubleMap works
- singleMap works
- fix incorrect proof
- circuit and witness cannot be the same object
- counter start from 2
- all parts of witness get unconstrained error
- sumcheck in circuit, getting errors
- pass
- sumcheck in circuit, getting errors
- add Goldilocks tests
- add fake API tests
- bench kzg verifier with plonk
- add test/solver_test.go ([#329](https://github.com/Consensys/gnark/issues/329))
- binary composition test
- implement lookup2 test
- implement constant test
- fewer test cases
- implement large computation circuit
- implement select test

### Pull Requests
- Merge pull request [#469](https://github.com/Consensys/gnark/issues/469) from ConsenSys/fix/mimc-pow7
- Merge pull request [#451](https://github.com/Consensys/gnark/issues/451) from ConsenSys/feat/iop_refactor
- Merge pull request [#455](https://github.com/Consensys/gnark/issues/455) from ConsenSys/develop
- Merge pull request [#453](https://github.com/Consensys/gnark/issues/453) from ConsenSys/mimx/nb-rounds-bls12377
- Merge pull request [#393](https://github.com/Consensys/gnark/issues/393) from ConsenSys/feat/gkr
- Merge pull request [#361](https://github.com/Consensys/gnark/issues/361) from ConsenSys/feat/polynomial
- Merge pull request [#363](https://github.com/Consensys/gnark/issues/363) from ConsenSys/fix/lde-0div
- Merge pull request [#362](https://github.com/Consensys/gnark/issues/362) from ConsenSys/fix/mathrand
- Merge pull request [#250](https://github.com/Consensys/gnark/issues/250) from ConsenSys/feat/plonk_generic
- Merge pull request [#325](https://github.com/Consensys/gnark/issues/325) from ConsenSys/feat/emulated-api
- Merge pull request [#331](https://github.com/Consensys/gnark/issues/331) from ConsenSys/perf/test-engine
- Merge pull request [#332](https://github.com/Consensys/gnark/issues/332) from ConsenSys/refactor/schema-parsing
- Merge pull request [#334](https://github.com/Consensys/gnark/issues/334) from ConsenSys/fix/nonnative-offbyone
- Merge pull request [#320](https://github.com/Consensys/gnark/issues/320) from ConsenSys/perf/nonnative
- Merge pull request [#307](https://github.com/Consensys/gnark/issues/307) from ConsenSys/feat/std/kzg-verifier
- Merge pull request [#302](https://github.com/Consensys/gnark/issues/302) from ConsenSys/feat/nonnative-ff
<a name="v0.7.1"></a>
## [v0.7.1] - 2022-04-14
### Clean
- std/groth16 uses same notation as out-of-circuit groth16 ([#304](https://github.com/Consensys/gnark/issues/304))
### Docs
- added security policy, gnark-announce and twitter link
- updated DOI
### Feat
- added VerifyingKey.Assign methods in std/groth16 ([#306](https://github.com/Consensys/gnark/issues/306))
### Fix
- fix previous commit
- restored logger format
- err instead of panic when recursively solving hints
### Refactor
- delete dead code (TripleMillerLoop)
### Style
- code cleaning in std/pairing

### Pull Requests
- Merge pull request [#298](https://github.com/Consensys/gnark/issues/298) from ConsenSys/fix/hint-panic
<a name="v0.7.0"></a>
## [v0.7.0] - 2022-03-25
### Build
- fix gosec warnings
- updated to gnark-crypto v0.7.0
### CI
- updated github actions
- test against go1.17 and go1.18 ([#288](https://github.com/Consensys/gnark/issues/288))
### Clean
- remove PairingContext and Extension objects from api calls in std/.../pairing ([#286](https://github.com/Consensys/gnark/issues/286))
### Docs
- updated README.md with same warning as in docs
- added Deprecated comments in front of APIs moved to Compiler interface
- clean up hint interface comment
- updated DOI
### Feat
- adds std/math/bits/ToNAF
- remove offset shifts in plonk compile
- added ivokub suggestion on logging duration values
- add gnark/logger
- hint.NbOuputs should not be used at solve time, only at compile time
- remove post-compile offset id in R1CS builder
- added internal/stats package
- added ToTernary closes [#269](https://github.com/Consensys/gnark/issues/269)
- adds gnark logger. closes [#202](https://github.com/Consensys/gnark/issues/202)
- disable logger in tests by default, unless debug tag present
- implement PR suggestions in std/math/bits
- moved api.FromBinary to std/math/bits
- add ToBinary in std/math/bits
- added std.GetHints for convenience. fixes [#264](https://github.com/Consensys/gnark/issues/264). error message when hint is missing now has hint name
- added NBits hint
- make nboutputs of a hint explicit at compile time
- **std:** added AssertIsTrit
### Fix
- add whitespace between vars in test.Println
- closes [#293](https://github.com/Consensys/gnark/issues/293) and enables recursive hints solving
- replace stats snippet signature with newVariable() instead of fixed variable
- move init() behind sync.Once. remove verbose option in stats binary
- re generated stats
- gosec errors
- fixes [#266](https://github.com/Consensys/gnark/issues/266) by adding constant path in Lookup2 and Select
- uncomment fuzz part of test
- std.GetHints() return bits.NNAF
- incorrect handling of nbBits == 1 in api.ToBinary
- **stats:** fix pairing stats. added run flag for stats binary to filter with regexp
### Perf
- restored frontend.WithCapacity option...
- **plonk:** IsConstant -> ConstantValue
- **sw:** no need for Lookup2 in constScalarMul
- **tEd:** Add -1C
### Refactor
- std/pairing have more consistent apis
- std/pairing bls12377 api more coherent
- remove StaticHint wrapper, log duplicate hints ([#289](https://github.com/Consensys/gnark/issues/289))
- backend.WithOutput -> backend.WithCircuitLogger
- remove all internal circuits from stats, keep important snippets only
- move circuit_stats_test.go into internal/stats
- move NBits hint to math/bits
- move ntrits hint to std/math/bits
- make api.ToBinary point to math/bits/ToBinary
- revert Builder -> Compiler internal name change
- compiler -> r1cs and scs internally
- start moving api.ToBinary to std/math/bits/
- compiled.Variable -> compiled.LinearExpression
- factorize coeff table initialization
- frontend/cs subpackages to match new interfaces
- split compiler, api and builder interface into interfaces
- remove IsBoolean from R1CS variables
- preparing frontend.Compiler interface
- frontend.Compile now takes a builder instead of backendID as parameter
- moved internal/compiled to frontend/compiled
- remove nb inputs from hint declaration
### Style
- code cleaning
- added clearer error message for groth16 verifier missing init in circuit
- remove dead code
- remove duplicate import in template
- code cleaning
- remove dead code
- code cleaning
### Test
- add failing test for [#293](https://github.com/Consensys/gnark/issues/293)

### Pull Requests
- Merge pull request [#295](https://github.com/Consensys/gnark/issues/295) from ConsenSys/fix/test-println
- Merge pull request [#294](https://github.com/Consensys/gnark/issues/294) from ConsenSys/fix/recursivehhints
- Merge pull request [#291](https://github.com/Consensys/gnark/issues/291) from ConsenSys/refactor/std/pairing
- Merge pull request [#281](https://github.com/Consensys/gnark/issues/281) from ConsenSys/feat/logger
- Merge pull request [#280](https://github.com/Consensys/gnark/issues/280) from ConsenSys/simplify-r1cs-compile
- Merge pull request [#279](https://github.com/Consensys/gnark/issues/279) from ConsenSys/feat/statistics
- Merge pull request [#276](https://github.com/Consensys/gnark/issues/276) from ConsenSys/feat-math-bits
- Merge pull request [#278](https://github.com/Consensys/gnark/issues/278) from ConsenSys/perf-constant-lookup2
- Merge pull request [#272](https://github.com/Consensys/gnark/issues/272) from ConsenSys/refactor-hint
- Merge pull request [#275](https://github.com/Consensys/gnark/issues/275) from ConsenSys/refactor-compiler-builder
- Merge pull request [#271](https://github.com/Consensys/gnark/issues/271) from ConsenSys/refactor-compiled
- Merge pull request [#267](https://github.com/Consensys/gnark/issues/267) from ConsenSys/perf/tEd-add
- Merge pull request [#265](https://github.com/Consensys/gnark/issues/265) from ConsenSys/perf/SW-constScalarMul
<a name="v0.6.5"></a>
## [v0.6.5] - 2022-04-13
### Fix
- **plonk:** security vuln in fiat-shamir inputs
<a name="v0.6.4"></a>
## [v0.6.4] - 2022-02-15
### Build
- update to gnark-crpto v0.6.1
- updatd to latezst gnarkcrypto
### Docs
- updated changelog for v0.6.4
- updated README.md with playground link
### Feat
- plonk adapted to kzg modifications
- udpate gnark-crypto
- code gen for plonk
- polynomial --> []frElement
- groth16 prover adapted to new fft OK
- **plonk:** beta is dervied using Fiat Shamir
- **tEd:** implements double-base scalar mul
### Fix
- fixed trace and println tests
- fixed wrong bigInt op in plonk api
- resolve comments
- restored commented code blinding polynomial
- fixed verifier
- verifier obtains correct quotient
- missing beta in linearized polynomial
- linearized polynomial OK
- correct up to quotient
- fixed plonk up to permutation polynomial
- **tEd:** case when scalar size is odd
- **tEd:** case when scalar size is odd
### Perf
- sparse R1CS solver is parallel
- R1CS solver may now run in parallel
- **EdDSA:** eddsa gadget using double-base scalar mul
- **bandersnatch:** apply tEd perf changes to Bandersnatch
### Refactor
- **eddsa:** rearrange eddsa verif as cofactor clearing counts
### Style
- code cleaning
- removed debug comments
### Test
- **tEd:** test scalarMul for all curves and schemes

### Pull Requests
- Merge pull request [#259](https://github.com/Consensys/gnark/issues/259) from ConsenSys/perf-parallel-solver
- Merge pull request [#261](https://github.com/Consensys/gnark/issues/261) from ConsenSys/feat/kzg_updated
- Merge pull request [#257](https://github.com/Consensys/gnark/issues/257) from ConsenSys/perf/EdDSA
- Merge pull request [#253](https://github.com/Consensys/gnark/issues/253) from ConsenSys/feat/fft_cosets
<a name="v0.6.3"></a>
## [v0.6.3] - 2022-02-13
### Build
- make staticcheck happy
### Docs
- updated changelog for v0.6.3
- updated example in README.md
### Feat
- updated gnark-crypto
- removed seed in mimc
- mimc implem corresponds to ethereum implem
### Fix
- fixes [#255](https://github.com/Consensys/gnark/issues/255) variable visibility inheritance regression
- mod reduce input in solve with hint when coming from interface
- counter was set with PLONK backend ID in R1CS
- fixed conflicts
- assign a, b, c to solution and div by coeff instead of mul
- use uint64 for cbor unmarshal and cast
- fixed mimc example
### Perf
- replace big int pool in hint solver by tmp slice
- r1cs solver faster linear expression eval
- r1cs solver 40% faster by avoiding redudnant check
### Test
- benchmark solve r1cs with large linear exp
- added r1cs solve benchmark

### Pull Requests
- Merge pull request [#256](https://github.com/Consensys/gnark/issues/256) from ConsenSys/fix-bug-compile-visibility
- Merge pull request [#249](https://github.com/Consensys/gnark/issues/249) from ConsenSys/perf-ccs-hint
- Merge pull request [#248](https://github.com/Consensys/gnark/issues/248) from ConsenSys/perf-ccs-solver
- Merge pull request [#247](https://github.com/Consensys/gnark/issues/247) from ConsenSys/fix/plonk_cbor
<a name="v0.6.2"></a>
## [v0.6.2] - 2022-01-28
### Fix
- r1cs.GetConstraint bad alloc
<a name="v0.6.1"></a>
## [v0.6.1] - 2022-01-28
### Build
- go 1.16 to go 1.17
- github workflow against go 1.17 only
- github workflow against go 1.17 and go 1.18
### Clean
- better errors in witness
### Docs
- updated CHANGELOG.md with v0.6.1 changes
- update backend/witness godoc
- added bibtex citation
- **backend:** unify documentation for options
- **frontend:** unify docs for options
- **test:** unify documentation for options
### Feat
- added ccs.GetConstraints
- added witness.Public() to return Public part of the witness
- addition of Cmp in the API
- added GetSchema in CompiledConstraintSystem
- witness unmarshal uses limit reader if schema is set
- schema now stores nbPublic and nbSecret
- add optional omitempty tag in json generated schema
- prepare new witness API
- added frontend/schema to build circuit and witness schemas
### Fix
- handle array of array of array... in schema
- remove limit reader when parsing json
- deal with zero value in partial JSON witness
- added witness MarshalJSON working test. few ugly hacks to remove
- implemented pr suggestions. restored, fixed and addded sub tests in tags_test.go
- remove gnark embed tag in example rollup
- remove embbed struct tag
- typo in hint fn name
### Perf
- minimize allocations in ccs.GetConstraints
### Refactor
- compiled.Visbility -> schema.Visibiility
- added IsSolved API on the CompiledConstraintSystem interface
- backend/witness has no more dependency on frontend
- reduce frontend dependency in witness and remove most of type switches
- witness.WriteSequence -> schema.WriteSequence
- CopyTo -> VectorToAssignment
- factorize code in witness_test
- rename some variables from witness to assignment to avoid confusion
- cleaned internal/witness unused code
- killed ReadAndProve and ReadAndVerify (plonk)
- killed ReadAndProve and ReadAndVerify (groth16)
### Style
- replace ①  by 1
- change main/companion to outer/inner curve
- clean up unsatisfied constraint error paths
- return constraint formatted as in the paper
- experiment 2 constraint str
- experiment 1 plonk constraint string repr
- plonk human readable constraint A+M+k == O
- constraint is not satified err -> constraint #id is not satisfied
- cosmetics in sparseR1C repr
- constraint cosmetics string repr. remove ToHTML deadcode
- code cleaning
- code cleaning, error refactoring
- code clean up, pr review changes
- remove defers in test/assert.go
- group WitnessOption under same type, implements PR review
- clean some todo
- **frontend:** create CompileOption type
- **frontend:** use functional opts for witness
- **test:** create TestingOption type for function opts
### Test
- added assert.marshalWitness subtest to ensure round trip json and binary serialization test coverage
### Tests
- run marshalling tests as subtests

### Pull Requests
- Merge pull request [#244](https://github.com/Consensys/gnark/issues/244) from ConsenSys/plonk-human-readable
- Merge pull request [#237](https://github.com/Consensys/gnark/issues/237) from ConsenSys/ccs-get-constraints
- Merge pull request [#233](https://github.com/Consensys/gnark/issues/233) from ConsenSys/feat/api_cmp
- Merge pull request [#235](https://github.com/Consensys/gnark/issues/235) from ConsenSys/witness-public-api
- Merge pull request [#232](https://github.com/Consensys/gnark/issues/232) from ConsenSys/cleanup-231-group-options
- Merge pull request [#230](https://github.com/Consensys/gnark/issues/230) from ConsenSys/ccs-schema
- Merge pull request [#229](https://github.com/Consensys/gnark/issues/229) from ConsenSys/ccs-issolved-api
- Merge pull request [#228](https://github.com/Consensys/gnark/issues/228) from ConsenSys/witness-json
- Merge pull request [#226](https://github.com/Consensys/gnark/issues/226) from ConsenSys/feat-circuit-schema
- Merge pull request [#227](https://github.com/Consensys/gnark/issues/227) from ConsenSys/build-update-go1.17
- Merge pull request [#222](https://github.com/Consensys/gnark/issues/222) from ConsenSys/perf/std-sw-glv
<a name="v0.6.0"></a>
## [v0.6.0] - 2022-01-04
### Build
- update to latest gnark-crypto with fix for empty addchain folders
- updated to latest gnark-crypto
### Clean
- remove TotalInputs
### Docs
- updated changelog.md
- updated README.md example
- draft release notes for v0.6.0
- zkteam -> gnark
- add suggestion to error
### Feat
- extended the Add test
- internal/parser handles interface values and outputs warning when a struct is non adressable [#169](https://github.com/Consensys/gnark/issues/169)
- added explicit warning when parser encounters unadressable struct field [#169](https://github.com/Consensys/gnark/issues/169)
- addition of test for mul
- lighter stack trace by default for circuits, more verbose when -tags=debug provided
- added api.Tag and api.AddCounter to measure number of constraints in portion of circuit
- add debug info for SparseR1CS inverse
- add option to define newBuilder
- register frontend for backends
- register frontend compilers
- removed txt logs
- handle non zero divisor in Div
- addition of boolean table for sparseR1cs
- restored  options (forgot to commit the file)
- extended select test
- addition of test for select api
- api.AddCounter now measure new plonk constraints too
- made inv test explicit
- test circuits specifiy curves (useful for Div,Inv)
- addition of test for final exp in sw_bls24315
- cleaned  frontend/
- code uses new Compile from compile.go
- hint inptus LinearExpression -> interface
- closes [#197](https://github.com/Consensys/gnark/issues/197) FromInterface supports uintXX and intXX types
- extended add test
- addition of Compile method on System interface
- addition of tests in r1cs/
- addition of Tag, Counter in plonk/ and r1cs/
- populated r1cs/ plonk/ for separating schemes
- finished assertions plonk
- completion of API (except rangeCheck, lookup2, Hints)
- started the addition of plonk secific cs
- added frontend.IsConstant and ConstantValue apis
- added api.CurveID()
- boolean constraint are handled separately
- restored plonk/groth16 switch in frontend
- add new curve bw6-633
- triplePairing test uses 3 different pairs
- counters accesible through CompiledConstraintSystem
- **frontend:** add lookup2 API method
- **frontend:** NewHint returns multiple outputs
- **integration_test:** add variable-input/output hint test
- **std:** fields, SW and pairing over BLS24-315 in BW6-633 circuit
- **test:** add Run for running as subtests
- **test:** add Log method for logging in subtests
- **test:** solve multi-output hints in engine
### Fix
- fixed mul
- addition of mod reduction in plonk api to bound bigInt
- re-exposed compiled.ConstraintSystem (internal) as frontend.CompiledConstraintSystem
- fixed examples/plonk
- reduce variables modulo scalar order
- hint solver was not returning objects to pool
- use sr1cs debug representation
- restored check unconstrained inputs when compiling
- fixed staticcheck
- fixes [#168](https://github.com/Consensys/gnark/issues/168) adds context to a non-deterministic compilation error in the Assert object
- fixed staticheck
- removed unused file
- ran go generate
- fixed signature of addPlonkConstraint
- fixed bigInt passed by copy in plonk api
- mul test for all curves
- pairing test on Plonk + Groth16
- removed dead folder
- fixed mul test
- fixed AssertIsEqual when an argument is constant
- fixed mul by zero
- fixed Div (plonk)
- fixed Div(constant, var)
- plonk solver handles both L and R to solve
- Div -> DivUnchecked test div
- fixed code gen
- fixed range_constant plonk
- restored simpler version for range_constant r1cs
- fixed lookup2
- fixed isZero
- fixed assertIsEqual
- fixed assertion (AssertIsEqual missing return)
- fixed AssertIsBoolean in plonk (mul by constant failed)
- fixes [#169](https://github.com/Consensys/gnark/issues/169) ensure frontend.Circuit methods are defined on pointer receiver
- extended sub test
- fixed Groth16 integration tests
- restored bootloader
- removed Compile() method in engine
- fixed API missing methods
- incorrect handling of hints in r1cs solver
- fixes [#178](https://github.com/Consensys/gnark/issues/178) by adding cbor.MaxMapPairs options when reading R1CS
- merge with develop branch
- remove deadcode (csfuzz targets)
- go:generate bw6633 and updated circuit stats
- fixed code gen :/
- fixed gosec
- ran gofmt
- set variable to Solved after Or,And,Xor when compiling to plonk
- handled nbBits=1 in toBinary
- fixed comments
- resolve comments
- fixed Div
- fixed tests in cs_api_test
- restored log in parser
- fixed XOR, OR, mustBeLessOrEqCst
- fixed select to reduce nb of plonk constraints
- fixed ToBinary
- fixed toSparseR1CS, removed dead code
- fixed Select constraint
- **debug_test:** reverse trace and expected trace order
- **examples:** omit unnecessary api call
- **frontend:** reduce constant by modulus
- **frontend:** set only hint internal variables constrained
- **init.stats:** update circuit statistics
- **integration_test:** remove fuzzing call
### Frontend
- update hint documentation
### Perf
- **std:** bls24 Miller loop in 2NAF + opt. Final exp
### Refactor
- frontend.Variable -> cs.Variable
- simplified cs_to_r1cs_sparse algo
- Variable is now an interface. std/ wip
- moved compile in compiler/
- std/ uses Variable interface{}
- remove api.Constant. can now assign directly
- move GetWitnessValue to internal test engine func
- unpublish frontend/cs/ structures
- rename frontend/R1CSRefactor to frontend/R1CS
- use compile option to define builder
- cs.Variable -> frontend.Variable
- rename frontend.System to frontend.Builder
- TotalOutputs -> NbOutputs
- use internal util
- move frontend util to internal
- use frontend.Compile
- added frontend.IsConstant and ConstantValue apis
- Define(curveID, api) -> Define(api); api.CurveId()
- modified definition of Variable in zkpScheme
- compiled.CompiledConstraintSystem -> compiled.ConstraintSystem
- move definitions to frontend
- changed Variable definition in cs.go and compiled/
- remove curve from system Compile
- frontend.Variable -> cs.Variable
- interface --> Variable
- CurveID() --> Curve() in API
- cleaning hierarchy of constraints systems
- addition of compiler for both systems
- constraintSystme -> R1CS
- Hint takes []LinearExpression as input
- VariableID -> WireID
- use subtests in backend serialization tests
- simplifed wire tracking in a cs
- api interface allows access to backendID
- refactored  frontend
- modified cs_api.go
- **frontend:** move Tag to frontend/
- **frontend:** add compiler registry
- **integration_test:** run as subtests
- **lookup2:** use multiple witnesses for tests
- **stats:** use subassert for errors
- **stats:** run as subtests
- **test:** use Tag
- **test:** run assert subtests using Run
### Style
- added few comments
- removed dead code
- remove counter example in std/
- remove unused displayCounters boolean
- remove frontend.DisplayCounters option
- remove witnessValue method
- remove bls377tobw761 conv func
- remove bls377tobw761 conv func
- error strings should not end with punctuation or a newline
- **Miller loop:** for loop instead of addition chain
### Test
- use BN254 in modulus-dependent tests for speed
- added failing test with multiple hints in one R1C
- **lookup2:** add integration test

### Pull Requests
- Merge pull request [#192](https://github.com/Consensys/gnark/issues/192) from ConsenSys/multi-hint
- Merge pull request [#220](https://github.com/Consensys/gnark/issues/220) from ConsenSys/feat-from-interface
- Merge pull request [#217](https://github.com/Consensys/gnark/issues/217) from ConsenSys/fix-internal-compiled
- Merge pull request [#191](https://github.com/Consensys/gnark/issues/191) from ConsenSys/assert-subtests
- Merge pull request [#200](https://github.com/Consensys/gnark/issues/200) from ConsenSys/refactor/frontend
- Merge pull request [#205](https://github.com/Consensys/gnark/issues/205) from ConsenSys/fix/constant-mod-reduction
- Merge pull request [#186](https://github.com/Consensys/gnark/issues/186) from ConsenSys/fix/plonk_constraints
- Merge pull request [#185](https://github.com/Consensys/gnark/issues/185) from ConsenSys/feat/bw6-633
- Merge pull request [#189](https://github.com/Consensys/gnark/issues/189) from ConsenSys/lookup2
- Merge pull request [#183](https://github.com/Consensys/gnark/issues/183) from ivokub/hint-registry
- Merge pull request [#182](https://github.com/Consensys/gnark/issues/182) from ConsenSys/std/pairing
- Merge pull request [#176](https://github.com/Consensys/gnark/issues/176) from ConsenSys/feat-constraint-counter
- Merge pull request [#180](https://github.com/Consensys/gnark/issues/180) from ConsenSys/refactor-variable-interface
- Merge pull request [#173](https://github.com/Consensys/gnark/issues/173) from ConsenSys/feat-debug-tag
<a name="v0.5.2"></a>
## [v0.5.2] - 2021-11-03
### Build
- updated to gnark-crypto v0.5.3
- fix fuzz target compile error
- fix fuzz target compile error
- updated to latest gnark-crypto
- updated to latest gnark-crypto
- updated to gnark-crypto v0.5.2
- updated test timeout, while we improve plonk compile speeds
- fix staticcheck warning
- updated to latest gnark-crypto
- fix unchecked errors
- fix gofuzz target
- re-ran go generate
- fix gofuzz build
### Docs
- updated CHANGELOG.md for v0.5.2
- added pull requests in changelog.md
- added doc to frontend.API interface
- added documentation to new test pacakge
### Feat
- Sub matches Add api in circuit
- attempt at reducing nb constraints for ML by working in affine
- added frontend compile options to handle capacity and unconstrained inputs ignore flag
- added gcd for int64 coeff values in splitR1C, untested
- added test engine support for hints
- added UnsafeReadFrom for groth16 Proving and Verifying keys
- GetKey now returns an ID of a primitive linear expression
- added DivUnchecked. start factorizing some frontend.API with better Constant cases
- added post-compile check to ensure all inputs are constrained fixes [#163](https://github.com/Consensys/gnark/issues/163)
- ignore zero coefficients for variable constraint check
- added frontend.API interface
- added fuzzing. div now takes 2 constraints
- caching test srs for faster tests
- added TestableCircuit interface
- added debugInfo for ToBinary API
- unset variables error message comes with a stack trace
- frontend bits operation adjusted to fr.Bits real size
- ml with short addition chain (13245cs -> 12297, marginal gain)
- **std:** add bandersnatch
### Fix
- fixes [#155](https://github.com/Consensys/gnark/issues/155) slow compiling with plonk frontend
- don't check if one wire is constrained
- restore std/algebra/sw g1ScalarMul test circuit
- bug in Select when parameters are constant
- regenerated stats.
- remove unneeded mod operations in api
- fixed constraints blow up for plonk
- test engine mod reduce range check bound if not constant
- introduced bug in refactoring
- fix toHTML
- reduce duplicate when splitting r1c
- plonk build permutation index out of bounds
- std/twistededwards remove A
- std/twistededwards remove A
- added markBoolean on inplace boolean constraints to avoid duplicated constraints
### Perf
- fast path with int64 in divide linear expression
- cs.coeffID with gobencode
- fast path for coeffID when coeff is int64
- sparseR1CS reduce improvments
- plonk frontend split and reduce improvments
- plonk compile, replace sha256 with fast lookup with collisions
- minor perf adjustement on big.Int operations and allocations
- reduced redundant constraints in range check
### Refactor
- delete old curve typed hint functions
- hint function signature uses big.Int, no more ID from name
- splitBis -> split
- h and record are now part of scs
- moved testing in assert, code cleaning
- moved testing in assert, code cleaning
- reverted gnark to api in Define()
- all circuits use frontend.API in place of *frontend.ConstraintSystem
- in circuits *frontend.ConstraintSystem to frontend.API
- factorized assert helper accross curves and backends
### Style
- remove unused code (nSquare)
- removed commented code
- removed code for used for debugging purposes
- clean up std/algebra/g1
- removed useless lines in g1 Double
- clean up std/fp2
- use ecc.Info() where possible to get modulus or field size
- std/twisted edwards code cleaning
- std/fiat-shamir clean up
- cleaned up some TODO
- move stats tests in circuitstats_test.go
- remove plonk and groth16 assert.go
- added comment in range check
- remove code no longer used in the pairing
- commented ml test used to diplay nb constraints
### Test
- groth16 marshal 10 round only
- passing
- bypass fuzz test of frontend for now
### Tests
- added add and sub internal test circuits
- minor adjustements or better fuzzing

### Pull Requests
- Merge pull request [#159](https://github.com/Consensys/gnark/issues/159) from ConsenSys/std/bandersnatch
- Merge pull request [#164](https://github.com/Consensys/gnark/issues/164) from ConsenSys/perf-scs-compile
- Merge pull request [#161](https://github.com/Consensys/gnark/issues/161) from ConsenSys/test-engine-with-hints
- Merge pull request [#162](https://github.com/Consensys/gnark/issues/162) from ConsenSys/std/pairing
- Merge pull request [#160](https://github.com/Consensys/gnark/issues/160) from ConsenSys/perf-unsafe-decoding
- Merge pull request [#156](https://github.com/Consensys/gnark/issues/156) from ConsenSys/std/twistedEdwards
- Merge pull request [#151](https://github.com/Consensys/gnark/issues/151) from ConsenSys/testable-circuits
- Merge pull request [#153](https://github.com/Consensys/gnark/issues/153) from ConsenSys/fix/plonk_constraints_blowup
- Merge pull request [#146](https://github.com/Consensys/gnark/issues/146) from ConsenSys/feat/ml-snark-pairing
- Merge pull request [#148](https://github.com/Consensys/gnark/issues/148) from ConsenSys/perf-range-check
<a name="v0.5.1"></a>
## [v0.5.1] - 2021-09-21
### Build
- go mod tidy
- remove dead code, makes staticcheck happier
- comment fuzz test part that depends on assertions
- increased CI test timeout and run race test on ubuntu only
- fix gosec unhandled error warning
### Docs
- added release notes for v0.5.1 in CHANGELOG.md
### Feat
- added ToHTML on R1CS
- cs.Println and debugInfo supported in groth16 and plonk
- add witness reconstruction methods. closes [#135](https://github.com/Consensys/gnark/issues/135)
- added sanity check in frontend.Compile to ensure constraint validity
- add witness.WriteSequence to export expected witness sequence
- hintFunction now returns an error instead of panic
- added sanity checks in plonk solver
- plonk support for hints ok
- added Hints data struct in SparseR1CS
- added ToHTML on SparseR1CS
-  debugInfoComputation and debugInfoAssertion in a cs
- cs.Println now supports structures with Variables
- added assertions in ToHTML template
- debug info is displayed when div by 0 happens (Groth16 only)
- test circuit for AssertIsDifferent
- added skelleton for hintFunctions in r1cs
- IsZero is now implemented with 3 constraints fixes [#132](https://github.com/Consensys/gnark/issues/132)
- **frontend:** added cs.NewHint
- **groth16:** added dummyInifinty counts for dummySetup accurate sizes generation of pk
- **plonk:** isZero with advice wire OK, binaryDec NOK
- **r1cs:** replaced isZero solver path by solver hint
- **r1cs:** removed binaryDec solving method in favor of cs.NewHint
### Fix
- hint functions use compiled.Term instead of variable IDs only
- fix previous fix
- remove debug stack trace from frontend error
- ProvingKey marshaling test with infinity flags, fixes [#141](https://github.com/Consensys/gnark/issues/141)
- return empty slice when R1CS.Solve fails
- remove references to assertions in html templates
- sparseR1CS rebuilds hint map when deserializing
- ensure frontend.ConstraintSystem is not modified by compile process
- added Virtual variables to avoid creating wires for boolean constraints
- comment fuzz test
- fix serialization test. ensure we init hints when reading R1CS
- fixed error msg in Inverse, Div for groth16 fuzzer
- initialize InfinityX in dummy setup
- can constraint linear expressions to be boolean fixes [#136](https://github.com/Consensys/gnark/issues/136)
- BinaryDecomposition solving assumes bits are in L, which is fine
- removed fmt.Println trace in setup
- **eddsa:** addition of isOnCurve check
- **eddsa:** S not splitted (s<r) + 2,3 Double instead of [cofactor]G
- **groth16:** Prove with force flag wasn't doing much since msm had lots of zeroes in input
- **test:** integration test failing due to missing witness assignment
### Frontend
- **groth16:** ensure R (as in LRO) as less variables than L
### Perf
- **groth16:** filter wire values after solve in go routines
- **groth16:** filter A and B for infinity points
- **groth16:** use batch invert in groth16.Setup
### Refactor
- groth16.Prove and plonk.Prove takes backend.ProverOption as parameter
- save hints in a map in ConstraintSystem instead of slice
- factorized structs between compiled.SparseR1Cs and compiled.R1CS
- remove NbConstraints from R1CS
- move mHints to compiled R1CS and SparseR1CS
- factorize logging between R1CS and SparseR1CS
- separated hint functions in their own file
- factorizing code between R1CS and SparseR1CS
- introduced solution struct shared between R1CS and SparseR1CS
- remove assertions in Groth16 R1CS
- remove Assertions in compiled sparseR1CS
- removed r1c.SolvingMethod in favor of cs.NewHint
- moved assertions in cs_assertions.go
- cs.IsZero doesn't need curveID anymore
### Style
- printArg doesn't return error
- code cleaning in cs_to_r1cs_sparse.go
- fixed comment in popConstant
- cleaned eddsa
- in-place filtering of points in setup
- fixed comments on S in eddsa
- cleaned eddsa_test
### Test
- ensure frontend.Compile is deterministic
- added non regression for cs.Println and debugInfo traces
- integration test remove Public in favor of Good in test circuits
- replaced Fatal by Error in stat check test
- added circuit statistic non regression tests
- added plonk path to integration_test.go
- fix gofuzz compile error
- added test from [#136](https://github.com/Consensys/gnark/issues/136)

### Pull Requests
- Merge pull request [#142](https://github.com/Consensys/gnark/issues/142) from ConsenSys/frontend-println-tests
- Merge pull request [#139](https://github.com/Consensys/gnark/issues/139) from ConsenSys/cs-hint
- Merge pull request [#134](https://github.com/Consensys/gnark/issues/134) from ConsenSys/is-zero
- Merge pull request [#130](https://github.com/Consensys/gnark/issues/130) from ConsenSys/groth16-setup-filter-inf
- Merge pull request [#131](https://github.com/Consensys/gnark/issues/131) from ConsenSys/fix/i_128
- Merge pull request [#129](https://github.com/Consensys/gnark/issues/129) from ConsenSys/fix/reduce_constraints_eddsa
<a name="v0.5.0"></a>
## [v0.5.0] - 2021-08-23
### Build
- updated to latest gnark-crypto
- remove 32bit test for now, add timeout for github action
- updated to latest gnark-crypto. use ecc.NextPowerOfTwo
- updated to latest gnark-crypto
- add github CI action checks
- updated to latest gnark-crypto
- updated to msm-cpus branh of gnark-crypto
- updated to latest gnark-crypto
- updated to latest gnark-crypto
- updated to latest gnark crypto. fixes [#120](https://github.com/Consensys/gnark/issues/120)
- updated to latest gnark-crypto
- updated to latest gnark-crypto
- run go mod tidy
- updated to gnark-crypto v0.5.0
- make gosec happy by handling un-handled errors
- run go generate
- updated to latest gnark-crypto
- restored gnark-crypto version
- updated to latest gnark-crypto. kzg api refactor
- updated to latest gnark-crypto
- updated to latest gnark-crypto. plonk Setup now takes kzg SRS, and re-uses fft domain
- updated to latest gnark-crypto
- ran go:generate for bls24 after merging develop into sself
- ran go:generate for bls24-315 plonk marshal
- re-ran go:generate
- **staticheck:** commented debugInfoUnsetVariable
### CI
- added -mod=mod fix, maybe?
- replace go test sum by go test, CI check
### Chore
- cleaned plonk bn254, removed old version
### Clean
- cosmetics in plonk.Verify
### Cleanup
- removed to_delete.go file
### Docs
- fix go report card link
- prepare release notes for v0.5.0
- fix go report card link
- updated doc link and logo on README.md
### Feat
- plonk as-in-the-paper implem for bn254
- LinearExpression implements Sort interface. replaced quickSort() by sort.Sort(...)
- remove term.CoeffValue and use constant coeff ID for special values instead
- addition of circuit to test determinism
- update gnark-crypto[@feat](https://github.com/feat)/kzg/multi_points
- addition of FiatShamir in std
- updated go.mod
- modified example/benchmark with setup and run options
- updated go.sum, use of external hash function in plonk
- plonk verifier uses kzg BatchVerifyMultiPoints
- remove serialization test by default in assert helper
- replaced individual ScalarMul by MultiExp in plonk.Verify
- addition of unit test for cyclo square in std/../e12.go
- add bls24-315 to gnark
- added example for plonk (exponentiate circuit)
- added NewCS and NewPublicData on plonk package, with io.ReaderFrom and io.WriterTo unimplemented interfaces
- blind of a, b, c OK for bn254
- added reference benchmarks for plonk
- added NbG1 and NbG2 apis on groth16 Proving and Verifying keys closes [#116](https://github.com/Consensys/gnark/issues/116)
- call stack displayed when AssertIsEqual fails
- gnarkd circuit data structure extension to support both groth16 and plonk
- added PublicRaw marhsal methods, ignoring KZG for now
- added WriteTo and ReadFrom to SparseR1CS objects
- added Neg on frontend API, cleaned Neg in twistededwards
- official implem of plonk, verifier in progress
- moving to strongly typed kzg
- **plonk:** code gen, started modifying backend interfaces
- **plonk:** added convenient method to create a kzg SRS from a compiled constraint system
- **plonk:** setup check srs size against fft domain cardinality
- **plonk:** added VerifyingKey serialization
- **plonk:** added VerifyingKey serialization with test
- **plonk:** added ProvingKey serialization
- **plonk:** modified folded commitment of h
- **plonk:** blinded z, modified test circuits to have nbConstraints>8
- **plonk:** code gen for proof blinding
- **plonk:** added ProvingKey serialization test
- **plonk:** added InitKZG methods on ProvingKey and VerifyingKey
### Fix
- fixed gnarkd tests for kzg srs
- shuffleVariables in fuzz testing with bad offset
- restore benchmark/main.go
- don't close channels that are use in the select as they become always ready to receive
- groth16 prove missing chan close in one path
- groth16.Prove handles multiExp error returns
- fixed conflicts
- fixed conflicts
- restored benchmark/main.go
- avoid code gen for bw633 until feat/bw633 is merged
- invalid gnark struct tag options return error at compile time fixes [#111](https://github.com/Consensys/gnark/issues/111)
- kzg srs size +3
- r1cs compilation is deterministic, fixes [#90](https://github.com/Consensys/gnark/issues/90)
- fixes [#112](https://github.com/Consensys/gnark/issues/112)
- removed unused error variable
- make go vet happy
- use of doubling formula instead of add(x,x) fixes [#114](https://github.com/Consensys/gnark/issues/114)
- updated go.mod
- go.mod points to gnark-crypto[@develop](https://github.com/develop), fixes [#96](https://github.com/Consensys/gnark/issues/96)
- SetupDummyCommitment calls with Proving and Verifying key in return
- added BLS24_315 in plonk constructors
- backend plonk bls24 process error
- create cbor decoder with MaxArrayElements set to max value
- regenerated code
- **frontend:** restored isBoolean logic to avoid dupplicate constraints. remove dangling variable thing
- **frontend:** set initial capacity for constraint system slices to 0
- **gnarkd:** kzg srs generation in test cases with correct size
- **plonk:** fixed error in ComputeH  when nbConstraints+nbPublicInputs<6
### Perf
- start computeZ earlier
- plonk prove remove most fft.BitReverse
- replaced string concat in frontend with strings.Builder
- remove clone in computeLinearizedPoly
- minor optim
- use batch inversion in plonk.computeZ
- plonk.computeLinearizedPolynomial with less polynomial clones
- improving parallelism in prover
- minor change
- make constraint slice initalCapacity an optional paremeter in compile
- plonk frontend replace map by slice, avoid few allocs and useless slice copies
- frontend.ConstraintSystem special values fast path for coefficients
- plonk frontend fast path for -1, 0 and 1 as coeffs
- reduced memory allocations in plonk frontend
- evalIDCosets shiftEval done in parallel, better trace
- shiftZ in parallel with other stuff
- remove useless copy in computeH
- sparseR1CS.Solve few times faster by avoiding Div at constraint solving
- hunting memallocs - remove evaluid and uuid in evalConstraint
- blinded polynomials re-use input polynomial memory
- remove polynomial clone in foldedH computation
- remove bitReverse in evalIDCosets
- use ecc.CPUSemaphore in kzg.Commit to ensure pretty trace
- remove one additional plynomoial clone
- parralelize computeH
- **experimental:** start too many go routines in Prover
- **frontend:** rewrote linear expression reduce in place instead of multiple map allocs
- **frontend:** minor adjustements
- **frontend:** rewrote cs.ToBinary to avoid unecessary func calls
- **plonk:** shiftEval done without copy or bitReverse
- **plonk:** compute shifted Z element on the fly without allocating a new polynomial
- **plonk:** partly parallel computeBlindedZ
- **plonk:** when doing fft on domainH with coset, don't scale zero values
- **plonk:** minor tweaks, removing un-needed bitreverse and mem allocs
- **scs:** rewrote solve O
- **scs:** sparse r1cs have fast path for special coeffs operations
- **std:** adds E2/E12 square and cyclo square in E12 (used FinalExp)
### Refactor
- removed gnarkd and examples/benchmark
- mimc uses Write(data) then Sum() instead of Sum(data)
- Hash-->Sum in mimc gadget
- added deriveRandomness utility func in plonk verifier
- strongly typed KZG, Plonk test passing
- renamed Groth16 protobuf service to ZKSnark
- **groth16:** SizePublicWitness to NbPublicWitness
### Style
- cleaning plonk.prove
- renamed GetCurveID() to CurveID() on groth16 objects
- minor change
- more cleaning in cs_to_r1cs_sparse.go
- start clean up cs_to_r1cs_sparse.go
- replaced very long suite of if else by switch
- remove Bis suffixes in plonk prover
- moved derivedrandomness
- cleaning plonk APIs
- go fmt
- modified comment on reduce
- **kzg:** factorized some methods in the prover
- **plonk:** use close(chan) instead of send twice on it
### Test
- test for Fiat Shamir gadget
- added reference frontend.Compile benchmarks
- fix circuitID path
- **gnarkd:** plonk end to end pass
- **gnarkd:** gRPC test run in parallel w multiple curves

### Pull Requests
- Merge pull request [#126](https://github.com/Consensys/gnark/issues/126) from ConsenSys/develop
- Merge pull request [#124](https://github.com/Consensys/gnark/issues/124) from ConsenSys/groth16-stats-pk-vk
- Merge pull request [#113](https://github.com/Consensys/gnark/issues/113) from ConsenSys/feat/gnarkd/plonk
- Merge pull request [#117](https://github.com/Consensys/gnark/issues/117) from ConsenSys/perf/recursive-proof
- Merge pull request [#108](https://github.com/Consensys/gnark/issues/108) from ConsenSys/feat/plonk/clean_verifier
- Merge pull request [#104](https://github.com/Consensys/gnark/issues/104) from ConsenSys/bls24-315
- Merge pull request [#95](https://github.com/Consensys/gnark/issues/95) from ConsenSys/fix/deterministic_r1cs
<a name="v0.4.0"></a>
## [v0.4.0] - 2021-04-29
### Build
- updated gnark-crypto in go.mod
- updated to latest bavard and gnark-crypto
- updated to latest gnark-crypto
- moved solidity integration tests in github.com/consensys/gnark-tests
- updated .gitignore
- added .gitlint file
### CI
- added integration fuzz test in backend/groth16/fuzz_test.go
### Docs
- preparing v0.4.0 release with new README.md and CHANGELOG.md
- added comments for the splitting of S in eddsa
- updated package level godoc
- fixed comments on wire ordering for sparse r1cs
- **plonk:** fixed doc for computeH
- fixed typo ([#63](https://github.com/Consensys/gnark/issues/63)) in README.md
### Eddsa
- bw761 blinding factor and private key size are consistant with the field size
### Feat
- added funcitons for proving PLONK's claim 1 (bn256), not tested
- mock polynomial commitments for all curves + templates
- added code gen for placeholder feature
- added Fiat Shamir for plonk
- added intefaces for polynomial commitments
- updated go.mod (points to gnark-crypto[@hotfix](https://github.com/hotfix)/issue_36)
- support for batch proofs opening at single point
- **fft:** fft/fftInv now works on abitrary cosets (bounded by maxOrder)
- **gnarkd:** exposing gnark APIs through RPCs ([#54](https://github.com/Consensys/gnark/issues/54))
- **gnarkd:** added optional TTL in CreateProveJobRequest
- **gnarkd:** added CancelProveJob method
- **gnarkd:** added ListProveJob method
- **plonk:** addition of placeholders to handle public inputs
- **plonk:** proof that Z starts at 1 done, tests ok (bn256)
- **plonk:** added commitments verification in plonk's verifier
- **plonk:** plonk tests are now executed via generic code in assert
- **plonk:** proof of permutation done (bn256), tests ok
- **plonk:** templates for plonk setup/prove/verify
- **plonk:** permutation proof part implemented, to be tested
- **plonk:** claim 1 of plonk prover works correctly(bn256)
- **plonk:** templates for testing prover (to be moved to backend/plonk)
- **plonk:** addition of templates + code gen for computing Z
- **plonk:** applying previous commit on all curves with code gen
- **plonk:** code gen for the previous fix
- **plonk:** addition of plonk generic code in backend/
- **plonk:** addition of the permutation in the setup
- **plonk:** H is split as h1+X**m*h2+X**2m*h3
- **plonk:** polynomial accumulating partial permutation OK (bn256)
- **plonk cs:** adding functionality to convert a constraint system to PLONK constraints ([#56](https://github.com/Consensys/gnark/issues/56))
### Fix
- cs.Println doesn't trigger panic anymore
- fixed Groth16 snark circuit according to previous commit
- inverse and div in frontend had some variable ID offset issues ([#62](https://github.com/Consensys/gnark/issues/62))
- fixed snark circuit for bls377 pairing
- removed dead function (getOneWire) in cs.go
- fixes [#88](https://github.com/Consensys/gnark/issues/88)
- go mod update + fix bad import path with gofuzz build tag
- bn256 -> bn254
- updated go.mod to latest gnark-crypto on develop
- r1cs serialization test doesn't need to check logger io.Writer output
- ensure that L.id=M[0].id and R.id=M[1].id in a sparse_r1c
- added go.sum
- removed unreachable code piece
- typo in readme.md fixes [#60](https://github.com/Consensys/gnark/issues/60)
- **fft:** fixed the ordering of cosets factor according to DIF/DIT
- **gnarkd:** ListProveJob test didn't account for other test adding jobs to the queue
- **plonk:** removed useless multiplication by L in the prover
- **plonk:** fixed size of permutation, it's now a power of 2
- **plonk:** fixed formula for Li->Li+1 in verify ... (bn256)
- **r1cs:** TestSerialization running sequentially
- **r1cs:** moved bytes.Buffer in t.Run (TestSerialization)
- **r1cs_sparse:** ensure that Solve never returns nil, err
### Groth16
- VerifyingKey data structure change to ensure compatibility with other impl and Solidity in Ethereum. Serialization format change.
### Integration_test
- added witness serialization tests
### Refactor
- gurvy -> gnark-crypto
- use gnark-crypto polynomial and accumulator packages
- bls381 -> bls12381
- bls377 -> bls12377
- templates for groth16 are in a dedicated folder
- moved crypto/utils in frontend/, for now
- bw761 -> bw6761
- bn256 -> bn254, bls377 -> bls12-377, etc. following gnark-crypto v0.4.0
- bn256 -> bn254
- first step for gurvy -> gnark-crypto
- removed the Curve field in the R part of eddsa signature
- verification of openings return an error instead of bool
- removed challenge for batch opening/verifying poly commit
- claimed value is inside an opening proof
- added method ClaimedValue on Proof interface
- **fft:** nbCosets --> Depth, easier for interpreting cosets
- **plonk:** lrozh (in the proof) are now in a single slice
- **plonk:** challenges are built in init() until Fiat Shamir
- **plonk:** suffix raw added to plonk API
- **plonk:** setup, prove, verify take frontend.Circuit as witness
- **plonk:** prove, verifiy now return error
### Style
- simplified findUnsolvedVariable in SparseR1CS
- untrack to_delete_bn256.go (used for printing stuff)
- removed comments of the previous fft in groth16 prove
- **plonk:** removed comments (used for testing) in setup
### Test
- added frontend and backend fuzz.go, go-fuzz compatible format
- added cs.Println must not panic base test

### Pull Requests
- Merge pull request [#94](https://github.com/Consensys/gnark/issues/94) from ConsenSys/develop
- Merge pull request [#93](https://github.com/Consensys/gnark/issues/93) from ConsenSys/hotfix/fft_groth16
- Merge pull request [#92](https://github.com/Consensys/gnark/issues/92) from ConsenSys/feat/fiat_shamir
- Merge pull request [#89](https://github.com/Consensys/gnark/issues/89) from ConsenSys/fix/eddsa
- Merge pull request [#86](https://github.com/Consensys/gnark/issues/86) from ConsenSys/docs/godoc
- Merge pull request [#65](https://github.com/Consensys/gnark/issues/65) from ConsenSys/refactor/gnark-crypto
- Merge pull request [#64](https://github.com/Consensys/gnark/issues/64) from ConsenSys/feat/plonk_prover
- Merge pull request [#58](https://github.com/Consensys/gnark/issues/58) from ConsenSys/feat/fft_cosets
- Merge pull request [#57](https://github.com/Consensys/gnark/issues/57) from ConsenSys/feature/gnarkd
- Merge pull request [#53](https://github.com/Consensys/gnark/issues/53) from ConsenSys/serialization/witness
- Merge pull request [#51](https://github.com/Consensys/gnark/issues/51) from ConsenSys/eddsa_cleanup
- Merge pull request [#46](https://github.com/Consensys/gnark/issues/46) from ConsenSys/experimental/solidity
- Merge pull request [#48](https://github.com/Consensys/gnark/issues/48) from ConsenSys/issue_45
<a name="v0.3.8"></a>
## [v0.3.8] - 2020-12-23
<a name="v0.3.7"></a>
## [v0.3.7] - 2020-12-22
<a name="v0.3.6"></a>
## [v0.3.6] - 2020-12-22
### Features
- **profiling:** Adds a way to print the number of constraints in the circuit
### Fix
- **typo:** insertion -> assertion
### R1cs
- implemented serialization interfaces
### Serialization
- using gurvy.Encoder and gurvy.Decoder. Added benchmark and assert helpers
- added proving key
- added for fft domain
- replaced some int by uint64 to avoid ambiguity in serialization protocols
- gnark object implement io.ReaderFrom and io.WriterTo
### Wip
- updating to latest gurvy

### Pull Requests
- Merge pull request [#42](https://github.com/Consensys/gnark/issues/42) from ConsenSys/linearexp
- Merge pull request [#41](https://github.com/Consensys/gnark/issues/41) from AlexandreBelling/feature/cs-nb-constraints
- Merge pull request [#38](https://github.com/Consensys/gnark/issues/38) from ConsenSys/hotfix/discard_secret
<a name="v0.3.5"></a>
## [v0.3.5] - 2020-10-19
<a name="v0.3.4"></a>
## [v0.3.4] - 2020-10-19
<a name="v0.3.3"></a>
## [v0.3.3] - 2020-09-23
<a name="v0.3.1"></a>
## [v0.3.1] - 2020-09-22
<a name="v0.3.0"></a>
## [v0.3.0] - 2020-09-22
<a name="v0.3.0-alpha"></a>
## [v0.3.0-alpha] - 2020-09-15
### Backend
- interface to big.Int added minimalist test
- moved  generated curve specific backends into internal to forbid library user to directly import it
### Backends
- restored bw761 groth16 code generation path
### Circleci
- added step to ensure no generated files are modified by hand
- change cache key
- new workflow with more insight on unit tests
### Encoding
- switch from gob to cbor
### Frontend
- remove Context object, mostly used as a curve.ID wrapper
- added frontend.Compile benchmark for reference in further modifications
- allocate slice capacity when known
- added Circuit and CircuitVariable interfaces. Can now assign values with compiler check (no more strings). Rollup tests OK
### Gnark
- fixing few staticcheck warnings
- input file is now json. accepts 0x hex and decimal repr for assignment to a circuit
### Groth16
- updated to latest gurvy and added go routines in prover workflow. WIP need to be benchmarked
- reorganize Setup to use gurvy.BatchScalarMultiplication api
- prover, removed appends in prover that resulted in array copies
- added test for reference circuit (non short path)
- restored reference circuit for benchmarking purposes
- fix possible starvation issue in Prover -- there existed a world were go routine may wait for ever for the tokenn causing a timeout in tests
### R1cs
- added GetNbCoefficients and GetNbWires to interface
- Solve takes typed arguments
### Refactor
- remove Gadget suffix from many structs
- checkpoint
### Wip
- investigating millerloop result in snark circuit
- frontend.NewConstraintSystem is now private. ToR1CS() is private. test circuits moved to internal. gadgets and test circuits use frontend.Compile()

### Pull Requests
- Merge pull request [#26](https://github.com/Consensys/gnark/issues/26) from ConsenSys/gadget_cleanup
- Merge pull request [#23](https://github.com/Consensys/gnark/issues/23) from ConsenSys/tagless_refactor
<a name="v0.2.1-alpha"></a>
## [v0.2.1-alpha] - 2020-06-18
<a name="v0.2.0-alpha"></a>
## [v0.2.0-alpha] - 2020-06-05
### Backend
- cleaned asserts
- generating backend/static/CURVE submodules from same template
- remove curve generated code, keep only build tag version
### Circleci
- added missing goimports indirect dependency
- run go generate to ensure repo consistency in CI
- test full repo with each build tag
### Cmd
- removed wip export command for now
### Examples
- back at root of repo
### Frontend
- fixed division-by-constant constraint
### Gnark
- integration test now uses test circuits defined in internal/tests/circuits
### Groth16
- fix reference to large reference test circuit in groth16
- remove assertion when checking number of inputs and fix missing curve in testdata path
- add point check infinity in assert
- VerifyingKey stores K in Affine, not Jacobian. Fixes [#18](https://github.com/Consensys/gnark/issues/18)
### Integration_test
- be nice with circleci, do not add large circuit into integration test
### Refactor
- separated frontend and backend, code generate typed backend and tests for groth16. yes that's a big commit
### Templates
- minor code cleaning
### WIP
- using big.Int in frontend to avoid build tags

### Pull Requests
- Merge pull request [#22](https://github.com/Consensys/gnark/issues/22) from ConsenSys/refactor
- Merge pull request [#21](https://github.com/Consensys/gnark/issues/21) from Mikerah/patch-1
<a name="v0.1.0-alpha"></a>
## v0.1.0-alpha - 2020-03-06

### Pull Requests
- Merge pull request [#11](https://github.com/Consensys/gnark/issues/11) from nkeywal/exGadget
- Merge pull request [#8](https://github.com/Consensys/gnark/issues/8) from ConsenSys/internal-curve-tests
- Merge pull request [#7](https://github.com/Consensys/gnark/issues/7) from ConsenSys/develop Fixed [#6](https://github.com/Consensys/gnark/issues/6)
- Merge pull request [#5](https://github.com/Consensys/gnark/issues/5) from ConsenSys/go1.14_deps
[v0.16.3]: https://github.com/Consensys/gnark/compare/v0.16.2...v0.16.3
[v0.16.2]: https://github.com/Consensys/gnark/compare/v0.16.1...v0.16.2
[v0.16.1]: https://github.com/Consensys/gnark/compare/v0.16.0...v0.16.1
[v0.16.0]: https://github.com/Consensys/gnark/compare/v0.15.0...v0.16.0
[v0.15.0]: https://github.com/Consensys/gnark/compare/v0.14.0...v0.15.0
[v0.14.0]: https://github.com/Consensys/gnark/compare/v0.13.0...v0.14.0
[v0.13.0]: https://github.com/Consensys/gnark/compare/v0.12.0...v0.13.0
[v0.12.0]: https://github.com/Consensys/gnark/compare/v0.11.0...v0.12.0
[v0.11.0]: https://github.com/Consensys/gnark/compare/v0.10.0...v0.11.0
[v0.10.0]: https://github.com/Consensys/gnark/compare/v0.9.1...v0.10.0
[v0.9.1]: https://github.com/Consensys/gnark/compare/v0.9.0...v0.9.1
[v0.9.0]: https://github.com/Consensys/gnark/compare/v0.9.0-alpha...v0.9.0
[v0.9.0-alpha]: https://github.com/Consensys/gnark/compare/v0.8.1...v0.9.0-alpha
[v0.8.1]: https://github.com/Consensys/gnark/compare/v0.8.0...v0.8.1
[v0.8.0]: https://github.com/Consensys/gnark/compare/v0.7.1...v0.8.0
[v0.7.1]: https://github.com/Consensys/gnark/compare/v0.7.0...v0.7.1
[v0.7.0]: https://github.com/Consensys/gnark/compare/v0.6.5...v0.7.0
[v0.6.5]: https://github.com/Consensys/gnark/compare/v0.6.4...v0.6.5
[v0.6.4]: https://github.com/Consensys/gnark/compare/v0.6.3...v0.6.4
[v0.6.3]: https://github.com/Consensys/gnark/compare/v0.6.2...v0.6.3
[v0.6.2]: https://github.com/Consensys/gnark/compare/v0.6.1...v0.6.2
[v0.6.1]: https://github.com/Consensys/gnark/compare/v0.6.0...v0.6.1
[v0.6.0]: https://github.com/Consensys/gnark/compare/v0.5.2...v0.6.0
[v0.5.2]: https://github.com/Consensys/gnark/compare/v0.5.1...v0.5.2
[v0.5.1]: https://github.com/Consensys/gnark/compare/v0.5.0...v0.5.1
[v0.5.0]: https://github.com/Consensys/gnark/compare/v0.4.0...v0.5.0
[v0.4.0]: https://github.com/Consensys/gnark/compare/v0.3.8...v0.4.0
[v0.3.8]: https://github.com/Consensys/gnark/compare/v0.3.7...v0.3.8
[v0.3.7]: https://github.com/Consensys/gnark/compare/v0.3.6...v0.3.7
[v0.3.6]: https://github.com/Consensys/gnark/compare/v0.3.5...v0.3.6
[v0.3.5]: https://github.com/Consensys/gnark/compare/v0.3.4...v0.3.5
[v0.3.4]: https://github.com/Consensys/gnark/compare/v0.3.3...v0.3.4
[v0.3.3]: https://github.com/Consensys/gnark/compare/v0.3.1...v0.3.3
[v0.3.1]: https://github.com/Consensys/gnark/compare/v0.3.0...v0.3.1
[v0.3.0]: https://github.com/Consensys/gnark/compare/v0.3.0-alpha...v0.3.0
[v0.3.0-alpha]: https://github.com/Consensys/gnark/compare/v0.2.1-alpha...v0.3.0-alpha
[v0.2.1-alpha]: https://github.com/Consensys/gnark/compare/v0.2.0-alpha...v0.2.1-alpha
[v0.2.0-alpha]: https://github.com/Consensys/gnark/compare/v0.1.0-alpha...v0.2.0-alpha

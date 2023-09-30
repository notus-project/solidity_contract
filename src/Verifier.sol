// SPDX-License-Identifier: AML
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

// 2019 OKIMS

pragma solidity ^0.8.17;

import "./Pairing.sol";
import "./BigNumbers.sol";

contract Verifier {
    using Pairing for *;
    using BigNumbers for *;

    uint256 constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant PRIME_Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct VerifyingKey {
        Pairing.G1Point alfa1;
        Pairing.G2Point beta2;
        Pairing.G2Point gamma2;
        Pairing.G2Point delta2;
        Pairing.G1Point[8] IC;
    }

    struct Proof {
        Pairing.G1Point A;
        Pairing.G2Point B;
        Pairing.G1Point C;
    }

    function verifyingKey() internal pure returns (VerifyingKey memory vk) {
        vk.alfa1 = Pairing.G1Point(
            uint256(
                4002454945995142310093457620111641427869597062862299568146064957055735117280
            ),
            uint256(
                7945921591083723297698687967525175667061174038761655595508781672546661960109
            )
        );
        vk.beta2 = Pairing.G2Point(
            [
                uint256(
                    18276443434917879997883875923943598161759605712772776336865433443136080460132
                ),
                uint256(
                    19297489925081955574465749979642968101472022360878075159600768699751781464815
                )
            ],
            [
                uint256(
                    16122792022462824330584111185938803331597233324551638120553554884796471050829
                ),
                uint256(
                    7599712081412665010857608421177978008703710504431406094414163528060020461421
                )
            ]
        );
        vk.gamma2 = Pairing.G2Point(
            [
                uint256(
                    19456301773958018890848016251545423414128560603475076394615933417299564314776
                ),
                uint256(
                    8049143193851922776486690065551948744820386138299019556509347486301821342653
                )
            ],
            [
                uint256(
                    20918036918147128188304236096773331398876610365884830445889841216450430583845
                ),
                uint256(
                    7337245945886350026818915603683742228493213372325681794600518969804398859926
                )
            ]
        );
        vk.delta2 = Pairing.G2Point(
            [
                uint256(
                    21155349094279722810465579021029162492494888937711377952264314345335941287315
                ),
                uint256(
                    514923321438828581566859443049552514291396989804519985343881118170944277330
                )
            ],
            [
                uint256(
                    6940258564247862593899313702031908617611008309660218338749956339500052104339
                ),
                uint256(
                    10648720158330591193959377135107166592873729644844905608546017365982961153949
                )
            ]
        );
        vk.IC[0] = Pairing.G1Point(
            uint256(
                1481518090649929432092124431370652774626200268919967114653357087635500949287
            ),
            uint256(
                17051994505882933681620942657153977542507609339919021292658121964031574429607
            )
        );
        vk.IC[1] = Pairing.G1Point(
            uint256(
                13907527130918668912782521378963008755675507551477939287183915134427570653660
            ),
            uint256(
                18036517493280684994086422472836684574958522046082104706191767971772588653414
            )
        );
        vk.IC[2] = Pairing.G1Point(
            uint256(
                12024878971219924596126167470912164126069571470920303836981484077735740045808
            ),
            uint256(
                12088532900345917689372970084382914967376381683133843567036433805021059831782
            )
        );
        vk.IC[3] = Pairing.G1Point(
            uint256(
                18636548249513754170037480213561800274730274480431671474510506775565820670538
            ),
            uint256(
                484862457012831091000783580971633664837980608891731523078317918087979015627
            )
        );
        vk.IC[4] = Pairing.G1Point(
            uint256(
                12854380827072509998894453778511927881740702346601022548753656112883525949779
            ),
            uint256(
                21016659594031436027610734629912485368654520267464487058274396512796059069605
            )
        );
        vk.IC[5] = Pairing.G1Point(
            uint256(
                4544019347201695882789396639027859595936136516099841711754648249115364055017
            ),
            uint256(
                9132001756003505846917719392050459738388935268423112173203455225850718409826
            )
        );
        vk.IC[6] = Pairing.G1Point(
            uint256(
                2707284442813110789542002829754932878085381333155093435984816354338373747733
            ),
            uint256(
                9985794599114598976150761017422279321926833732396436356012891646240264175081
            )
        );
        vk.IC[7] = Pairing.G1Point(
            uint256(
                19216498579120724438395752292152035023946521488253681705256787857670741034254
            ),
            uint256(
                15442461392939439298422570900746792941640606215207840357965496110782956288763
            )
        );
    }

    /*
     * @returns Whether the proof is valid given the hardcoded verifying key
     *          above and the public inputs
     */
    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[7] memory input
    ) public view returns (bool r) {
        Proof memory proof;
        proof.A = Pairing.G1Point(a[0], a[1]);
        proof.B = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.C = Pairing.G1Point(c[0], c[1]);

        VerifyingKey memory vk = verifyingKey();

        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);

        // Make sure that proof.A, B, and C are each less than the prime q
        require(proof.A.X < PRIME_Q, "verifier-aX-gte-prime-q");
        require(proof.A.Y < PRIME_Q, "verifier-aY-gte-prime-q");

        require(proof.B.X[0] < PRIME_Q, "verifier-bX0-gte-prime-q");
        require(proof.B.Y[0] < PRIME_Q, "verifier-bY0-gte-prime-q");

        require(proof.B.X[1] < PRIME_Q, "verifier-bX1-gte-prime-q");
        require(proof.B.Y[1] < PRIME_Q, "verifier-bY1-gte-prime-q");

        require(proof.C.X < PRIME_Q, "verifier-cX-gte-prime-q");
        require(proof.C.Y < PRIME_Q, "verifier-cY-gte-prime-q");

        // Make sure that every input is less than the snark scalar field
        for (uint256 i = 0; i < input.length; i++) {
            require(
                input[i] < SNARK_SCALAR_FIELD,
                "verifier-gte-snark-scalar-field"
            );
            vk_x = Pairing.plus(
                vk_x,
                Pairing.scalar_mul(vk.IC[i + 1], input[i])
            );
        }

        vk_x = Pairing.plus(vk_x, vk.IC[0]);

        return
            Pairing.pairing(
                Pairing.negate(proof.A),
                proof.B,
                vk.alfa1,
                vk.beta2,
                vk_x,
                vk.gamma2,
                proof.C,
                vk.delta2
            );
    }

    /*
     * Check if q^l * g^r mod n == acc
     */
    // function verifyExp(
    //     BigNumber memory q,
    //     BigNumber memory l,
    //     BigNumber memory g,
    //     BigNumber memory r,
    //     BigNumber memory acc,
    //     BigNumber memory n
    // ) public view returns (bool isExpValid) {
    //     BigNumber memory left = q.modexp(l, n).modmul(g.modexp(r, n), n);
    //     BigNumber memory right = acc;
    //     return left.eq(right);
    // }
    function verifyExp(
        bytes memory q,
        bytes memory l,
        bytes memory g,
        bytes memory r,
        bytes memory acc,
        bytes memory n
    ) public view returns (bool) {
        BigNumber memory bigQ = BigNumbers.init(q, false);
        BigNumber memory bigL = BigNumbers.init(l, false);
        BigNumber memory bigG = BigNumbers.init(g, false);
        BigNumber memory bigR = BigNumbers.init(r, false);
        BigNumber memory bigAcc = BigNumbers.init(acc, false);
        BigNumber memory bigN = BigNumbers.init(n, false);
        BigNumber memory left = BigNumbers.modexp(bigQ, bigL, bigN);
        left = BigNumbers.modmul(
            left,
            BigNumbers.modexp(bigG, bigR, bigN),
            bigN
        );
        BigNumber memory right = BigNumbers.mod(bigAcc, bigN);
        return BigNumbers.eq(left, right);
    }
}

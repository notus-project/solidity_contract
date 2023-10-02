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
                11460788318663872288332080909120039512671561465486145154732447000153019562663
            ),
            uint256(
                6042172821563996358814229983031228474168109856915046669932603707896647602961
            )
        );
        vk.beta2 = Pairing.G2Point(
            [
                uint256(
                    19771390413774882314907644004626994554839733954634516347153406244599427669987
                ),
                uint256(
                    16572403825201975497743811365792296350192905464638051625257533911006061624886
                )
            ],
            [
                uint256(
                    14653738967017037208569618612971070349090695585049401089663549389372834984612
                ),
                uint256(
                    4504997239064181931385376842182186874922114470487162482010690993447764827277
                )
            ]
        );
        vk.gamma2 = Pairing.G2Point(
            [
                uint256(
                    7749296602456844703318638559408021946138200863569600436931930157262223909606
                ),
                uint256(
                    7616089433139718685243898981811220786562334844959836695062852550219304249969
                )
            ],
            [
                uint256(
                    11026794782568873782034314080314344871362105556102521042064859311266237283210
                ),
                uint256(
                    12573106918424627017902674665429024319389341177830590621015226277450639987978
                )
            ]
        );
        vk.delta2 = Pairing.G2Point(
            [
                uint256(
                    15474866171569184899729297975596894503683660434410163062295009452592894320426
                ),
                uint256(
                    5902242973419922751200631072599212149633475929764045999574281712782706335404
                )
            ],
            [
                uint256(
                    4407981917883476415379748121319587735211358359619314558771899831846518689889
                ),
                uint256(
                    11518310447014692502462292765169354431448812113373054609201876039814678331511
                )
            ]
        );
        vk.IC[0] = Pairing.G1Point(
            uint256(
                6319551697037067644097036242903236429991102558458957061413791727422156086463
            ),
            uint256(
                765479346855466031267723247645678061535196986300819168406807813743257805925
            )
        );
        vk.IC[1] = Pairing.G1Point(
            uint256(
                20206260828118814960836471210872076087454713805304507717376738491925169137789
            ),
            uint256(
                20984844416863624722327112311028234901099257816351887540721621659304474791778
            )
        );
        vk.IC[2] = Pairing.G1Point(
            uint256(
                21288426163204857305515895242121886029660388088043299305734503463470084127552
            ),
            uint256(
                12749125030661830524178606310253686705921639563436707568787205023479408842753
            )
        );
        vk.IC[3] = Pairing.G1Point(
            uint256(
                19086047988674808304034573887757560111167381219245943550896784171674746605473
            ),
            uint256(
                11343753409487642173532197912049391944461273410276252349386475344073112442342
            )
        );
        vk.IC[4] = Pairing.G1Point(
            uint256(
                408949343485575747416729573561328452135138763794829489161651377124921237486
            ),
            uint256(
                20511171418139002014632318213633318897469348162236664707687233000417853737332
            )
        );
        vk.IC[5] = Pairing.G1Point(
            uint256(
                14041337247683887173447835606730016294838684608794650565315162166759168598679
            ),
            uint256(
                11374039012179830387744741796509431654763760940624567920831351260842872157297
            )
        );
        vk.IC[6] = Pairing.G1Point(
            uint256(
                14406854369631936592245031690173511596955564740176871110245014138148850822173
            ),
            uint256(
                5694755419877286641017212523578462915658831071663640129064783725116097898178
            )
        );
        vk.IC[7] = Pairing.G1Point(
            uint256(
                4638943817097147500036042852497838079011712889338272903467842009761825249838
            ),
            uint256(
                10419703510208103857658913427226719526062816327177852227264733023819171134817
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

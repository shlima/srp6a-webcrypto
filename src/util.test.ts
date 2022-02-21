import {Hash, Uint8ArrayFromHex} from "./util";

describe('Uint8ArrayFromHex', () => {
    const input = `
EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C
9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4
8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29
7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A
FD5138FE 8376435B 9FC61D2F C0EB06E3`

    const expected = new Uint8Array([
        238, 175, 10, 185, 173, 179, 141, 214, 156, 51, 248, 10, 250, 143, 197, 232, 96, 114, 97, 135, 117, 255, 60, 11, 158, 162, 49, 76, 156, 37, 101, 118, 214, 116, 223, 116, 150, 234, 129, 211, 56, 59, 72, 19, 214, 146, 198, 224, 224, 213, 216, 226, 80, 185, 139, 228, 142, 73, 92, 29, 96, 137, 218, 209, 93, 199, 215, 180, 97, 84, 214, 182, 206, 142, 244, 173, 105, 177, 93, 73, 130, 85, 155, 41, 123, 207, 24, 133, 197, 41, 245, 102, 102, 14, 87, 236, 104, 237, 188, 60, 5, 114, 108, 192, 47, 212, 203, 244, 151, 110, 170, 154, 253, 81, 56, 254, 131, 118, 67, 91, 159, 198, 29, 47, 192, 235, 6, 227
    ])

    it('works', async () => {
        expect(Uint8ArrayFromHex(input)).toEqual(expected)
    })
})


describe('Hash', () => {
    const input1 = new TextEncoder().encode("foo")
    const input2 = new TextEncoder().encode("bar")

    // @refs https://emn178.github.io/online-tools/sha256.html
    const expected1 = Uint8ArrayFromHex("2C26B46B68FFC68FF99B453C1D30413413422D706483BFA0F98A5E886266E7AE")
    const expected2 = Uint8ArrayFromHex("FCDE2B2EDBA56BF408601FB721FE9B5C338D10EE429EA04FAE5511B68FBF8FB9")
    const expected3 = Uint8ArrayFromHex("C3AB8FF13720E8AD9047DD39466B3C8974E592C2FA383D4A3960714CAEF0C4F2")

    it('works', async () => {
        expect(await Hash("SHA-256", input1)).toEqual(expected1)
        expect(await Hash("SHA-256", input2)).toEqual(expected2)
        expect(await Hash("SHA-256", input1, input2)).toEqual(expected3)
    })
})

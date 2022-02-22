import {SrpClient} from "./client"
import {RFC5054b1024Sha1, RFC5054b8192Sha1} from "./rfc5054"

describe('SrpClient', () => {
    describe('randomSalt', () => {
        it('uses size of N', async () => {
            const client1 = new SrpClient("foo", "bar", RFC5054b1024Sha1)
            const client2 = new SrpClient("foo", "bar", RFC5054b8192Sha1)

            const salt1 = await client1.randomSalt()
            const salt2 = await client2.randomSalt()

            expect(salt1).toHaveLength(1024 >> 3)
            expect(salt2).toHaveLength(8192 >> 3)
        })

        it('generates a random', async () => {
            const client1 = new SrpClient("foo", "bar", RFC5054b1024Sha1)
            const client2 = new SrpClient("foo", "bar", RFC5054b1024Sha1)

            const salt1 = await client1.randomSalt()
            const salt2 = await client2.randomSalt()

            expect(salt1).not.toEqual(salt2)
        })
    })
})

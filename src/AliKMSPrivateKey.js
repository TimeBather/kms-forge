import btoa from 'btoa'
import atob from 'atob'
class AliKMSPrivateKey{
    constructor(kmsClient,algorithm,keyId,keyVersionId) {
        this.client=kmsClient
        this.algorithm=algorithm
        this.keyId=keyId
        this.keyVersionId=keyVersionId
    }
    async sign(hash){
        let digest=(hash.digest().getBytes())
        var params = {
            Algorithm: "RSA_PKCS1_SHA_256",
            KeyId: this.keyId,
            KeyVersionId: this.keyVersionId,
            Digest: btoa(digest),
        }

        var requestOption = {
            method: 'POST'
        };
        let result=await this.client.request('AsymmetricSign', params, requestOption)
        console.info("Signature OK!")
        return atob(result['Value'])
    }
    signCertificate(certificate,md){
        return new Promise(((resolve, reject) => {
            var that=this;
            certificate.sign({
                sign(hash) {
                    that.sign(hash).then((data)=>{
                         certificate.signature =data
                             resolve();
                     })
                }
            },md)
        }))
    }
}
export default AliKMSPrivateKey;
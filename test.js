import config from './.config.js'
import kmsForge from './index.js'
import forge from 'node-forge'
import Core from '@alicloud/pop-core';
let apiConfig = new Core({
    accessKeyId: config.accessId,
    accessKeySecret: config.accessSecret,
    endpoint:config.endpoint,
    apiVersion: '2016-01-20'
});
let privateKey = new kmsForge.AliKMSPrivateKey(apiConfig, 'RSA_PKCS1_SHA_256', config.kmsKeyId, config.kmsKeyVersionId);
/* Examples from node-forge */
const pki = forge.pki;
let cert = pki.createCertificate();
cert.publicKey = pki.publicKeyFromPem(config.publicKey);
cert.serialNumber = '01';
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date();
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
var attrs = [{
    name: 'commonName',
    value: 'example.org'
}, {
    name: 'countryName',
    value: 'US'
}, {
    shortName: 'ST',
    value: 'Virginia'
}, {
    name: 'localityName',
    value: 'Blacksburg'
}, {
    name: 'organizationName',
    value: 'Test'
}, {
    shortName: 'OU',
    value: 'Test'
}];
cert.setSubject(attrs);
cert.setIssuer(attrs);
cert.setExtensions([{
    name: 'basicConstraints',
    cA: true
}, {
    name: 'keyUsage',
    keyCertSign: true,
    digitalSignature: true,
    nonRepudiation: true,
    keyEncipherment: true,
    dataEncipherment: true
}, {
    name: 'extKeyUsage',
    serverAuth: true,
    clientAuth: true,
    codeSigning: true,
    emailProtection: true,
    timeStamping: true
}, {
    name: 'nsCertType',
    client: true,
    server: true,
    email: true,
    objsign: true,
    sslCA: true,
    emailCA: true,
    objCA: true
}, {
    name: 'subjectAltName',
    altNames: [{
        type: 6, // URI
        value: 'http://example.org/webid#me'
    }, {
        type: 7, // IP
        ip: '127.0.0.1'
    }]
}, {
    name: 'subjectKeyIdentifier'
}]);
privateKey.signCertificate(cert,forge.md.sha256.create()).then(()=>{
    console.info(forge.pki.certificateToPem(cert))
})

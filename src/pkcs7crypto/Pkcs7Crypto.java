package pkcs7crypto;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.CMSVerifierCertificateNotValidException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

/**
 *
 * @author Abhishek
 */
public class Pkcs7Crypto {

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static Map<String, Object> signJson(String payload, String pfxPath, String pfxPwd, String pfxAlias) {
        Map<String, Object> response = new LinkedHashMap<>();
        Gson gson = new Gson();
        try {
            // ----------- 1. JSON Payload -----------
            byte[] data = payload.getBytes("UTF-8");

            // ----------- 2. Load Certificate & Private Key -----------
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream(pfxPath), pfxPwd.toCharArray());
            String alias = ks.aliases().nextElement();
            PrivateKey privateKey = (PrivateKey) ks.getKey(alias, "emudhra".toCharArray());
            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);

            // ----------- 3. Create PKCS#7 Signature -----------
            List<X509Certificate> certList = new ArrayList<>();
            certList.add(cert);
            Store certs = new JcaCertStore(certList);

            CMSTypedData cmsData = new CMSProcessableByteArray(data);
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder().build())
                    .build(new JcaContentSignerBuilder("SHA256withRSA").build(privateKey), cert));
            gen.addCertificates(certs);

            CMSSignedData signedData = gen.generate(cmsData);
            String base64Signature = Base64.getEncoder().encodeToString(signedData.getEncoded());

            // ----------- 4. Build Final JSON Output -----------
            Map<String, Object> signatureInfo = new LinkedHashMap<>();
            signatureInfo.put("algorithm", "SHA256withRSA");
            signatureInfo.put("signatureFormat", "PKCS7");
            signatureInfo.put("signature", base64Signature);

            // Add signer certificate in Base64
            signatureInfo.put("x5c", Collections.singletonList(Base64.getEncoder().encodeToString(cert.getEncoded())));

            JsonObject payloadObj = gson.fromJson(payload, JsonObject.class);

            response.put("status", true);
            response.put("payload", payloadObj);
            response.put("signatureInfo", signatureInfo);
            String finaljsonStr = gson.toJson(response);

            // ----------- 5. Print Final JSON -----------
            System.out.println("SignedJson:\n" + finaljsonStr); // pretty print

        } catch (JsonSyntaxException | IOException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | CertificateException | CMSException | OperatorCreationException e) {
            response.put("status", false);
            response.put("message", e.getMessage());
        }
        return response;
    }

    public static boolean verifySignedJson(String signedJson) throws Exception {
        Gson gson = new Gson();
        try {
            Map<String, Object> request = gson.fromJson(signedJson, Map.class);
            Object payloadObj = (Object) request.getOrDefault("payload", "");
            Object signatureInfoObj = (Object) request.getOrDefault("signatureInfo", "");
            String payloadStr = gson.toJson(payloadObj);
            String signatureBase64 = "";
            if (signatureInfoObj != null) {
                String signatureInfoJsonStr = gson.toJson(signatureInfoObj);
                Map<String, Object> signatureInfoJson = gson.fromJson(signatureInfoJsonStr, Map.class);
                String signatureFormat = (String) signatureInfoJson.getOrDefault("signatureFormat", "");
                if (signatureInfoJson != null && signatureFormat.equalsIgnoreCase("pkcs7")) {
                    signatureBase64 = (String) signatureInfoJson.getOrDefault("signature", "");
                }
            }
            byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
            byte[] payloadBytes = payloadStr.getBytes("UTF-8");

            System.out.println("============================================================================================================================");
            Map<String, Object> verifyPkcs7Data = verifyPKCS7WithEmbeddedCert(signatureBase64, payloadBytes);
            boolean verifyStatus = (boolean) verifyPkcs7Data.getOrDefault("status", false);
            if (verifyStatus) {
                System.out.println("✅ Signature verified successfully.");
            } else {
                System.out.println("❌ Signature verification failed.");
            }
            System.out.println(">>> Verification result: " + verifyStatus);
            System.out.println("============================================================================================================================");
            return verifyStatus;
        } catch (Exception e) {
            return false;
        }
    }

    public static Map<String, Object> verifyPKCS7WithEmbeddedCert(String pkcs7DataBase64, byte[] detachedContent) throws Exception {
        Map<String, Object> response = new HashMap<>();
        try {
            boolean signatureValid = false;
            // Decode PKCS#7
            byte[] pkcs7Data = Base64.getDecoder().decode(pkcs7DataBase64);

            // First, check if PKCS7 has encapsulated content
            CMSSignedData cmsSignedData = new CMSSignedData(pkcs7Data);
            CMSTypedData signedContent = cmsSignedData.getSignedContent();

            System.out.println("DEBUG: signedContent is " + (signedContent == null ? "NULL" : "NOT NULL"));
            System.out.println("DEBUG: detachedContent is " + (detachedContent == null ? "NULL" : "NOT NULL"));

            if (signedContent != null && detachedContent != null) {
                // Extract the embedded content from PKCS7
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                signedContent.write(bos);
                byte[] embeddedContent = bos.toByteArray();

                System.out.println("DEBUG: Extracted embedded content length: " + embeddedContent.length);
                System.out.println("DEBUG: Embedded content: " + new String(embeddedContent, "UTF-8"));
                System.out.println("DEBUG: Provided payload: " + new String(detachedContent, "UTF-8"));

                // Compare with the provided payload
                if (!java.util.Arrays.equals(embeddedContent, detachedContent)) {
                    System.out.println("⚠️ WARNING: Payload has been modified!");
                    System.out.println("   Embedded content length: " + embeddedContent.length);
                    System.out.println("   Provided payload length: " + detachedContent.length);
                    System.out.println("   Embedded content: " + new String(embeddedContent, "UTF-8"));
                    System.out.println("   Provided payload: " + new String(detachedContent, "UTF-8"));
                    throw new Exception("Payload tampering detected: provided payload does not match signed content");
                }
                System.out.println("✓ Payload matches the signed content");
            } else if (signedContent == null && detachedContent != null) {
                // Detached signature - must verify message digest from signed attributes
                System.out.println("Detached signature detected. Verifying message digest...");

                SignerInformationStore signerInfoStore = cmsSignedData.getSignerInfos();
                Collection<SignerInformation> signers = signerInfoStore.getSigners();

                if (signers.isEmpty()) {
                    throw new Exception("No signer information found in PKCS#7 data");
                }

                // Verify the message digest for each signer
                for (SignerInformation signer : signers) {
                    // Get the message-digest attribute from signed attributes
                    Attribute messageDigestAttr = signer.getSignedAttributes().get(CMSAttributes.messageDigest);

                    if (messageDigestAttr == null) {
                        throw new Exception("No message-digest attribute found in signed attributes");
                    }

                    // Extract the digest value from the attribute
                    ASN1OctetString digestValue = (ASN1OctetString) messageDigestAttr.getAttrValues().getObjectAt(0);
                    byte[] signedDigest = digestValue.getOctets();

                    // Determine the hash algorithm used
                    String digestAlgorithm = signer.getDigestAlgOID().equals("2.16.840.1.101.3.4.2.1") ? "SHA-256" : "SHA-1";
                    System.out.println("DEBUG: Using digest algorithm: " + digestAlgorithm);

                    // Compute the hash of the provided payload
                    MessageDigest md = MessageDigest.getInstance(digestAlgorithm);
                    byte[] computedDigest = md.digest(detachedContent);

                    System.out.println("DEBUG: Signed digest length: " + signedDigest.length);
                    System.out.println("DEBUG: Computed digest length: " + computedDigest.length);
                    System.out.println("DEBUG: Signed digest (hex): " + bytesToHex(signedDigest));
                    System.out.println("DEBUG: Computed digest (hex): " + bytesToHex(computedDigest));

                    // Compare the digests
                    if (!java.util.Arrays.equals(signedDigest, computedDigest)) {
                        System.out.println("⚠️ WARNING: Payload has been modified!");
                        System.out.println("   The message digest in the signature does not match the provided payload");
                        System.out.println("   Provided payload: " + new String(detachedContent, "UTF-8"));
                        throw new Exception("Payload tampering detected: message digest mismatch");
                    }

                    System.out.println("✓ Payload message digest matches the signed digest");
                }
            }

            // Verify the signature using embedded content (not detached)
            System.out.println("Verifying encapsulated signature");

            Store certStore = cmsSignedData.getCertificates();
            SignerInformationStore signerInfoStore = cmsSignedData.getSignerInfos();
            Collection<SignerInformation> signers = signerInfoStore.getSigners();

            if (signers.isEmpty()) {
                throw new Exception("No signer information found in PKCS#7 data");
            }

            // Make sure EM provider is registered
            if (Security.getProvider("EM") == null) {
                Security.addProvider(new org.bouncycastle.jce.provider.emCastleProvider());
            }
            JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter().setProvider("EM");

            for (SignerInformation signer : signers) {
                Collection<?> certCollection = certStore.getMatches(signer.getSID());

                if (certCollection.isEmpty()) {
                    System.out.println("⚠️ No certificate found for this signer");
                    continue;
                }

                for (Object certObj : certCollection) {
                    X509CertificateHolder certHolder = (X509CertificateHolder) certObj;
                    X509Certificate pkcs7Cert = certConverter.getCertificate(certHolder);

                    System.out.println("Found certificate in PKCS#7: " + pkcs7Cert.getSubjectDN());

                    try {
                        // Build verifier with EM provider
                        SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder()
                                .setProvider("EM")
                                .build(certHolder);

                        if (signer.verify(verifier)) {
                            signatureValid = true;
                            System.out.println("✅ Signature verified successfully for signer: " + pkcs7Cert.getSubjectDN());
                            response.put("status", true);
                            response.put("message", "✅ Signature verified successfully for signer: " + pkcs7Cert.getSubjectDN());
                        } else {
                            System.out.println("❌ Signature verification failed for signer: " + pkcs7Cert.getSubjectDN());
                            response.put("status", false);
                            response.put("message", "❌ Signature verification failed for signer: " + pkcs7Cert.getSubjectDN());
                        }
                    } catch (CMSVerifierCertificateNotValidException e) {
                        // Certificate not valid at signing time - verify signature cryptographically only
                        System.out.println("⚠️ Certificate not valid at signing time, verifying signature cryptographically only...");
                        try {
                            // Use Java Signature API directly to verify without time checks
                            java.security.Signature sig = java.security.Signature.getInstance(
                                    signer.getDigestAlgOID().equals("2.16.840.1.101.3.4.2.1") ? "SHA256withRSA" : "SHA1withRSA",
                                    "EM");
                            sig.initVerify(pkcs7Cert.getPublicKey());

                            // Get the signed attributes (the data that was actually signed)
                            byte[] signedData = signer.getEncodedSignedAttributes();
                            if (signedData != null) {
                                sig.update(signedData);
                            } else {
                                // If no signed attributes, use the content directly
                                sig.update(detachedContent);
                            }

                            if (sig.verify(signer.getSignature())) {
                                signatureValid = true;
                                System.out.println("✅ Signature cryptographically valid (time check skipped) for: " + pkcs7Cert.getSubjectDN());
                                response.put("status", true);
                                response.put("message", "✅ Signature cryptographically valid (time check skipped) for: " + pkcs7Cert.getSubjectDN());
                            } else {
                                System.out.println("❌ Signature cryptographically invalid for: " + pkcs7Cert.getSubjectDN());
                                response.put("status", false);
                                response.put("message", "❌ Signature cryptographically invalid for: " + pkcs7Cert.getSubjectDN());
                            }
                        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException ex) {
                            System.out.println("❌ Failed to verify signature: " + ex.getMessage());
                            throw new Exception("❌ Failed to verify signature: " + ex.getMessage());
                        }
                    } catch (CMSException | OperatorCreationException e) {
                        throw new Exception("Failed to verify signature: " + e.getMessage(), e);
                    }
                }
            }
            if (!signatureValid) {
                throw new Exception("No valid signature found in PKCS#7 data");
            }
        } catch (Exception e) {
            response.put("status", false);
            response.put("message", e.getMessage());
        }
        return response;
    }

    public static boolean verifyPKCS7WithPFX(String pkcs7DataBase64, byte[] detachedContent, String pfxPath, String pfxPwd, String pfxAlias) throws Exception {
        // Load the PFX keystore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(pfxPath)) {
            keyStore.load(fis, pfxPwd.toCharArray());
        }

        if (!keyStore.containsAlias(pfxAlias)) {
            throw new Exception("Alias " + pfxAlias + " does not exist in the PFX KeyStore");
        }

        X509Certificate x509Cert = (X509Certificate) keyStore.getCertificate(pfxAlias);
        if (x509Cert == null) {
            throw new Exception("No certificate found for alias: " + pfxAlias);
        }
        System.out.println("Certificate retrieved for alias " + pfxAlias + ": " + x509Cert.getSubjectDN());

        // Decode PKCS#7
        byte[] pkcs7Data = Base64.getDecoder().decode(pkcs7DataBase64);

        CMSSignedData cmsSignedData;
        if (detachedContent != null) {
            System.out.println("Verifying detached signature with content length: " + detachedContent.length);
            cmsSignedData = new CMSSignedData(new CMSProcessableByteArray(detachedContent), pkcs7Data);
        } else {
            System.out.println("Verifying attached signature");
            cmsSignedData = new CMSSignedData(pkcs7Data);
        }

        Store certStore = cmsSignedData.getCertificates();
        SignerInformationStore signerInfoStore = cmsSignedData.getSignerInfos();
        Collection<SignerInformation> signers = signerInfoStore.getSigners();
        if (signers.isEmpty()) {
            throw new Exception("No signer information found in PKCS#7 data");
        }

        boolean signatureValid = false;
        // Make sure BC provider is registered
        Security.addProvider(new org.bouncycastle.jce.provider.emCastleProvider());
        JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter().setProvider("EM");

        for (SignerInformation signer : signers) {
            Collection<?> certCollection = certStore.getMatches(signer.getSID());
            for (Object certObj : certCollection) {
                X509CertificateHolder certHolder = (X509CertificateHolder) certObj;
                X509Certificate pkcs7Cert = certConverter.getCertificate(certHolder);

                if (pkcs7Cert.equals(x509Cert)) {
                    try {
                        // Build verifier with EM provider
                        SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder()
                                .setProvider("EM")
                                .build(certHolder);

                        if (signer.verify(verifier)) {
                            signatureValid = true;
                            System.out.println("✅ Signature verified successfully for signer: " + pkcs7Cert.getSubjectDN());
                        } else {
                            System.out.println("❌ Signature verification failed for signer: " + pkcs7Cert.getSubjectDN());
                        }
                    } catch (CMSVerifierCertificateNotValidException e) {
                        // Certificate not valid at signing time - verify signature cryptographically only
                        System.out.println("⚠️ Certificate not valid at signing time, verifying signature cryptographically only...");
                        try {
                            // Use Java Signature API directly to verify without time checks
                            java.security.Signature sig = java.security.Signature.getInstance(
                                    signer.getDigestAlgOID().equals("2.16.840.1.101.3.4.2.1") ? "SHA256withRSA" : "SHA1withRSA",
                                    "EM");
                            sig.initVerify(pkcs7Cert.getPublicKey());

                            // Get the signed attributes (the data that was actually signed)
                            byte[] signedData = signer.getEncodedSignedAttributes();
                            if (signedData != null) {
                                sig.update(signedData);
                            } else {
                                // If no signed attributes, use the content directly
                                sig.update(detachedContent);
                            }

                            if (sig.verify(signer.getSignature())) {
                                signatureValid = true;
                                System.out.println("✅ Signature cryptographically valid (time check skipped) for: " + pkcs7Cert.getSubjectDN());
                            } else {
                                System.out.println("❌ Signature cryptographically invalid for: " + pkcs7Cert.getSubjectDN());
                            }
                        } catch (Exception ex) {
                            System.out.println("❌ Failed to verify signature: " + ex.getMessage());
                        }
                    } catch (CMSException | OperatorCreationException e) {
                        throw new Exception("Failed to verify signature: " + e.getMessage(), e);
                    }
                }
            }
        }

        if (!signatureValid) {
            throw new Exception("No valid signature found matching the PFX certificate");
        }

        // Print certificate chain if available
        Certificate[] certChain = keyStore.getCertificateChain(pfxAlias);
        if (certChain != null) {
            System.out.println("Certificate chain length: " + certChain.length);
            for (int i = 0; i < certChain.length; i++) {
                System.out.println("Certificate " + (i + 1) + ": " + ((X509Certificate) certChain[i]).getSubjectDN());
            }
        }

        return true;
    }

}

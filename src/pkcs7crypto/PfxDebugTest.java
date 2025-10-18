package pkcs7crypto;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class PfxDebugTest {

    public static void main(String[] args) {
        // Add EM provider
        if (Security.getProvider("EM") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.emCastleProvider());
            System.out.println("EM provider registered\n");
        }

        String[] pfxFiles = {
            "D:\\4Certificates\\Bank\\Test-Class3DocumentSigner2014.pfx",
            "C:\\Users\\21701\\Downloads\\test.pfx"
        };

        String[] passwords = {"1", "1"}; // Adjust if passwords are different

        for (int i = 0; i < pfxFiles.length; i++) {
            System.out.println("========================================");
            System.out.println("Testing PFX: " + pfxFiles[i]);
            System.out.println("========================================");
            testPfxFile(pfxFiles[i], passwords[i]);
            System.out.println();
        }
    }

    public static void testPfxFile(String pfxPath, String password) {
        FileInputStream fis = null;
        try {
            // First, try to load with default provider
            System.out.println("1. Attempting to load with DEFAULT provider...");
            KeyStore ks = null;

            try {
                ks = KeyStore.getInstance("PKCS12");
                fis = new FileInputStream(pfxPath);
                ks.load(fis, password.toCharArray());
                System.out.println("   [OK] Successfully loaded with DEFAULT provider");
            } catch (Exception e) {
                System.out.println("   [FAIL] Failed with DEFAULT provider: " + e.getMessage());

                // Try with EM provider
                System.out.println("\n2. Attempting to load after removing EM provider...");
                try {
                    if (fis != null) fis.close();

                    // Temporarily remove EM provider
                    Security.removeProvider("EM");

                    ks = KeyStore.getInstance("PKCS12");
                    fis = new FileInputStream(pfxPath);
                    ks.load(fis, password.toCharArray());
                    System.out.println("   [OK] Successfully loaded after removing EM provider");

                    // Re-add EM provider
                    Security.addProvider(new org.bouncycastle.jce.provider.emCastleProvider());
                } catch (Exception e2) {
                    System.out.println("   [FAIL] Failed even without EM provider: " + e2.getMessage());
                    e2.printStackTrace();
                    return;
                }
            } finally {
                if (fis != null) fis.close();
            }

            // Show aliases
            System.out.println("\n3. Keystore Aliases:");
            Enumeration<String> aliases = ks.aliases();
            int count = 0;
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                count++;
                System.out.println("   Alias " + count + ": " + alias);

                // Get certificate
                X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
                if (cert != null) {
                    System.out.println("   - Subject: " + cert.getSubjectDN());
                    System.out.println("   - Issuer: " + cert.getIssuerDN());
                    System.out.println("   - Valid From: " + cert.getNotBefore());
                    System.out.println("   - Valid To: " + cert.getNotAfter());
                    System.out.println("   - Serial: " + cert.getSerialNumber());
                }

                // Check if has private key
                try {
                    PrivateKey pk = (PrivateKey) ks.getKey(alias, password.toCharArray());
                    if (pk != null) {
                        System.out.println("   - Private Key: [OK] Available (" + pk.getAlgorithm() + ")");
                    } else {
                        System.out.println("   - Private Key: [FAIL] Not found");
                    }
                } catch (Exception e) {
                    System.out.println("   - Private Key: [ERROR] " + e.getMessage());
                }
                System.out.println();
            }

            if (count == 0) {
                System.out.println("   [WARNING] No aliases found in keystore!");
            }

            // Test signing
            System.out.println("4. Testing JSON signing...");
            String testJson = "{\"test\":\"data\"}";
            try {
                String firstAlias = ks.aliases().nextElement();
                java.util.Map<String, Object> result = pkcs7crypto.Pkcs7Crypto.signJson(
                    testJson, pfxPath, password, firstAlias
                );

                Object status = result.get("status");
                if (status != null && status.toString().equals("true")) {
                    System.out.println("   [OK] Signing successful");
                } else {
                    System.out.println("   [FAIL] Signing failed: " + result.get("message"));
                }
            } catch (Exception e) {
                System.out.println("   [ERROR] Signing exception: " + e.getMessage());
                e.printStackTrace();
            }

        } catch (Exception e) {
            System.out.println("ERROR: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try {
                if (fis != null) fis.close();
            } catch (Exception e) {
                // Ignore
            }
        }
    }
}
